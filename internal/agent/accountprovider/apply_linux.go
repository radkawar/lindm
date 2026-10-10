//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/resource"
)

func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || beforeEffect == nil || p.config.NativeTransaction == nil {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	d := resource.PlanDesired(plan)
	if err := p.validateDesired(d); err != nil {
		return nil, err
	}
	l, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if l.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	ld, err := journal.ResourceOwnershipDigest(l)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ld[:], plan.GetOwnershipRevisionSha256()) {
		return nil, ErrConflict
	}
	before, receipt, db, err := p.observe(ctx, d, l)
	if err != nil {
		return nil, err
	}
	if !sameObserved(plan.GetBefore(), before.GetObservation()) {
		return nil, ErrConflict
	}
	rebuilt, err := p.plan(ctx, d, plan.GetOperation(), before, db, l)
	if err != nil {
		return nil, err
	}
	// Metadata timestamps are observation evidence, not a native precondition.
	rebuilt.Before = proto.CloneOf(plan.GetBefore())
	rebuilt.ObservationSha256 = bytes.Clone(plan.GetObservationSha256())
	if !proto.Equal(rebuilt, plan) {
		return nil, ErrConflict
	}
	target, edges, err := p.target(d, plan.GetOperation(), before, db, l)
	if err != nil {
		return nil, err
	}
	dims := dimensions(before, target)
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		dims = slices.Clone(l.GetOwnedDimensions())
	}
	if len(dims) == 0 && plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		return verification(plan, target, before, receipt)
	}
	before.AccountMemberEdges = edges
	if l == nil || l.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		l, err = p.config.Journal.ClaimResourceOwnership(ctx, p.config.ActionID, int64(l.GetRevision()), before)
		if err != nil {
			return nil, err
		}
	}
	l, err = p.config.Journal.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(l.GetRevision()), before, dims)
	if err != nil {
		return nil, err
	}
	consumed := false
	gate := func(effectCtx context.Context) error {
		if consumed {
			return ErrConflict
		}
		consumed = true
		return beforeEffect(effectCtx)
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	before.Observation = proto.CloneOf(plan.GetBefore())
	if err = p.config.NativeTransaction(ctx, &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: proto.CloneOf(l), ActionId: p.config.ActionID, Nonce: nonce}, gate); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !consumed {
		return nil, ErrOutcomeUnknown
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	// Bind the expected newly allocated identity generation to the independently
	// observed native poststate. The helper cannot return invented observations.
	observedLedger := proto.CloneOf(l)
	observedLedger.LastApplied = target
	after, receipt, _, err := p.observe(finish, d, observedLedger)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	v, err := verification(plan, target, after, receipt)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if v.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		return v, ErrNotConverged
	}
	after.AccountMemberEdges = edges
	if _, err = p.config.Journal.CompleteResourceOwnershipEffect(finish, p.config.ActionID, int64(l.GetRevision()), after); err != nil {
		return v, errors.Join(ErrOutcomeUnknown, err)
	}
	return v, nil
}
func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	d := resource.PlanDesired(plan)
	if err := p.validateDesired(d); err != nil {
		return nil, err
	}
	l, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if l.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	after, receipt, db, err := p.observe(ctx, d, l)
	if err != nil {
		return nil, err
	}
	var target *agentv1.ResourceOwnershipSnapshot
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if l.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			return nil, ErrConflict
		}
		target = l.GetLastApplied()
	} else {
		target, _, err = p.target(d, plan.GetOperation(), after, db, l)
		if err != nil {
			return nil, err
		}
	}
	return verification(plan, target, after, receipt)
}
func sameObserved(a, b *resourcev1.ResourceObservation) bool {
	if a == nil || b == nil {
		return false
	}
	if !bytes.Equal(a.GetMetadata().GetNativeRevision(), b.GetMetadata().GetNativeRevision()) {
		return false
	}
	if a.GetLocalGroup() != nil {
		return proto.Equal(a.GetLocalGroup(), b.GetLocalGroup())
	}
	return proto.Equal(a.GetLocalUser(), b.GetLocalUser())
}
func verification(plan *resourcev1.ResourcePlan, target, after *agentv1.ResourceOwnershipSnapshot, receipt *resourcev1.ProbeReceipt) (*resourcev1.ResourceVerification, error) {
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	v := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: digest[:], After: after.GetObservation(), Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED}
	converged := false
	if g := target.GetObservation().GetLocalGroup(); g != nil {
		actual := after.GetObservation().GetLocalGroup()
		identityMatch := g.GetExists() == actual.GetExists() && actual.GetOrigin() == resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES
		gid := !g.GetExists() || g.GetGid() == actual.GetGid()
		membership := slices.Equal(g.GetMembers(), actual.GetMembers())
		converged = identityMatch && gid && membership && receipt.GetPassed()
		v.Checks = &resourcev1.ResourceVerification_LocalGroup{LocalGroup: &resourcev1.LocalGroupChecks{LocalIdentityMatches: identityMatch, GidMatches: gid, MembersMatch: membership, NssReread: receipt, Converged: converged}}
	} else {
		want, got := target.GetObservation().GetLocalUser(), after.GetObservation().GetLocalUser()
		identityMatch := want.GetExists() == got.GetExists() && got.GetOrigin() == resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES
		uid := !want.GetExists() || (want.GetUid() == got.GetUid() && want.GetUidGeneration() == got.GetUidGeneration())
		fields := !want.GetExists() || (want.GetGid() == got.GetGid() && want.GetShell() == got.GetShell() && homeMatches(want.GetHome(), got.GetHome()))
		groups := slices.Equal(want.GetGroups(), got.GetGroups())
		password := !want.GetExists() || want.GetPasswordLocked() == got.GetPasswordLocked() && target.GetAccountPrivate().GetPasswordToken() == after.GetAccountPrivate().GetPasswordToken()
		aging := !want.GetExists() || proto.Equal(want.GetAging(), got.GetAging())
		converged = identityMatch && uid && fields && groups && password && aging && receipt.GetPassed()
		v.Checks = &resourcev1.ResourceVerification_LocalUser{LocalUser: &resourcev1.LocalUserChecks{LocalIdentityMatches: identityMatch, UidGenerationMatches: uid, FieldsMatch: fields, MembershipsMatch: groups, PasswordPolicyMatches: password, AgingMatches: aging, NssReread: receipt, Converged: converged}}
	}
	if converged {
		v.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	if err := resource.ValidateVerification(v); err != nil {
		return nil, err
	}
	return v, nil
}
func homeMatches(want, got *resourcev1.HomeMetadata) bool {
	if want == nil || got == nil {
		return want == got
	}
	return want.GetPath() == got.GetPath() && want.GetExists() == got.GetExists() && (!want.GetExists() || (want.GetOwnerUid() == got.GetOwnerUid() && want.GetOwnerGid() == got.GetOwnerGid() && want.GetMode() == got.GetMode() && (want.GetInode() == 0 || want.GetInode() == got.GetInode()) && (want.GetDevice() == 0 || want.GetDevice() == got.GetDevice())))
}
