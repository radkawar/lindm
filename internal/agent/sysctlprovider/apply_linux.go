// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sysctlprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

func (p *Provider) target(ctx context.Context, d *resourcev1.SysctlDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	target, err := targetSnapshot(d, before, ledger, operation)
	if err != nil {
		return nil, err
	}
	if err := validateOwnedStanza(d.GetKey(), target.GetSysctlPersistence().GetContent()); err != nil {
		return nil, err
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && !before.GetSysctlPersistence().GetState().GetExists() && target.GetSysctlPersistence().GetState().GetExists() {
		file := fileSnapshot(target)
		if err := nativefile.CreationMetadata(ctx, file); err != nil {
			return nil, err
		}
		target.SysctlPersistence.State = proto.CloneOf(file.GetObservation().GetManagedFile())
		target.SysctlPersistence.Xattrs = file.GetManagedFileXattrs()
		target.GetObservation().GetSysctl().PersistenceFileState = proto.CloneOf(target.SysctlPersistence.State)
	}
	return target, nil
}
func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	if beforeEffect == nil || p.config.NativeApply == nil {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := desiredState(plan.GetSysctl().GetDesired())
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBackend(), p.backend) || plan.GetBefore().GetMetadata().GetExecutorIncarnation() != p.config.ExecutorIncarnation {
		return nil, ErrConflict
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, ledger, plan.GetOperation()); err != nil {
		return nil, err
	}
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ld[:], plan.GetOwnershipRevisionSha256()) {
		return nil, ErrConflict
	}
	before, err := p.observe(ctx, desired.GetSysctl())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(before.GetObservation().GetSysctl(), plan.GetSysctl().GetBefore()) {
		return nil, ErrConflict
	}
	target, err := p.target(ctx, desired.GetSysctl(), before, ledger, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		inverse, err := inverseBinding(ledger, before, target)
		if err != nil {
			return nil, err
		}
		if !proto.Equal(inverse, plan.GetSysctl().GetInverse()) {
			return nil, ErrConflict
		}
	}
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger, err = p.store.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), before)
		if err != nil {
			return nil, err
		}
	}
	requestLedger := proto.CloneOf(ledger)
	dimensions := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE}
	if desired.GetSysctl().GetPersistent() {
		dimensions = append(dimensions, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE)
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		dimensions = append([]agentv1.ResourceOwnedDimension(nil), ledger.GetOwnedDimensions()...)
	}
	ledger, err = p.store.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), before, dimensions)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: requestLedger, ActionId: p.config.ActionID, Nonce: nonce}
	consumed := false
	gate := func(effectContext context.Context) error {
		if consumed {
			return ErrOutcomeUnknown
		}
		consumed = true
		return beforeEffect(effectContext)
	}
	if err := p.config.NativeApply(ctx, request, gate); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !consumed {
		return nil, ErrOutcomeUnknown
	}
	after, err := p.observe(ctx, desired.GetSysctl())
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !targetMatches(after, target) {
		return nil, errors.Join(ErrOutcomeUnknown, ErrNotConverged)
	}
	verification, err := verificationFor(plan, after, requestLedger, target, true)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !verification.GetSysctl().GetConverged() {
		return verification, errors.Join(ErrOutcomeUnknown, ErrNotConverged)
	}
	if _, err := p.store.CompleteResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return verification, errors.Join(ErrOutcomeUnknown, err)
	}
	return verification, nil
}
func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := desiredState(plan.GetSysctl().GetDesired())
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBackend(), p.backend) || plan.GetBefore().GetMetadata().GetExecutorIncarnation() != p.config.ExecutorIncarnation {
		return nil, ErrConflict
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	after, err := p.observe(ctx, desired.GetSysctl())
	if err != nil {
		return nil, err
	}
	var target *agentv1.ResourceOwnershipSnapshot
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			return nil, ErrConflict
		}
		target = proto.CloneOf(ledger.GetBeforeEffect())
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
			if owned(ledger, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE) {
				target.GetObservation().GetSysctl().Value = proto.String(ledger.GetBaseline().GetObservation().GetSysctl().GetValue())
			}
			if owned(ledger, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE) {
				target.SysctlPersistence = proto.CloneOf(ledger.GetBaseline().GetSysctlPersistence())
			}
		}
	} else {
		target, err = p.target(ctx, desired.GetSysctl(), after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
	}
	return verificationFor(plan, after, ledger, target, false)
}
func verificationFor(plan *resourcev1.ResourcePlan, after *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, target *agentv1.ResourceOwnershipSnapshot, applied bool) (*resourcev1.ResourceVerification, error) {
	d := plan.GetSysctl().GetDesired()
	o := after.GetObservation().GetSysctl()
	checks := &resourcev1.SysctlChecks{LiveValueMatches: o.Value != nil && normalizeValue(o.GetValue()) == normalizeValue(target.GetObservation().GetSysctl().GetValue()), PersistenceMatches: true, PersistenceOwnerMatches: true}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		checks.PersistenceMatches = fileTargetMatches(after.GetSysctlPersistence(), target.GetSysctlPersistence())
	} else if d.GetPersistent() {
		checks.PersistenceMatches = o.PersistentValue != nil && normalizeValue(o.GetPersistentValue()) == normalizeValue(d.GetValue()) && !o.GetPersistenceConflict()
		checks.PersistenceOwnerMatches = fileTargetMatches(after.GetSysctlPersistence(), target.GetSysctlPersistence()) && o.GetPersistentSource() == StanzaPath(d.GetKey()) && ledger.GetLastApplied() != nil && proto.Equal(after.GetSysctlPersistence(), ledger.GetLastApplied().GetSysctlPersistence())
		// During successful Apply the ledger is UNKNOWN until independent
		// observation completes. The admitted target is the ownership proof.
		if applied {
			checks.PersistenceOwnerMatches = fileTargetMatches(after.GetSysctlPersistence(), target.GetSysctlPersistence()) && o.GetPersistentSource() == StanzaPath(d.GetKey())
		}
		last := ledger.GetLastApplied().GetObservation()
		checks.RebootPersistenceVerified = last != nil && last.GetMetadata().GetBootId() != after.GetObservation().GetMetadata().GetBootId() && proto.Equal(last.GetSysctl().GetPersistenceFileState(), o.GetPersistenceFileState()) && bytes.Equal(last.GetSysctl().GetPersistenceGraphSha256(), o.GetPersistenceGraphSha256()) && checks.LiveValueMatches && checks.PersistenceMatches && checks.PersistenceOwnerMatches
	}
	checks.Converged = checks.LiveValueMatches && checks.PersistenceMatches && checks.PersistenceOwnerMatches
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	} else if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_RELEASE_CONFLICT
	}
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	result := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: digest[:], After: after.GetObservation(), Disposition: disposition, Checks: &resourcev1.ResourceVerification_Sysctl{Sysctl: checks}}
	if err := resource.ValidateVerification(result); err != nil {
		return nil, err
	}
	return result, nil
}
