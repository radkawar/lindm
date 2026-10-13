//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/resource"
)

func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if beforeEffect == nil || p.config.NativeTransaction == nil || p.config.ActionID == "" {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := planDesired(plan)
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	manifest, _, err := p.loadManifest(plan.GetNativePackage().GetTransactionManifest())
	if err != nil {
		return nil, err
	}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		return nil, err
	}
	// Another frontend (a release upgrade, unattended-upgrades) owns the
	// database: refuse before ownership or native state is touched. A race
	// lost after this point is still caught by the helper's own lock.
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		if held, err := dpkgFrontendHeld(dpkgFrontendLock); err != nil {
			return nil, err
		} else if held {
			return nil, ErrBusy
		}
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	ownershipDigest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ownershipDigest[:], plan.GetOwnershipRevisionSha256()) {
		return nil, ErrConflict
	}
	db, err := p.database(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(db.revision, plan.GetNativePackage().GetNativeDatabaseRevision()) {
		return nil, ErrConflict
	}
	current, err := p.observe(ctx, desired, db, ledger, nil)
	if err != nil {
		return nil, err
	}
	// The plan's baseline carries the provenance its preparation proved for this
	// exact installation; the ownership claim records that proven baseline.
	if proof := manifest.GetInstalledProvenance(); proof != nil && !applyInstalledProvenance(current.GetNativePackage().GetRecord(), proof, desired.GetNativePackage().GetRepository()) {
		return nil, ErrConflict
	}
	if !proto.Equal(current.GetNativePackage(), plan.GetBefore().GetNativePackage()) {
		return nil, ErrConflict
	}
	if err := p.acquisitionAllowed(current, ledger, plan.GetOperation()); err != nil {
		return nil, err
	}
	effective := proto.CloneOf(desired.GetNativePackage())
	if effective.GetAny() != nil && current.GetNativePackage().GetInstalled() && effective.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		effective.Version = &resourcev1.NativePackageDesired_Exact{Exact: proto.CloneOf(current.GetNativePackage().GetRecord().GetVersion())}
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		var inverse *resourcev1.OwnershipInverseBinding
		var pin []byte
		effective, pin, inverse, err = releaseTarget(desired, current, ledger)
		if err != nil {
			return nil, err
		}
		if !proto.Equal(inverse, plan.GetNativePackage().GetInverse()) || !bytes.Equal(pin, plan.GetNativePackage().GetPinContents()) {
			return nil, ErrConflict
		}
	} else {
		pin, err := p.renderPin(plan.GetRef(), desired.GetNativePackage(), current.GetNativePackage().GetPinContents())
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pin, plan.GetNativePackage().GetPinContents()) {
			return nil, ErrConflict
		}
	}
	source, err := p.source(effective)
	if err != nil {
		return nil, err
	}
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: current, Artifacts: []*resourcev1.ArtifactRef{plan.GetNativePackage().GetTransactionManifest()}}
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger, err = p.config.Journal.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), snapshot)
		if err != nil {
			return nil, err
		}
	}
	ledger, err = p.config.Journal.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), snapshot, packageDimensions(plan, ledger))
	if err != nil {
		return nil, err
	}
	request := &agentv1.NativePackageTransactionRequest{Operation: agentv1.NativePackageHelperOperation_NATIVE_PACKAGE_HELPER_OPERATION_APPLY, Desired: desired, EffectiveDesired: effective, Source: source, TransactionId: plan.GetNativePackage().GetTransactionManifest().GetArtifactId(), ExpectedDatabaseRevision: bytes.Clone(db.revision), Manifest: manifest, Plan: proto.CloneOf(plan), Platform: proto.CloneOf(p.config.Platform), ActionId: p.config.ActionID}
	request.StagingExpiresAt = proto.CloneOf(p.config.Preparation.GetDeadline())
	request.StagingMaxBytes = min(p.config.Preparation.GetMaxCacheBytes(), uint64(512<<20))
	request.IntentSha256 = bytes.Clone(p.config.IntentDigest)
	if manifest.GetOriginalPin() != nil {
		request.OriginalPin = proto.CloneOf(manifest.GetOriginalPin())
		request.CandidatePinSha256 = bytes.Clone(manifest.GetCandidatePinSha256())
		request.CandidatePinContents = pinProjection(plan.GetBackend().GetBackend(), plan.GetNativePackage().GetPinContents())
	}
	consumed := false
	gate := func(effectContext context.Context) error {
		if consumed {
			return errors.New("packageprovider: beforeEffect replay")
		}
		if err := p.dependencyOwnership(effectContext, manifest); err != nil {
			return err
		}
		consumed = true
		return beforeEffect(effectContext)
	}
	if err := p.config.NativeTransaction(ctx, request, gate); err != nil {
		return nil, nativeTransactionError(err, consumed)
	}
	if !consumed {
		return nil, fmt.Errorf("%w: native helper omitted final authority gate", ErrOutcomeUnknown)
	}
	// Persist trustworthy poststate even when the caller's transport disappeared.
	// This is evidence recovery, never another package installation attempt.
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	afterDB, err := p.database(finish)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := transactionMatchesDatabase(manifest, db, afterDB); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	after, err := p.observe(finish, desired, afterDB, ledger, manifest)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	verification, err := packageVerification(plan, after, ledger, manifest, true)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !verification.GetNativePackage().GetConverged() {
		return verification, ErrNotConverged
	}
	_, err = p.config.Journal.CompleteResourceOwnershipEffect(finish, p.config.ActionID, int64(ledger.GetRevision()), &agentv1.ResourceOwnershipSnapshot{Observation: after, Artifacts: snapshot.Artifacts})
	if err != nil {
		return verification, errors.Join(ErrOutcomeUnknown, err)
	}
	return verification, nil
}

// nativeTransactionError classifies a failed native transaction. A busy native
// database before the final authority gate changed nothing, so it stays
// ErrBusy for the server to retry; any failure after the gate, or any other
// failure, leaves the outcome unknown.
func nativeTransactionError(err error, gateConsumed bool) error {
	if !gateConsumed && errors.Is(err, ErrBusy) {
		return err
	}
	return errors.Join(ErrOutcomeUnknown, err)
}
