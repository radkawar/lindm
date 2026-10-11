//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func planDesired(plan *resourcev1.ResourcePlan) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: proto.CloneOf(plan.GetRef()), State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: proto.CloneOf(plan.GetNativePackage().GetDesired())}}
}

func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := planDesired(plan)
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	manifest, _, err := p.loadManifest(plan.GetNativePackage().GetTransactionManifest())
	if err != nil {
		return nil, err
	}
	if err := ValidateNativePlan(plan, manifest); err != nil {
		return nil, err
	}
	db, err := p.database(ctx)
	if err != nil {
		return nil, err
	}
	after, err := p.observe(ctx, desired, db, ledger, nil)
	if err != nil {
		return nil, err
	}
	return packageVerification(plan, after, ledger, manifest, manifestMatchesDatabase(manifest, db))
}
func packageVerification(plan *resourcev1.ResourcePlan, after *resourcev1.ResourceObservation, ledger *agentv1.ResourceOwnershipLedger, manifest *resourcev1.PackageTransactionManifest, sideEffects bool) (*resourcev1.ResourceVerification, error) {
	desired := plan.GetNativePackage().GetDesired()
	observed := after.GetNativePackage()
	databaseMatches := nativeMatches(desired, observed.GetRecord())
	exactMatches := desired.GetExact() == nil || !observed.GetInstalled() || proto.Equal(desired.GetExact(), observed.GetRecord().GetVersion())
	approved := !observed.GetInstalled() || observed.GetRecord().GetProvenanceKnown() && proto.Equal(observed.GetRecord().GetSource(), desired.GetRepository())
	pin := pinMatches(plan.GetBackend().GetBackend(), plan.GetRef(), desired, observed.GetPinContents())
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		// Release verifies the executor-computed inverse, never the original
		// desired state that is deliberately no longer managed.
		baseline := ledger.GetBaseline().GetObservation().GetNativePackage()
		target := baseline
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN || desired.GetRemoval() == resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_RETAIN_INSTALLATION {
			target = plan.GetBefore().GetNativePackage()
		}
		databaseMatches = observed.GetInstalled() == target.GetInstalled()
		exactMatches = samePackageRecord(observed.GetRecord(), target.GetRecord())
		approved = !observed.GetInstalled() || observed.GetRecord().GetProvenanceKnown()
		pin = bytes.Equal(observed.GetPinContents(), plan.GetNativePackage().GetPinContents())
	}
	// Readiness here means native package configuration is complete, not an
	// invented application-specific health command. No arbitrary launch API is
	// inferred from a package name. The authoritative probe already rejects
	// half-configured dpkg rows and incomplete RPM database reads.
	ready := databaseMatches && exactMatches && pin
	evidence, err := digestMessage(observed)
	if err != nil {
		return nil, err
	}
	planDigest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	checks := &resourcev1.NativePackageChecks{
		NativeDatabaseMatches: databaseMatches, ExactVersionMatches: exactMatches,
		ApprovedSourceMatches: approved, SideEffectsMatchManifest: sideEffects,
		NativeConfigurationReadiness: &resourcev1.ProbeReceipt{ProbeId: uuid.New().String(),
			ObservedAt: timestamppb.Now(), Passed: ready, EvidenceSha256: evidence,
			Reason: "native package database configuration and persistent version pin"},
		Converged: ready && approved && sideEffects,
	}
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	} else if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_RELEASE_CONFLICT
	}
	result := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: planDigest[:], After: after, Disposition: disposition, Checks: &resourcev1.ResourceVerification_NativePackage{NativePackage: checks}}
	if err := resource.ValidateVerification(result); err != nil {
		return nil, err
	}
	return result, nil
}
func manifestMatchesDatabase(manifest *resourcev1.PackageTransactionManifest, db *database) bool {
	for _, entry := range manifest.GetEntries() {
		key := packageKey(entry.GetPackage())
		actual := db.records[key]
		if db.multiple[key] {
			return false
		}
		if entry.GetAfter() == nil {
			if actual != nil {
				return false
			}
		} else if actual == nil || !proto.Equal(actual.GetVersion(), entry.GetAfter()) {
			return false
		}
	}
	return true
}
func transactionMatchesDatabase(manifest *resourcev1.PackageTransactionManifest, before, after *database) error {
	if !manifestMatchesDatabase(manifest, after) {
		return ErrNotConverged
	}
	changed := make(map[string]*resourcev1.PackageTransactionEntry, len(manifest.GetEntries()))
	for _, entry := range manifest.GetEntries() {
		key := packageKey(entry.GetPackage())
		if changed[key] != nil {
			return ErrConflict
		}
		changed[key] = entry
		if !proto.Equal(before.records[key].GetVersion(), entry.GetBefore()) {
			return ErrConflict
		}
	}
	for key, record := range before.records {
		if changed[key] == nil && (!samePackageRecord(record, after.records[key]) || before.identities[key] != after.identities[key]) {
			return fmt.Errorf("%w: unmanifested native package change %s", ErrOutcomeUnknown, key)
		}
	}
	for key := range after.records {
		if before.records[key] == nil && changed[key] == nil {
			return fmt.Errorf("%w: unmanifested native package install %s", ErrOutcomeUnknown, key)
		}
	}
	return nil
}

// ValidateNativePlan binds the already-validated plan to its complete native
// manifest, including the effect summary used before issuing a final grant.
func ValidateNativePlan(plan *resourcev1.ResourcePlan, manifest *resourcev1.PackageTransactionManifest) error {
	changePackages, err := manifestChangesPackages(manifest)
	if err != nil {
		return err
	}
	if plan.GetNativePackage().GetChangePackages() != changePackages {
		return errors.New("packageprovider: package effect summary does not match native manifest")
	}
	if !bytes.Equal(manifest.GetNativeDatabaseRevision(), plan.GetNativePackage().GetNativeDatabaseRevision()) || manifest.GetNativeLockIdentity() != plan.GetNativePackage().GetNativeLockIdentity() {
		return ErrConflict
	}
	if len(manifest.GetAffectedResources()) != 1 || len(manifest.GetAffectedDesiredSha256()) != 1 || !proto.Equal(manifest.GetAffectedResources()[0], plan.GetRef()) || !bytes.Equal(manifest.GetAffectedDesiredSha256()[0], plan.GetDesiredSha256()) {
		return errors.New("packageprovider: manifest is not bound to signed resource plan")
	}
	if manifest.GetOriginalPin() != nil {
		if !proto.Equal(manifest.GetOriginalPin(), plan.GetBefore().GetNativePackage().GetPinFile()) {
			return ErrConflict
		}
		digest := sha256.Sum256(pinProjection(plan.GetBackend().GetBackend(), plan.GetNativePackage().GetPinContents()))
		if !bytes.Equal(digest[:], manifest.GetCandidatePinSha256()) {
			return ErrConflict
		}
	} else if len(manifest.GetCandidatePinSha256()) != 0 {
		return ErrConflict
	}
	return nil
}
func manifestChangesPackages(manifest *resourcev1.PackageTransactionManifest) (bool, error) {
	if manifest == nil {
		return false, ErrConflict
	}
	for _, entry := range manifest.GetEntries() {
		switch entry.GetOperation() {
		case resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_INSTALL, resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_UPGRADE, resourcev1.PackageTransactionOperation_PACKAGE_TRANSACTION_OPERATION_REMOVE_OWNED:
		default:
			return false, errors.New("packageprovider: unsupported manifest transaction operation")
		}
	}
	return len(manifest.GetEntries()) != 0, nil
}
