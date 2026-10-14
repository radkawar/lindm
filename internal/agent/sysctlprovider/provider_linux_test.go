// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sysctlprovider

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func TestApplyIdempotenceAndOwnershipSafeRelease(t *testing.T) {
	ctx := context.Background()
	p, store, current, desired := fixtureProvider(t)
	plan, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	gates := 0
	verification, err := p.Apply(ctx, plan, func(context.Context) error {
		gates++
		if store.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
			t.Fatal("effect precedes durable unknown ownership")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verification.GetSysctl().GetConverged() || gates != 1 || store.complete != 1 {
		t.Fatal("apply missing protected completion")
	}
	if store.ledger.GetBaseline().GetObservation().GetSysctl().GetValue() != "60" {
		t.Fatal("baseline overwritten")
	}
	plan, err = p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetSysctl().GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE {
		t.Fatal("equal live state requested another kernel write")
	}
	verification, err = p.Verify(ctx, plan)
	if err != nil || !verification.GetSysctl().GetConverged() {
		t.Fatalf("idempotent verify: %v", err)
	}
	store.releasing = true
	release, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	verification, err = p.Apply(ctx, release, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !verification.GetSysctl().GetConverged() || (*current).GetObservation().GetSysctl().GetValue() != "60" || store.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		t.Fatal("release did not restore owned baseline")
	}
}
func TestUnknownEffectIsNeverReplayed(t *testing.T) {
	for _, mode := range []string{"native partial", "completion failure", "gate rejection", "missing callback"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			p, store, current, desired := fixtureProvider(t)
			calls := 0
			p.config.NativeApply = func(ctx context.Context, r *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) error {
				calls++
				if mode == "missing callback" {
					return nil
				}
				if err := gate(ctx); err != nil {
					return err
				}
				*current = proto.CloneOf(r.GetTarget())
				if mode == "native partial" {
					return errors.New("kernel write failed after persistent effect")
				}
				return nil
			}
			if mode == "completion failure" {
				store.completionErr = errors.New("journal fsync failed")
			}
			plan, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Apply(ctx, plan, func(context.Context) error {
				if mode == "gate rejection" {
					return errors.New("expired signed grant")
				}
				return nil
			})
			if !errors.Is(err, ErrOutcomeUnknown) || store.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN || store.complete != 0 {
				t.Fatalf("uncertain effect was successful: %v", err)
			}
			if _, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("unknown ownership allowed another plan")
			}
			if _, err := p.Apply(ctx, plan, func(context.Context) error { return nil }); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("unknown ownership allowed replay")
			}
			if calls != 1 {
				t.Fatal("native uncertain effect replayed")
			}
		})
	}
}
func TestStalePlanRejectedBeforeFinalGate(t *testing.T) {
	p, _, current, desired := fixtureProvider(t)
	ctx := context.Background()
	plan, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	(*current).GetObservation().GetSysctl().Value = proto.String("40")
	called := false
	if _, err := p.Apply(ctx, plan, func(context.Context) error { called = true; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale plan accepted: %v", err)
	}
	if called {
		t.Fatal("authority consumed before native preconditions")
	}
}
func TestReleaseRefusesRuntimeIdentityAndPersistentDrift(t *testing.T) {
	_, store, current, desired := fixtureProvider(t)
	baseline := proto.CloneOf(*current)
	last := persistentFixture(*current, "20")
	store.ledger = &agentv1.ResourceOwnershipLedger{Owner: store.owner, Baseline: baseline, LastApplied: last, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE}}
	for _, change := range []func(*agentv1.ResourceOwnershipSnapshot){
		func(s *agentv1.ResourceOwnershipSnapshot) { s.GetObservation().GetSysctl().Value = proto.String("21") },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.GetObservation().GetSysctl().NativeIdentitySha256[0]++ },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.SysctlPersistence.State.File.Inode++ },
		func(s *agentv1.ResourceOwnershipSnapshot) {
			s.SysctlPersistence.Content = append(s.SysctlPersistence.Content, '#')
		},
	} {
		now := proto.CloneOf(last)
		change(now)
		if _, err := targetSnapshot(desired.GetSysctl(), now, store.ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
			t.Fatal("release overwrote external managed dimension")
		}
	}
	target, err := targetSnapshot(desired.GetSysctl(), last, store.ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if target.GetSysctlPersistence().GetState().GetExists() || target.GetObservation().GetSysctl().GetValue() != "60" {
		t.Fatal("private baseline not restored")
	}
}

// Release after a reboot was refused because the live value's boot-scoped
// identity changed although the owned stanza had re-applied it at boot.
func TestReleaseAfterRebootRestoresBaseline(t *testing.T) {
	_, store, current, desired := fixtureProvider(t)
	baseline := proto.CloneOf(*current)
	last := persistentFixture(*current, "20")
	store.ledger = &agentv1.ResourceOwnershipLedger{Owner: store.owner, Baseline: baseline, LastApplied: last, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE}}
	rebooted := proto.CloneOf(last)
	rebooted.Observation.Metadata.BootId = "8d2f1c44-0a51-4f0e-9a43-6b1f3c2e7d90"
	rebooted.GetObservation().GetSysctl().NativeIdentitySha256[0]++
	target, err := targetSnapshot(desired.GetSysctl(), rebooted, store.ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatalf("release after reboot refused: %v", err)
	}
	if target.GetSysctlPersistence().GetState().GetExists() || target.GetObservation().GetSysctl().GetValue() != "60" {
		t.Fatal("private baseline not restored after reboot")
	}
	rebooted.SysctlPersistence.Content = append(rebooted.SysctlPersistence.Content, '#')
	if _, err := targetSnapshot(desired.GetSysctl(), rebooted, store.ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
		t.Fatal("reboot excused an external stanza edit")
	}
}
func TestReleaseInverseIgnoresObservationTimestampNotState(t *testing.T) {
	_, store, current, desired := fixtureProvider(t)
	last := proto.CloneOf(*current)
	store.ledger = &agentv1.ResourceOwnershipLedger{Owner: store.owner, Baseline: last, LastApplied: last, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE}}
	target, err := targetSnapshot(desired.GetSysctl(), last, store.ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	first, err := inverseBinding(store.ledger, last, target)
	if err != nil {
		t.Fatal(err)
	}
	target.Observation.Metadata.ObservedAt = timestamppb.Now()
	second, err := inverseBinding(store.ledger, last, target)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(first, second) {
		t.Fatal("fresh observation invalidated identical inverse")
	}
	target.Observation.GetSysctl().Value = proto.String("30")
	third, err := inverseBinding(store.ledger, last, target)
	if err != nil {
		t.Fatal(err)
	}
	if proto.Equal(second, third) {
		t.Fatal("changed inverse value not bound")
	}
}
func TestPersistenceAndRebootEvidenceAreDistinct(t *testing.T) {
	p, store, current, desired := fixtureProvider(t)
	ctx := context.Background()
	plan, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	plan.GetSysctl().Desired.Persistent = true
	desired.GetSysctl().Persistent = true
	digest, err := resource.DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	plan.DesiredSha256 = digest[:]
	plan.Claims, err = resource.Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	after := persistentFixture(*current, "20")
	ledger := &agentv1.ResourceOwnershipLedger{Owner: store.owner, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, LastApplied: proto.CloneOf(after)}
	verified, err := verificationFor(plan, after, ledger, after, false)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.GetSysctl().GetConverged() || verified.GetSysctl().GetRebootPersistenceVerified() {
		t.Fatal("initial convergence claimed a reboot")
	}
	after.Observation.Metadata.BootId = fixtureNextBoot
	verified, err = verificationFor(plan, after, ledger, after, false)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.GetSysctl().GetRebootPersistenceVerified() {
		t.Fatal("cross-boot unchanged persistence not recorded")
	}
	after.GetObservation().GetSysctl().PersistenceConflict = true
	verified, err = verificationFor(plan, after, ledger, after, false)
	if err != nil {
		t.Fatal(err)
	}
	if verified.GetSysctl().GetConverged() || verified.GetSysctl().GetRebootPersistenceVerified() {
		t.Fatal("conflicting configuration became persistent convergence")
	}
}
func TestCanonicalDesiredAndApprovalAreRequired(t *testing.T) {
	p, store, _, desired := fixtureProvider(t)
	for _, key := range []string{"kernel.panic", "net/ipv4/ip_forward", "vm..swappiness", "vm.dirty_ratio"} {
		candidate := proto.CloneOf(desired)
		candidate.GetSysctl().Key = key
		candidate.Ref = sysctlRef(key)
		if err := p.validateDesired(candidate); err == nil {
			t.Fatalf("unapproved or noncanonical key %s accepted", key)
		}
	}
	store.owner.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY
	if _, err := p.Plan(context.Background(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatal("live key implicitly adopted")
	}
}

func TestReleaseRestoresExistingStanzaMetadataAndRetainDoesNotWrite(t *testing.T) {
	_, store, current, desired := fixtureProvider(t)
	baseline := persistentFixture(*current, "60")
	baseline.SysctlPersistence.State.File.Mode = 0600
	baseline.Observation.GetSysctl().PersistenceFileState = proto.CloneOf(baseline.SysctlPersistence.State)
	baseline.Observation.GetSysctl().OwnedPersistenceFile = proto.CloneOf(baseline.SysctlPersistence.State.File)
	last := persistentFixture(*current, "20")
	ledger := &agentv1.ResourceOwnershipLedger{Owner: proto.CloneOf(store.owner), Baseline: baseline, LastApplied: last, OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_VALUE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE}}
	target, err := targetSnapshot(desired.GetSysctl(), last, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if !fileTargetMatches(target.GetSysctlPersistence(), baseline.GetSysctlPersistence()) || target.GetObservation().GetSysctl().GetValue() != "60" {
		t.Fatal("adopted original stanza bytes/mode not restored")
	}
	ledger.Owner.Policy.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN
	target, err = targetSnapshot(desired.GetSysctl(), last, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	request := &agentv1.NativeResourceTransactionRequest{Before: last, Target: target}
	if NeedsRuntimeWrite(request) || NeedsPersistenceWrite(request) {
		t.Fatal("retain release requested native privileges")
	}
}

func TestPersistentSameContentReplacementIsOwnershipDrift(t *testing.T) {
	p, store, current, desired := fixtureProvider(t)
	plan, err := p.Plan(context.Background(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	desired.GetSysctl().Persistent = true
	plan.GetSysctl().Desired.Persistent = true
	digest, err := resource.DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	plan.DesiredSha256 = digest[:]
	plan.Claims, err = resource.Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	after := persistentFixture(*current, "20")
	ledger := &agentv1.ResourceOwnershipLedger{Owner: store.owner, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, LastApplied: proto.CloneOf(after)}
	after.SysctlPersistence.State.File.Inode++
	after.Observation.GetSysctl().PersistenceFileState = proto.CloneOf(after.SysctlPersistence.State)
	after.Observation.GetSysctl().OwnedPersistenceFile = proto.CloneOf(after.SysctlPersistence.State.File)
	verification, err := verificationFor(plan, after, ledger, after, false)
	if err != nil {
		t.Fatal(err)
	}
	if verification.GetSysctl().GetConverged() || verification.GetSysctl().GetPersistenceOwnerMatches() {
		t.Fatal("same-content unowned replacement accepted")
	}
}

func TestPartialFileEffectCannotBecomeSuccessfulRuntimeApply(t *testing.T) {
	p, store, current, desired := fixtureProvider(t)
	ctx := context.Background()
	// Existing stanzas avoid native creation metadata in this deterministic
	// provider test. The native callback intentionally leaves only the file
	// half of the requested state applied, without claiming native coverage.
	*current = persistentFixture(*current, "60")
	plan, err := p.Plan(ctx, desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	desired.GetSysctl().Persistent = true
	plan.GetSysctl().Desired.Persistent = true
	digest, err := resource.DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	plan.DesiredSha256 = digest[:]
	plan.Claims, err = resource.Claims(desired)
	if err != nil {
		t.Fatal(err)
	}
	p.config.NativeApply = func(ctx context.Context, r *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) error {
		if err := gate(ctx); err != nil {
			return err
		}
		*current = proto.CloneOf(r.GetTarget())
		(*current).Observation.GetSysctl().Value = proto.String("60")
		return nil // A transport success is not native convergence evidence.
	}
	if _, err := p.Apply(ctx, plan, func(context.Context) error { return nil }); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("partial file effect succeeded: %v", err)
	}
	if store.complete != 0 || store.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		t.Fatal("partial native state finalized ownership")
	}
}
