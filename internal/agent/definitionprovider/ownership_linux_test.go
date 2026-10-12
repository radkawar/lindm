//go:build linux

package definitionprovider

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/journal"
)

func TestDefinitionReleaseRestoresOnlyOwnedBaseline(t *testing.T) {
	d := dropDesired()
	baseline := fixtureSnapshot(t, d, false)
	baseline.GetObservation().GetSystemdDefinition().EffectiveOptions.CpuWeight = 50
	current := fixtureSnapshot(t, d, true)
	ledger := fixtureLedger(t, d, baseline, current)
	target, err := targetImage(context.Background(), d, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if target.GetDefinitionFile().GetState().GetExists() || target.GetObservation().GetSystemdDefinition().GetEffectiveOptions().GetCpuWeight() != 50 {
		t.Fatal("release failed to restore captured absence/options")
	}
	if !current.GetDefinitionFile().GetState().GetExists() {
		t.Fatal("release planning mutated before evidence")
	}
	ledger.Owner.Policy.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN
	target, err = targetImage(context.Background(), d, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil || !imageEqual(target, current) {
		t.Fatalf("retain changed native state: %v", err)
	}
}
func TestDefinitionReleaseRefusesNativeIdentityDrift(t *testing.T) {
	d := timerDesired()
	baseline := fixtureSnapshot(t, d, false)
	current := fixtureSnapshot(t, d, true)
	ledger := fixtureLedger(t, d, baseline, current)
	for name, mutate := range map[string]func(*agentv1.ResourceOwnershipSnapshot){
		"inode": func(s *agentv1.ResourceOwnershipSnapshot) { s.DefinitionFile.State.File.Inode++ },
		"security metadata": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.DefinitionFile.State.SecurityMetadataSha256 = bytes.Repeat([]byte{99}, 32)
		},
		"parent": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.DefinitionFile.ParentIdentitySha256 = bytes.Repeat([]byte{99}, 32)
		},
		"link replacement": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().TimerInstallLinks[0].Inode++
		},
		"invocation": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().TimerInvocationId = bytes.Repeat([]byte{99}, 16)
		},
		"boot": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.Metadata.BootId = "22222222-2222-4222-8222-222222222222"
		},
		"foreign definition": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().TargetDefinitionSha256 = bytes.Repeat([]byte{99}, 32)
		},
		"pending reload": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().DaemonReloadPending = true
		},
		"pending job": func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetSystemdDefinition().TimerJobPending = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			drift := proto.CloneOf(current)
			mutate(drift)
			if _, err := targetImage(context.Background(), d, drift, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrConflict) {
				t.Fatalf("release with drift = %v", err)
			}
		})
	}
}
func TestOwnershipUnknownAndHistoricalBaselineNeverReplay(t *testing.T) {
	d := timerDesired()
	current := fixtureSnapshot(t, d, true)
	if _, err := targetImage(context.Background(), d, current, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrBaselineUnknown) {
		t.Fatalf("historical release = %v", err)
	}
	ledger := fixtureLedger(t, d, fixtureSnapshot(t, d, false), current)
	ledger.State = agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN
	if err := acquisitionAllowed(fixtureOwner(), current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("interrupted effect replay = %v", err)
	}
	if _, err := targetImage(context.Background(), d, current, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); !errors.Is(err, ErrBaselineUnknown) {
		t.Fatalf("interrupted release = %v", err)
	}
}
func TestAcquisitionRequiresApprovedAdoption(t *testing.T) {
	d := dropDesired()
	before := fixtureSnapshot(t, d, true)
	owner := fixtureOwner()
	if err := acquisitionAllowed(owner, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrAdoptionRequired) || !errors.Is(err, ErrConflict) || admissiondetail.Of(err) != "existing_definition" {
		t.Fatalf("unapproved overwrite = %v", err)
	}
	owner.Policy.Mode = resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
	if err := acquisitionAllowed(owner, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing approval = %v", err)
	}
	owner.Policy.AdoptionApprovalId = proto.String(fixtureID)
	if err := acquisitionAllowed(owner, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err != nil {
		t.Fatal(err)
	}
	ledger := fixtureLedger(t, d, fixtureSnapshot(t, d, false), before)
	other := fixtureOwner()
	other.Sources[0].ResourceId = "22222222-2222-4222-8222-222222222222"
	if err := acquisitionAllowed(other, before, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrConflict) {
		t.Fatalf("owner takeover = %v", err)
	}
}
func TestTimerPlanIsIdempotentAndBindsOwnership(t *testing.T) {
	d := timerDesired()
	before := fixtureSnapshot(t, d, true)
	ledger := fixtureLedger(t, d, fixtureSnapshot(t, d, false), before)
	p := fixtureProvider()
	target, err := targetImage(context.Background(), d, before, ledger, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.makePlan(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetSystemdDefinition().GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE || plan.GetSystemdDefinition().GetDaemonReload() {
		t.Fatalf("already converged timer plans mutation: %v", plan.GetSystemdDefinition())
	}
	digest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest[:], plan.GetOwnershipRevisionSha256()) {
		t.Fatal("plan omitted durable ownership revision")
	}
	verification, err := definitionVerification(plan, before, target)
	if err != nil || !verification.GetSystemdDefinition().GetConverged() {
		t.Fatalf("idempotent verification = %v, %v", verification, err)
	}
	before.Observation.GetSystemdDefinition().TimerActive = proto.Bool(false)
	if definitionChecks(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target).GetConverged() {
		t.Fatal("enabled but stopped timer reported converged")
	}
}
func TestDropInVerificationUsesNativeOptionsNotOnlyFile(t *testing.T) {
	d := dropDesired()
	before := fixtureSnapshot(t, d, true)
	target := proto.CloneOf(before)
	before.Observation.GetSystemdDefinition().EffectiveOptions.MemoryMax = ^uint64(0)
	checks := definitionChecks(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target)
	if !checks.GetDefinitionMatches() || checks.GetEffectiveOptionsMatch() || checks.GetConverged() {
		t.Fatalf("byte-only convergence: %v", checks)
	}
}

func TestNativeFileWrapperRetainsCustodyRevision(t *testing.T) {
	snapshot := fixtureSnapshot(t, dropDesired(), true)
	wrapped := fileSnapshot(snapshot)
	if !bytes.Equal(wrapped.GetObservation().GetMetadata().GetNativeRevision(), snapshot.GetDefinitionFile().GetNativeRevisionSha256()) {
		t.Fatal("file preparation received aggregate definition revision instead of nativefile custody revision")
	}
	if bytes.Equal(wrapped.GetObservation().GetMetadata().GetNativeRevision(), snapshot.GetObservation().GetMetadata().GetNativeRevision()) {
		t.Fatal("test fixture does not distinguish file and definition revisions")
	}
	wrapped.Observation.GetManagedFile().File.Inode++
	if wrapped.GetObservation().GetManagedFile().GetFile().GetInode() == snapshot.GetDefinitionFile().GetState().GetFile().GetInode() {
		t.Fatal("mutable helper projection aliases protected baseline")
	}
}

func TestPlanRefusesAnUnrelatedEffectiveOverride(t *testing.T) {
	d := dropDesired()
	before := fixtureSnapshot(t, d, true)
	before.Observation.GetSystemdDefinition().EffectiveOptions.CpuWeight = 900
	target, err := targetImage(context.Background(), d, before, nil, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixtureProvider().makePlan(d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("unrelated override accepted as a repairable plan: %v", err)
	}
}
