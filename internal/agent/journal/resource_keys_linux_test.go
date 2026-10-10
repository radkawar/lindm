package journal

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func accountResourceRecord(t *testing.T, f serviceJournalFixture, kind resourcev1.ResourceKind) *agentv1.ResourceExecutionRecord {
	t.Helper()
	record := f.record(t, 1, "unused.service", true)
	ref := &resourcev1.ResourceRef{Kind: kind, CanonicalKey: "same"}
	desired := &resourcev1.ResourceDesiredState{Ref: ref}
	plan := record.NativePlan
	plan.Ref = proto.CloneOf(ref)
	plan.Before.Ref = proto.CloneOf(ref)
	plan.Backend.Backend = resourcev1.Backend_BACKEND_SHADOW
	plan.Before.Metadata.Backend = proto.CloneOf(plan.Backend)
	plan.Safety.LockDomains = []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT}
	if kind == resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP {
		group := &resourcev1.LocalGroupDesired{Name: "same", Presence: resourcev1.Presence_PRESENCE_PRESENT}
		desired.State = &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: group}
		plan.Before.Observed = &resourcev1.ResourceObservation_LocalGroup{LocalGroup: &resourcev1.LocalGroupObservation{Name: "same", Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, LocalFileRevision: make([]byte, 32), IdentitySha256: make([]byte, 32)}}
		plan.Plan = &resourcev1.ResourcePlan_LocalGroup{LocalGroup: &resourcev1.LocalGroupPlan{Desired: group, Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE, ExpectedLocalRevision: make([]byte, 32), ExpectedIdentitySha256: make([]byte, 32)}}
	} else {
		user := &resourcev1.LocalUserDesired{Name: "same", Presence: resourcev1.Presence_PRESENCE_PRESENT}
		desired.State = &resourcev1.ResourceDesiredState_LocalUser{LocalUser: user}
		plan.Before.Observed = &resourcev1.ResourceObservation_LocalUser{LocalUser: &resourcev1.LocalUserObservation{Name: "same", Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, LocalFileRevision: make([]byte, 32), IdentitySha256: make([]byte, 32)}}
		plan.Plan = &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: user, Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE, ExpectedLocalRevision: make([]byte, 32), ExpectedIdentitySha256: make([]byte, 32)}}
	}
	record.Intent.Desired = desired
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	plan.DesiredSha256 = desiredDigest[:]
	observationDigest, err := resource.ObservationDigest(plan.GetBefore())
	if err != nil {
		t.Fatal(err)
	}
	plan.ObservationSha256 = observationDigest[:]
	planDigest, err := resource.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	record.Challenge.Ref = proto.CloneOf(ref)
	record.Challenge.NativePlanSha256 = planDigest[:]
	return record
}

func TestResourceKeysKeepCrossKindFloorsAndOwnershipIndependent(t *testing.T) {
	f := newServiceJournalFixture(t)
	var ledgers []*agentv1.ResourceOwnershipLedger
	for _, kind := range []resourcev1.ResourceKind{resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER} {
		record := queueOwnershipAction(t, f, accountResourceRecord(t, f, kind))
		ledger, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, ownershipSnapshot(record))
		if err != nil {
			t.Fatal(err)
		}
		ledgers = append(ledgers, ledger)
		if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, accountResourceRecord(t, f, kind)); !errors.Is(err, ErrResourceActionRejected) {
			t.Fatalf("same-kind floor replay accepted: %v", err)
		}
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	for _, ledger := range ledgers {
		got, err := reopened.LoadResourceOwnership(t.Context(), ledger.GetDeploymentId(), ledger.GetDeviceId(), ledger.GetEnrollmentGeneration(), ledger.GetRef())
		if err != nil || !proto.Equal(got, ledger) {
			t.Fatalf("compound key collapsed ownership: %v", err)
		}
	}
}

func TestResourceOwnershipNativePinIdentityAndUnrelatedDatabaseDrift(t *testing.T) {
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}
	pkg := &resourcev1.NativePackageObservation{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "example", Architecture: "amd64"}, DatabaseRevisionSha256: make([]byte, 32), PinFile: &resourcev1.FileIdentity{Path: "/etc/apt/preferences.d/lindm-example", Device: 1, Inode: 2, Mode: 0644, Sha256: make([]byte, 32)}, PinContents: []byte("Package: example\nPin: version 1\nPin-Priority: 1001\n")}
	last := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: ref, Observed: &resourcev1.ResourceObservation_NativePackage{NativePackage: pkg}}}
	current := proto.CloneOf(last)
	current.Observation.GetNativePackage().DatabaseRevisionSha256 = bytes.Repeat([]byte{1}, 32)
	dimensions := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_NATIVE_PACKAGE_PIN}
	if !ownershipDimensionsMatch(last, current, dimensions) {
		t.Fatal("unrelated package transaction erased pin ownership")
	}
	current.Observation.GetNativePackage().PinFile.Inode++
	if ownershipDimensionsMatch(last, current, dimensions) {
		t.Fatal("ABA same-content replacement inherited native pin ownership")
	}
}

func TestResourceOwnershipCapacityReservedBeforeEffect(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := queueOwnershipAction(t, f, f.record(t, 1, "reserved.service", true))
	before := ownershipSnapshot(record)
	if _, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, before); err != nil {
		t.Fatal(err)
	}
	// Saturate only the admission counter; corruption/restart tests independently
	// establish exact totals. Existing lifecycle transitions use their reservation.
	if _, err := f.store.db.Exec("UPDATE resource_ownership_usage SET record_count = 256"); err != nil {
		t.Fatal(err)
	}
	overflow := queueOwnershipAction(t, f, f.record(t, 1, "overflow.service", true))
	if _, err := f.store.ClaimResourceOwnership(t.Context(), overflow.GetIntent().GetActionId(), 0, ownershipSnapshot(overflow)); !errors.Is(err, ErrResourceOwnershipCapacity) {
		t.Fatalf("ownership admitted without lifecycle reservation: %v", err)
	}
	if _, err := f.store.LoadResourceOwnership(t.Context(), overflow.GetIntent().GetDeploymentId(), overflow.GetIntent().GetDeviceId(), overflow.GetIntent().GetEnrollmentGeneration(), overflow.GetIntent().GetDesired().GetRef()); !errors.Is(err, ErrResourceOwnershipNotFound) {
		t.Fatalf("failed reservation partially claimed ownership: %v", err)
	}
	pending, err := f.store.BeginResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), 1, before, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME})
	if err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CompleteResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), int64(pending.GetRevision()), &agentv1.ResourceOwnershipSnapshot{Observation: serviceConverged(running).GetAfter()}); err != nil {
		t.Fatalf("native outcome lost reserved capacity: %v", err)
	}
}
