package journal

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func ownershipSnapshot(record *agentv1.ResourceExecutionRecord) *agentv1.ResourceOwnershipSnapshot {
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(record.GetNativePlan().GetBefore())}
	if snapshot.GetObservation().GetLocalUser() != nil || snapshot.GetObservation().GetLocalGroup() != nil {
		snapshot.AccountPrivate = &agentv1.ResourceAccountPrivate{NativeGeneration: snapshot.GetObservation().GetMetadata().GetExecutorIncarnation(), IdentityAnchorSha256: make([]byte, 32)}
	}
	return snapshot
}

func queueOwnershipAction(t *testing.T, f serviceJournalFixture, record *agentv1.ResourceExecutionRecord) *agentv1.ResourceExecutionRecord {
	t.Helper()
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	return queued
}

func ownershipPlanBinding(t *testing.T, record *agentv1.ResourceExecutionRecord, ledger *agentv1.ResourceOwnershipLedger, before *agentv1.ResourceOwnershipSnapshot, release bool) {
	t.Helper()
	if ledger != nil {
		record.Intent.Ownership = proto.CloneOf(ledger.GetOwner())
	}
	plan := record.NativePlan
	plan.Before = proto.CloneOf(before.GetObservation())
	plan.GetSystemdService().Before = proto.CloneOf(plan.GetBefore().GetSystemdService())
	plan.Backend = proto.CloneOf(plan.GetBefore().GetMetadata().GetBackend())
	digest, err := ResourceOwnershipDigest(ledger)
	if err != nil {
		t.Fatal(err)
	}
	plan.OwnershipRevisionSha256 = digest[:]
	if release {
		record.Intent.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
		plan.Operation = record.Intent.GetOperation()
		plan.GetSystemdService().Inverse = &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: bytes.Clone(digest[:]), LastAppliedSha256: bytes.Repeat([]byte{1}, 32), NativeIdentitySha256: bytes.Repeat([]byte{2}, 32), InverseSha256: bytes.Repeat([]byte{3}, 32)}
	}
	observationDigest, err := resource.ObservationDigest(plan.GetBefore())
	if err != nil {
		t.Fatal(err)
	}
	plan.ObservationSha256 = observationDigest[:]
	planDigest, err := resource.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	record.Challenge.NativePlanSha256 = planDigest[:]
	record.Challenge.BootId = plan.GetBefore().GetMetadata().GetBootId()
	record.Challenge.Operation = record.GetIntent().GetOperation()
}

func applyOwnershipFixture(t *testing.T, f serviceJournalFixture) (*agentv1.ResourceOwnershipLedger, *agentv1.ResourceOwnershipSnapshot) {
	t.Helper()
	record := queueOwnershipAction(t, f, f.record(t, 1, "owned.service", true))
	before := ownershipSnapshot(record)
	ledger, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, before)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err = f.store.BeginResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), int64(ledger.GetRevision()), before, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME})
	if err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	after := &agentv1.ResourceOwnershipSnapshot{Observation: serviceConverged(running).GetAfter()}
	ledger, err = f.store.CompleteResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), int64(ledger.GetRevision()), after)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 3, 1, 2, serviceCompleted(running)); err != nil {
		t.Fatal(err)
	}
	return ledger, after
}

func TestResourceOwnershipConcurrentClaimCAS(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := queueOwnershipAction(t, f, f.record(t, 1, "owned.service", true))
	before := ownershipSnapshot(record)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Go(func() {
			_, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, before)
			results <- err
		})
	}
	group.Wait()
	close(results)
	var accepted, rejected int
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrConflict) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("claim winners=%d conflicts=%d", accepted, rejected)
	}
	ledger, err := f.store.LoadResourceOwnership(t.Context(), record.GetIntent().GetDeploymentId(), record.GetIntent().GetDeviceId(), record.GetIntent().GetEnrollmentGeneration(), record.GetIntent().GetDesired().GetRef())
	if err != nil {
		t.Fatal(err)
	}
	if ledger.GetRevision() != 1 || !proto.Equal(ledger.GetBaseline(), before) || !bytes.Equal(ledger.GetOwnerIntentEnvelope(), record.GetIntentEnvelope()) {
		t.Fatal("claim did not durably bind baseline and signed owner")
	}
	ledger.Baseline.Observation.GetSystemdService().ActiveState = "tampered"
	again, err := f.store.LoadResourceOwnership(t.Context(), record.GetIntent().GetDeploymentId(), record.GetIntent().GetDeviceId(), record.GetIntent().GetEnrollmentGeneration(), record.GetIntent().GetDesired().GetRef())
	if err != nil || !proto.Equal(again.GetBaseline(), before) {
		t.Fatal("caller mutation changed stored baseline")
	}
}

func TestResourceOwnershipUnknownSurvivesRestartWithoutReplay(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := queueOwnershipAction(t, f, f.record(t, 1, "owned.service", true))
	before := ownershipSnapshot(record)
	if _, err := f.store.ClaimResourceOwnership(t.Context(), record.GetIntent().GetActionId(), 0, before); err != nil {
		t.Fatal(err)
	}
	ledger, err := f.store.BeginResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), 1, before, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSTEMD_RUNTIME})
	if err != nil {
		t.Fatal(err)
	}
	if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN || !proto.Equal(ledger.GetBeforeEffect(), before) {
		t.Fatal("beforeEffect boundary did not persist uncertainty and native before-state")
	}
	if _, err := f.store.CompleteResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), 2, before); !errors.Is(err, ErrResourceOwnershipConflict) {
		t.Fatalf("effect completed without RUNNING authority: %v", err)
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, serviceRunning(record)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	got, err := reopened.LoadResourceOwnership(t.Context(), ledger.GetDeploymentId(), ledger.GetDeviceId(), ledger.GetEnrollmentGeneration(), ledger.GetRef())
	if err != nil || !proto.Equal(got, ledger) {
		t.Fatalf("restart erased unknown effect: %v", err)
	}
	if _, err := reopened.BeginResourceOwnershipEffect(t.Context(), record.GetIntent().GetActionId(), 2, before, ledger.GetOwnedDimensions()); err == nil {
		t.Fatal("RUNNING effect replayed")
	}
	if _, err := reopened.UpdateResourceAction(t.Context(), 3, 1, 2, serviceRunning(record)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("RUNNING transition replayed: %v", err)
	}
}

func TestResourceOwnershipReleaseDriftAndRevisionABA(t *testing.T) {
	f := newServiceJournalFixture(t)
	ledger, after := applyOwnershipFixture(t, f)
	release := f.record(t, 2, "owned.service", true)
	ownershipPlanBinding(t, release, ledger, after, true)
	release = queueOwnershipAction(t, f, release)
	drifted := proto.CloneOf(after)
	drifted.Observation.GetSystemdService().InvocationId = bytes.Repeat([]byte{9}, 16)
	if _, err := f.store.BeginResourceOwnershipEffect(t.Context(), release.GetIntent().GetActionId(), 3, drifted, ledger.GetOwnedDimensions()); !errors.Is(err, ErrResourceOwnershipDrift) {
		t.Fatalf("native identity replacement released: %v", err)
	}
	pending, err := f.store.BeginResourceOwnershipEffect(t.Context(), release.GetIntent().GetActionId(), 3, after, ledger.GetOwnedDimensions())
	if err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(release)
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	released, err := f.store.CompleteResourceOwnershipEffect(t.Context(), release.GetIntent().GetActionId(), int64(pending.GetRevision()), ledger.GetBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if released.GetRevision() != 5 || released.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		t.Fatal("release reset revision instead of retaining tombstone")
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 3, 1, 2, serviceCompleted(running)); err != nil {
		t.Fatal(err)
	}
	reclaim := f.record(t, 3, "owned.service", true)
	ownershipPlanBinding(t, reclaim, released, released.GetBaseline(), false)
	reclaim = queueOwnershipAction(t, f, reclaim)
	if _, err := f.store.ClaimResourceOwnership(t.Context(), reclaim.GetIntent().GetActionId(), 0, released.GetBaseline()); !errors.Is(err, ErrConflict) {
		t.Fatalf("ABA claim reused absent revision: %v", err)
	}
	claimed, err := f.store.ClaimResourceOwnership(t.Context(), reclaim.GetIntent().GetActionId(), 5, released.GetBaseline())
	if err != nil || claimed.GetRevision() != 6 {
		t.Fatalf("CAS reclaim revision=%d: %v", claimed.GetRevision(), err)
	}
}

func TestResourceOwnershipRejectsStealingAndStalePlan(t *testing.T) {
	for _, change := range []string{"owner", "plan_revision"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			ledger, after := applyOwnershipFixture(t, f)
			next := f.record(t, 2, "owned.service", true)
			ownershipPlanBinding(t, next, ledger, after, false)
			if change == "owner" {
				next.Intent.Ownership.Sources[0].ProfileId = uuid.NewString()
			} else {
				next.NativePlan.OwnershipRevisionSha256 = make([]byte, 32)
				digest, err := resource.PlanDigest(next.GetNativePlan())
				if err != nil {
					t.Fatal(err)
				}
				next.Challenge.NativePlanSha256 = digest[:]
			}
			next = queueOwnershipAction(t, f, next)
			if _, err := f.store.ClaimResourceOwnership(t.Context(), next.GetIntent().GetActionId(), 3, after); err == nil {
				t.Fatal("stale or foreign owner acquired baseline")
			}
		})
	}
}

func TestResourceOwnershipReconcileRepairsOwnedDrift(t *testing.T) {
	f := newServiceJournalFixture(t)
	ledger, after := applyOwnershipFixture(t, f)
	drifted := proto.CloneOf(after)
	drifted.Observation.GetSystemdService().ActiveState = "inactive"
	drifted.Observation.GetSystemdService().SubState = "dead"
	next := f.record(t, 2, "owned.service", true)
	ownershipPlanBinding(t, next, ledger, drifted, false)
	next = queueOwnershipAction(t, f, next)
	pending, err := f.store.BeginResourceOwnershipEffect(t.Context(), next.GetIntent().GetActionId(), 3, drifted, ledger.GetOwnedDimensions())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(pending.GetBaseline(), ledger.GetBaseline()) || !proto.Equal(pending.GetBeforeEffect(), drifted) {
		t.Fatal("repair replaced original baseline or omitted actual drift before-state")
	}
}

func TestResourceOwnershipHistoricalBaselineRefused(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := queueOwnershipAction(t, f, f.record(t, 1, "historical.service", true))
	running := serviceRunning(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 3, 1, 2, serviceCompleted(running)); err != nil {
		t.Fatal(err)
	}
	next := queueOwnershipAction(t, f, f.record(t, 2, "historical.service", true))
	if _, err := f.store.ClaimResourceOwnership(t.Context(), next.GetIntent().GetActionId(), 0, ownershipSnapshot(next)); !errors.Is(err, ErrResourceOwnershipUnknown) {
		t.Fatalf("invented historical baseline: %v", err)
	}
}

func TestResourceOwnershipCorruptionNeverRepairs(t *testing.T) {
	for _, damage := range []string{"revision", "kind", "record", "unknown", "missing", "accounting", "owner"} {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			ledger, _ := applyOwnershipFixture(t, f)
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}
			db := openFixtureDB(t, f.directory, "rw")
			query := "UPDATE resource_ownership SET revision = revision + 1"
			var args []any
			switch damage {
			case "kind":
				query = "UPDATE resource_ownership SET kind = 2"
			case "missing":
				query = "DELETE FROM resource_ownership"
			case "accounting":
				query = "UPDATE resource_ownership_usage SET record_count = 0"
			case "record":
				query, args = "UPDATE resource_ownership SET record = ?", []any{[]byte{0xff}}
			case "unknown", "owner":
				if damage == "unknown" {
					ledger.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
				} else {
					ledger.Owner.Sources[0].ProfileId = uuid.NewString()
				}
				encoded, err := proto.Marshal(ledger)
				if err != nil {
					t.Fatal(err)
				}
				query, args = "UPDATE resource_ownership SET record = ?", []any{encoded}
			}
			if _, err := db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			before := serviceDatabaseSnapshot(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("damaged ownership opened: %v", err)
			}
			db = openFixtureDB(t, f.directory, "ro")
			defer func() { _ = db.Close() }()
			if serviceDatabaseSnapshot(t, db) != before {
				t.Fatal("recovery hold rewrote ownership evidence")
			}
		})
	}
}

func TestResourceOwnershipEnrollmentCannotStealOlderGeneration(t *testing.T) {
	f := newServiceJournalFixture(t)
	ledger, _ := applyOwnershipFixture(t, f)
	nextAuthority := proto.CloneOf(f.authority)
	nextAuthority.EnrollmentGeneration = proto.String(uuid.NewString())
	if _, err := f.store.Update(t.Context(), 1, nextAuthority); err != nil {
		t.Fatal(err)
	}
	f.authority = nextAuthority
	record := f.record(t, 1, ledger.GetRef().GetCanonicalKey(), true)
	if _, err := f.store.AcceptResourceAction(t.Context(), 2, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 2, 2, queued); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ClaimResourceOwnership(t.Context(), queued.GetIntent().GetActionId(), 0, ownershipSnapshot(queued)); !errors.Is(err, ErrResourceOwnershipConflict) {
		t.Fatalf("new generation stole unreleased native owner: %v", err)
	}
}

func TestResourceOwnershipStableSourcesPermitRevisionChanges(t *testing.T) {
	f := newServiceJournalFixture(t)
	ledger, after := applyOwnershipFixture(t, f)
	next := f.record(t, 2, "owned.service", true)
	ownershipPlanBinding(t, next, ledger, after, false)
	next.Intent.Ownership.AssignmentId = uuid.NewString()
	next.Intent.Ownership.Sources[0].ProfileRevision = uuid.NewString()
	next = queueOwnershipAction(t, f, next)
	pending, err := f.store.BeginResourceOwnershipEffect(t.Context(), next.GetIntent().GetActionId(), 3, after, ledger.GetOwnedDimensions())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(pending.GetBaseline(), ledger.GetBaseline()) || !proto.Equal(pending.GetOwner(), next.GetIntent().GetOwnership()) {
		t.Fatal("revision update lost original baseline or signed current source binding")
	}
}
