package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// These fixtures test protected typed storage. Signature authentication is the
// executor's responsibility; opaque envelopes here are not signed authority.
type serviceJournalFixture struct {
	store     *Store
	directory string
	authority *agentv1.ExecutorJournalState
	trust     *agentv1.ExecutionTrustState
}

func newServiceJournalFixture(t *testing.T) serviceJournalFixture {
	t.Helper()
	f := serviceJournalFixture{directory: protectedDirectory(t), authority: acknowledgedState(t)}
	var err error
	f.store, err = Initialize(t.Context(), f.directory, f.authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	f.trust = configuredTrust(f.authority.GetInstallationId(), 1, 1, 1, time.Unix(1_800_000_000, 0).UTC())
	if revision, err := f.store.UpdateExecutionTrust(t.Context(), 1, f.trust); err != nil || revision != 2 {
		t.Fatalf("configure trust: revision=%d err=%v", revision, err)
	}
	return f
}

func (f serviceJournalFixture) record(t *testing.T, sequence uint64, unit string, drift bool) *agentv1.ServiceExecutionRecord {
	t.Helper()
	now := time.Unix(1_800_000_000+int64(sequence)*5, 0).UTC()
	intent := &agentv1.ServiceExecutionIntent{
		DeploymentId: f.trust.GetRoot().GetDeploymentId(), DeviceId: f.authority.GetDeviceId(), EnrollmentGeneration: f.authority.GetEnrollmentGeneration(),
		ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(), ResourceSequence: sequence, RecoveryEpoch: 1,
		RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Minute)),
		Desired: &agentv1.ServiceDesiredState{Unit: unit, Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED},
	}
	observation := &agentv1.ServiceObservation{
		Unit: unit, BootId: uuid.NewString(), ObservedAt: timestamppb.New(now), LoadState: "loaded", ActiveState: "inactive", SubState: "dead", UnitFileState: "disabled", ServiceType: "simple",
		DefinitionSha256: bytes.Repeat([]byte{1}, 32), FingerprintSha256: bytes.Repeat([]byte{2}, 32),
	}
	if !drift {
		observation.ActiveState, observation.SubState = "active", "running"
	}
	plan := &agentv1.ServicePlan{Desired: proto.CloneOf(intent.GetDesired()), Before: observation, ChangeRuntime: drift}
	envelope := []byte("opaque-intent-" + intent.GetActionId())
	digest := sha256.Sum256(envelope)
	record := &agentv1.ServiceExecutionRecord{
		FormatVersion: 1, InstallationId: f.authority.GetInstallationId(), IntentEnvelope: envelope, IntentSha256: digest[:], Intent: intent, NativePlan: plan,
		AcceptedRoot: proto.CloneOf(f.trust.GetRoot()), AcceptedDelegationEnvelope: bytes.Clone(f.trust.GetDelegationEnvelope()), AcceptedAt: timestamppb.New(now),
		State:   agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED,
		Failure: agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NONE,
	}
	if !drift {
		record.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED
		record.CompletedAt = timestamppb.New(now)
		record.Verification = serviceConverged(record)
		return record
	}
	encodedPlan, err := proto.MarshalOptions{Deterministic: true}.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planDigest := sha256.Sum256(encodedPlan)
	record.Challenge = &agentv1.ServiceExecutionChallenge{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(),
		DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: sequence, RecoveryEpoch: 1, IntentSha256: bytes.Clone(digest[:]), NativePlanSha256: planDigest[:],
		Nonce: bytes.Repeat([]byte{3}, 32), BootId: observation.GetBootId(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)),
	}
	record.ChallengeProof = []byte("opaque-device-proof")
	record.ChallengeCertificatePem = bytes.Repeat([]byte("C"), 96)
	record.ChallengeBoottimeNs = 30_000_000_000
	return record
}

func serviceQueued(record *agentv1.ServiceExecutionRecord) *agentv1.ServiceExecutionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED
	next.StartGrantEnvelope = []byte("opaque-start-" + record.GetIntent().GetActionId())
	digest := sha256.Sum256(next.GetStartGrantEnvelope())
	next.StartGrantSha256 = digest[:]
	next.GrantAcceptedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(time.Second))
	return next
}

func serviceRunning(record *agentv1.ServiceExecutionRecord) *agentv1.ServiceExecutionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING
	next.StartedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(2 * time.Second))
	return next
}

func serviceConverged(record *agentv1.ServiceExecutionRecord) *agentv1.ServiceVerification {
	observation := proto.CloneOf(record.GetNativePlan().GetBefore())
	observation.ActiveState, observation.SubState = "active", "running"
	return &agentv1.ServiceVerification{Observation: observation, RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, Converged: true}
}

func serviceCompleted(record *agentv1.ServiceExecutionRecord) *agentv1.ServiceExecutionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED
	next.CompletedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(3 * time.Second))
	next.Verification = serviceConverged(record)
	return next
}

func assertServiceRecord(t *testing.T, store *Store, expected *agentv1.ServiceExecutionRecord, revision int64) {
	t.Helper()
	got, gotRevision, err := store.LoadServiceAction(t.Context(), expected.GetIntent().GetActionId())
	if err != nil || gotRevision != revision || !proto.Equal(got, expected) {
		t.Fatalf("service record changed: revision=%d want=%d err=%v", gotRevision, revision, err)
	}
}

func TestServiceActionSequenceSupersessionAndRunningBusy(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	first := f.record(t, 1, "example.service", true)
	if revision, err := f.store.AcceptServiceAction(ctx, 1, 2, first); err != nil || revision != 1 {
		t.Fatalf("accept first: revision=%d err=%v", revision, err)
	}
	for _, replay := range []*agentv1.ServiceExecutionRecord{proto.CloneOf(first), f.record(t, 1, "example.service", true)} {
		if _, err := f.store.AcceptServiceAction(ctx, 1, 2, replay); !errors.Is(err, ErrServiceActionRejected) {
			t.Fatalf("sequence/action replay accepted: %v", err)
		}
	}
	queued := serviceQueued(first)
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	second := f.record(t, 2, "example.service", true)
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, second); err != nil {
		t.Fatal(err)
	}
	superseded := proto.CloneOf(queued)
	superseded.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED
	superseded.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_SUPERSEDED
	superseded.CompletedAt = proto.CloneOf(second.GetAcceptedAt())
	assertServiceRecord(t, f.store, superseded, 3)
	if _, err := f.store.UpdateServiceAction(ctx, 3, 1, 2, serviceRunning(queued)); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("superseded work started: %v", err)
	}
	queuedSecond := serviceQueued(second)
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, queuedSecond); err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(queuedSecond)
	if _, err := f.store.UpdateServiceAction(ctx, 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	third := f.record(t, 3, "example.service", true)
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, third); !errors.Is(err, ErrServiceActionBusy) {
		t.Fatalf("running resource superseded: %v", err)
	}
	assertServiceRecord(t, f.store, running, 3)
	if _, err := f.store.UpdateServiceAction(ctx, 3, 1, 2, serviceCompleted(running)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, third); err != nil {
		t.Fatalf("busy rejection consumed sequence: %v", err)
	}
	got, revision, err := f.store.NextUnfinishedServiceAction(ctx, "")
	if err != nil || revision != 1 || !proto.Equal(got, third) {
		t.Fatalf("unfinished cursor: revision=%d err=%v", revision, err)
	}
	if _, _, err := f.store.NextUnfinishedServiceAction(ctx, third.GetIntent().GetActionId()); !errors.Is(err, ErrServiceActionNotFound) {
		t.Fatalf("cursor end: %v", err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	assertServiceRecord(t, reopened, superseded, 3)
	assertServiceRecord(t, reopened, third, 1)
	if _, err := reopened.AcceptServiceAction(ctx, 1, 2, f.record(t, 2, "example.service", false)); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("restart lost sequence floor: %v", err)
	}
}

func TestServiceActionCASRevocationAndCompletion(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	record := f.record(t, 1, "example.service", true)
	for _, revisions := range [][2]int64{{0, 2}, {1, 1}} {
		if _, err := f.store.AcceptServiceAction(ctx, revisions[0], revisions[1], record); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale accept fence: %v", err)
		}
	}
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	for _, revisions := range [][3]int64{{2, 1, 2}, {1, 2, 2}, {1, 1, 1}} {
		if _, err := f.store.UpdateServiceAction(ctx, revisions[0], revisions[1], revisions[2], queued); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale update fence: %v", err)
		}
		assertServiceRecord(t, f.store, record, 1)
	}
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(queued)
	if _, err := f.store.UpdateServiceAction(ctx, 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	other := f.record(t, 1, "other.service", true)
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, other); err != nil {
		t.Fatal(err)
	}
	waiting := f.record(t, 1, "waiting.service", true)
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, waiting); err != nil {
		t.Fatal(err)
	}
	waiting = serviceQueued(waiting)
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, waiting); err != nil {
		t.Fatal(err)
	}
	revoked := proto.CloneOf(f.trust)
	revoked.DelegationVersion++
	revoked.MinimumRecoveryEpoch++
	revoked.DelegationEnvelope = []byte("replacement-delegation")
	if _, err := f.store.UpdateExecutionTrust(ctx, 2, revoked); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, serviceQueued(other)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale trust did not conflict: %v", err)
	}
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 3, serviceQueued(other)); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("revoked action queued: %v", err)
	}
	assertServiceRecord(t, f.store, other, 1)
	if _, err := f.store.UpdateServiceAction(ctx, 2, 1, 3, serviceRunning(waiting)); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("revoked queued action crossed effect boundary: %v", err)
	}
	assertServiceRecord(t, f.store, waiting, 2)
	completed := serviceCompleted(running)
	if _, err := f.store.UpdateServiceAction(ctx, 3, 1, 2, completed); !errors.Is(err, ErrConflict) {
		t.Fatalf("completion ignored CAS: %v", err)
	}
	if revision, err := f.store.UpdateServiceAction(ctx, 3, 1, 3, completed); err != nil || revision != 4 {
		t.Fatalf("revocation prevented historical completion: revision=%d err=%v", revision, err)
	}
	assertServiceRecord(t, f.store, completed, 4)
}

func TestServiceActionImmutableEvidenceAndTerminalRetries(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, record); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*agentv1.ServiceExecutionRecord){
		"intent":     func(r *agentv1.ServiceExecutionRecord) { r.Intent.ActorId = uuid.NewString() },
		"root":       func(r *agentv1.ServiceExecutionRecord) { r.AcceptedRoot.Threshold = 2 },
		"delegation": func(r *agentv1.ServiceExecutionRecord) { r.AcceptedDelegationEnvelope = []byte("changed") },
		"accepted time": func(r *agentv1.ServiceExecutionRecord) {
			r.AcceptedAt = timestamppb.New(r.GetAcceptedAt().AsTime().Add(time.Millisecond))
		},
		"challenge proof":       func(r *agentv1.ServiceExecutionRecord) { r.ChallengeProof = []byte("changed") },
		"challenge certificate": func(r *agentv1.ServiceExecutionRecord) { r.ChallengeCertificatePem[0]++ },
		"deadline":              func(r *agentv1.ServiceExecutionRecord) { r.ChallengeBoottimeNs++ },
		"unknown field":         func(r *agentv1.ServiceExecutionRecord) { r.Intent.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			next := serviceQueued(record)
			mutate(next)
			if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, next); !errors.Is(err, ErrServiceActionRejected) {
				t.Fatalf("immutable change accepted: %v", err)
			}
			assertServiceRecord(t, f.store, record, 1)
		})
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateServiceAction(ctx, 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"grant", "grant accepted"} {
		next := serviceRunning(queued)
		if field == "grant" {
			next.StartGrantEnvelope = []byte("changed-grant")
			digest := sha256.Sum256(next.GetStartGrantEnvelope())
			next.StartGrantSha256 = digest[:]
		} else {
			next.GrantAcceptedAt = timestamppb.New(queued.GetGrantAcceptedAt().AsTime().Add(time.Millisecond))
		}
		if _, err := f.store.UpdateServiceAction(ctx, 2, 1, 2, next); !errors.Is(err, ErrServiceActionRejected) {
			t.Fatalf("%s rewrite accepted: %v", field, err)
		}
	}
	running := serviceRunning(queued)
	if _, err := f.store.UpdateServiceAction(ctx, 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateServiceAction(ctx, 3, 1, 2, running); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("RUNNING replay accepted: %v", err)
	}
	changedStart := serviceCompleted(running)
	changedStart.StartedAt = timestamppb.New(running.GetStartedAt().AsTime().Add(time.Millisecond))
	if _, err := f.store.UpdateServiceAction(ctx, 3, 1, 2, changedStart); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("started_at rewritten: %v", err)
	}
	completed := serviceCompleted(running)
	if _, err := f.store.UpdateServiceAction(ctx, 3, 1, 2, completed); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		assertServiceRecord(t, f.store, completed, 4)
		if _, err := f.store.UpdateServiceAction(ctx, 4, 1, 2, completed); !errors.Is(err, ErrServiceActionRejected) {
			t.Fatalf("terminal rewrite accepted: %v", err)
		}
	}
	loaded, _, err := f.store.LoadServiceAction(ctx, completed.GetIntent().GetActionId())
	if err != nil {
		t.Fatal(err)
	}
	loaded.StartGrantEnvelope[0]++
	assertServiceRecord(t, f.store, completed, 4)
}

func TestServiceActionTerminalTransitionsRetainEvidence(t *testing.T) {
	for _, from := range []agentv1.ServiceExecutionState{
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING,
	} {
		for _, to := range []agentv1.ServiceExecutionState{
			agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED,
			agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED,
			agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED,
			agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN,
		} {
			t.Run(fmt.Sprintf("%s/%s", from, to), func(t *testing.T) {
				f := newServiceJournalFixture(t)
				current := f.record(t, 1, "example.service", true)
				revision, err := f.store.AcceptServiceAction(t.Context(), 1, 2, current)
				if err != nil {
					t.Fatal(err)
				}
				if from >= agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED {
					current = serviceQueued(current)
					revision, err = f.store.UpdateServiceAction(t.Context(), revision, 1, 2, current)
					if err != nil {
						t.Fatal(err)
					}
				}
				if from == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING {
					current = serviceRunning(current)
					revision, err = f.store.UpdateServiceAction(t.Context(), revision, 1, 2, current)
					if err != nil {
						t.Fatal(err)
					}
				}
				next := proto.CloneOf(current)
				next.State = to
				next.CompletedAt = timestamppb.New(current.GetAcceptedAt().AsTime().Add(3 * time.Second))
				next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED
				if to == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED {
					next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_SUPERSEDED
				}
				allowed := to == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED ||
					(from == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING && to == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN) ||
					(from != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING && to != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN)
				newRevision, err := f.store.UpdateServiceAction(t.Context(), revision, 1, 2, next)
				if !allowed {
					if !errors.Is(err, ErrServiceActionRejected) {
						t.Fatalf("illegal transition accepted: %v", err)
					}
					assertServiceRecord(t, f.store, current, revision)
					return
				}
				if err != nil || newRevision != revision+1 {
					t.Fatalf("terminal transition: revision=%d err=%v", newRevision, err)
				}
				assertServiceRecord(t, f.store, next, newRevision)
				if _, err := f.store.UpdateServiceAction(t.Context(), newRevision, 1, 2, next); !errors.Is(err, ErrServiceActionRejected) {
					t.Fatalf("terminal evidence rewritten: %v", err)
				}
			})
		}
	}
}

func TestServiceActionEnrollmentFenceBeforeEffect(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(f.authority)
	device, generation := uuid.NewString(), uuid.NewString()
	changed.DeviceId, changed.EnrollmentGeneration = &device, &generation
	if _, err := f.store.Update(t.Context(), 1, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateServiceAction(t.Context(), 2, 1, 2, serviceRunning(queued)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale enrollment revision accepted: %v", err)
	}
	if _, err := f.store.UpdateServiceAction(t.Context(), 2, 2, 2, serviceRunning(queued)); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("old enrollment crossed effect boundary: %v", err)
	}
	assertServiceRecord(t, f.store, queued, 2)
	failed := proto.CloneOf(queued)
	failed.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED
	failed.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_AUTHORITY
	failed.CompletedAt = timestamppb.New(queued.GetAcceptedAt().AsTime().Add(3 * time.Second))
	if _, err := f.store.UpdateServiceAction(t.Context(), 2, 2, 2, failed); err != nil {
		t.Fatalf("enrollment change prevented terminal evidence: %v", err)
	}
	assertServiceRecord(t, f.store, failed, 3)
}

func TestServiceActionNoDriftIdentityAndConcurrentSequence(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	noop := f.record(t, 1, "converged.service", false)
	if revision, err := f.store.AcceptServiceAction(ctx, 1, 2, noop); err != nil || revision != 1 {
		t.Fatalf("no-op acceptance: revision=%d err=%v", revision, err)
	}
	assertServiceRecord(t, f.store, noop, 1)
	wrongTarget := f.record(t, 1, "example.service", false)
	wrongTarget.Intent.DeviceId = uuid.NewString()
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, wrongTarget); !errors.Is(err, ErrServiceActionRejected) {
		t.Fatalf("wrong enrollment target accepted: %v", err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		record := f.record(t, 1, "example.service", true)
		group.Go(func() { _, err := f.store.AcceptServiceAction(ctx, 1, 2, record); results <- err })
	}
	group.Wait()
	close(results)
	var accepted, rejected int
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrServiceActionRejected) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent sequence winners=%d rejected=%d", accepted, rejected)
	}
}

func TestServiceActionCapacityRollbackAndCanceledContext(t *testing.T) {
	for _, dimension := range []string{"record_count", "record_bytes"} {
		t.Run(dimension, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			first := f.record(t, 1, "example.service", true)
			if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, first); err != nil {
				t.Fatal(err)
			}
			// Saturate only the accounting boundary, avoiding 65K unrelated
			// fixtures. Startup corruption tests independently check its totals.
			limit := maximumServiceActions
			if dimension == "record_bytes" {
				limit = maximumServiceActionTotalBytes
			}
			if _, err := f.store.db.Exec(fmt.Sprintf("UPDATE service_action_usage SET %s = ? WHERE id = 1", dimension), limit); err != nil {
				t.Fatal(err)
			}
			second := f.record(t, 2, "example.service", true)
			if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, second); !errors.Is(err, ErrServiceActionCapacity) {
				t.Fatalf("capacity did not reject: %v", err)
			}
			assertServiceRecord(t, f.store, first, 1)
			if _, _, err := f.store.LoadServiceAction(t.Context(), second.GetIntent().GetActionId()); !errors.Is(err, ErrServiceActionNotFound) {
				t.Fatalf("capacity inserted partial record: %v", err)
			}
		})
	}
	f := newServiceJournalFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptServiceAction(ctx, 1, 2, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled accept: %v", err)
	}
	if _, _, err := f.store.LoadServiceAction(ctx, record.GetIntent().GetActionId()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load: %v", err)
	}
	if _, _, err := f.store.NextUnfinishedServiceAction(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan: %v", err)
	}
}

func TestServiceActionCompletionPreservesWallClockRollback(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(queued)
	if _, err := f.store.UpdateServiceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	completed := serviceCompleted(running)
	completed.CompletedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(-time.Hour))
	completed.Verification.Observation.ObservedAt = proto.CloneOf(completed.GetCompletedAt())
	if _, err := f.store.UpdateServiceAction(t.Context(), 3, 1, 2, completed); err != nil {
		t.Fatalf("wall-clock rollback prevented actual outcome: %v", err)
	}
	assertServiceRecord(t, f.store, completed, 4)
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatalf("wall-clock rollback invalidated historical outcome: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	assertServiceRecord(t, reopened, completed, 4)
}

func TestServiceActionReservationsAllowCompletionAtCapacity(t *testing.T) {
	f := newServiceJournalFixture(t)
	const count = maximumServiceActionTotalBytes / maximumServiceActionBytes
	var retained [3]*agentv1.ServiceExecutionRecord
	for i := range count {
		record := f.record(t, 1, fmt.Sprintf("capacity-%04d.service", i), true)
		if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, record); err != nil {
			t.Fatalf("accept reserved action %d: %v", i, err)
		}
		if i < len(retained) {
			retained[i] = record
		}
	}
	assertServiceActionCapacity(t, f.store, count, maximumServiceActionTotalBytes)
	reopen := func() {
		t.Helper()
		if err := f.store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err := Open(t.Context(), f.directory)
		if err != nil {
			t.Fatalf("reopen reserved capacity: %v", err)
		}
		f.store = store
		t.Cleanup(func() { _ = store.Close() })
	}
	reopen()
	assertServiceActionCapacity(t, f.store, count, maximumServiceActionTotalBytes)
	overflow := f.record(t, 1, "overflow.service", true)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, overflow); !errors.Is(err, ErrServiceActionCapacity) {
		t.Fatalf("new work exceeded reserved capacity: %v", err)
	}
	replacement := f.record(t, 2, retained[2].GetIntent().GetDesired().GetUnit(), true)
	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, replacement); !errors.Is(err, ErrServiceActionCapacity) {
		t.Fatalf("supersession omitted retained terminal evidence: %v", err)
	}
	assertServiceRecord(t, f.store, retained[2], 1)
	assertServiceActionCapacity(t, f.store, count, maximumServiceActionTotalBytes)

	queued := serviceQueued(retained[0])
	if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatalf("reserved action could not queue at capacity: %v", err)
	}
	assertServiceActionCapacity(t, f.store, count, maximumServiceActionTotalBytes)
	running := serviceRunning(queued)
	if _, err := f.store.UpdateServiceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatalf("reserved action could not start at capacity: %v", err)
	}
	assertServiceActionCapacity(t, f.store, count, maximumServiceActionTotalBytes)
	reopen()
	assertServiceRecord(t, f.store, running, 3)
	assertServiceActionCapacity(t, f.store, count, maximumServiceActionTotalBytes)
	completed := serviceCompleted(running)
	if _, err := f.store.UpdateServiceAction(t.Context(), 3, 1, 2, completed); err != nil {
		t.Fatalf("reserved native outcome could not complete at capacity: %v", err)
	}
	charged := int64(maximumServiceActionTotalBytes - maximumServiceActionBytes + proto.Size(completed))
	assertServiceActionCapacity(t, f.store, count, charged)

	expired := proto.CloneOf(retained[1])
	expired.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
	expired.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED
	expired.CompletedAt = timestamppb.New(expired.GetAcceptedAt().AsTime().Add(time.Second))
	if _, err := f.store.UpdateServiceAction(t.Context(), 1, 1, 2, expired); err != nil {
		t.Fatalf("prepared restart expiry could not release reservation: %v", err)
	}
	charged += int64(proto.Size(expired) - maximumServiceActionBytes)
	assertServiceActionCapacity(t, f.store, count, charged)

	if _, err := f.store.AcceptServiceAction(t.Context(), 1, 2, replacement); err != nil {
		t.Fatalf("supersession could not reuse released capacity: %v", err)
	}
	superseded := proto.CloneOf(retained[2])
	superseded.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED
	superseded.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_SUPERSEDED
	superseded.CompletedAt = proto.CloneOf(replacement.GetAcceptedAt())
	// Replacing an unfinished action trades its reservation for the new one,
	// plus the exact size of the retained SUPERSEDED evidence.
	charged += int64(proto.Size(superseded))
	assertServiceActionCapacity(t, f.store, count+1, charged)
	assertServiceRecord(t, f.store, superseded, 2)
	assertServiceRecord(t, f.store, replacement, 1)
	reopen()
	assertServiceActionCapacity(t, f.store, count+1, charged)
	assertServiceRecord(t, f.store, completed, 4)
	assertServiceRecord(t, f.store, expired, 2)
	assertServiceRecord(t, f.store, superseded, 2)
	assertServiceRecord(t, f.store, replacement, 1)
}

func assertServiceActionCapacity(t *testing.T, store *Store, count, chargedBytes int64) {
	t.Helper()
	usage, err := store.queries.ReadServiceActionUsage(t.Context())
	if err != nil || usage.RecordCount != count || usage.RecordBytes != chargedBytes {
		t.Fatalf("stored capacity count=%d bytes=%d want count=%d bytes=%d err=%v", usage.RecordCount, usage.RecordBytes, count, chargedBytes, err)
	}
	totals, err := store.queries.ServiceActionTotals(t.Context())
	if err != nil || totals.RecordCount != count || totals.RecordBytes != chargedBytes {
		t.Fatalf("aggregate capacity count=%d bytes=%d want count=%d bytes=%d err=%v", totals.RecordCount, totals.RecordBytes, count, chargedBytes, err)
	}
}
