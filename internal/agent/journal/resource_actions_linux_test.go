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
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
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

func (f serviceJournalFixture) record(t *testing.T, sequence uint64, unit string, drift bool) *agentv1.ResourceExecutionRecord {
	t.Helper()
	now := time.Unix(1_800_000_000+int64(sequence)*5, 0).UTC()
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: unit}
	service := &resourcev1.SystemdServiceDesired{Unit: unit, Runtime: resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}
	desired := &resourcev1.ResourceDesiredState{Ref: ref, State: &resourcev1.ResourceDesiredState_SystemdService{SystemdService: service}}
	intent := &agentv1.ResourceExecutionIntent{
		DeploymentId: f.trust.GetRoot().GetDeploymentId(), DeviceId: f.authority.GetDeviceId(), EnrollmentGeneration: f.authority.GetEnrollmentGeneration(),
		ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(), ResourceSequence: sequence, RecoveryEpoch: 1,
		RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Minute)),
		Desired: desired, Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE,
		Ownership: &agentv1.ResourceOwnershipBinding{AssignmentId: uuid.NewString(), ResourceId: uuid.NewString(),
			Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: uuid.NewString(), ProfileRevision: uuid.NewString(), ResourceId: uuid.NewString()}},
			Policy:  &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED, AdoptionApprovalId: proto.String(uuid.NewString())}},
	}
	native := &resourcev1.SystemdServiceObservation{
		Unit: unit, BootId: uuid.NewString(), ObservedAt: timestamppb.New(now), LoadState: "loaded", ActiveState: "inactive", SubState: "dead", UnitFileState: "disabled", ServiceType: "simple",
		DefinitionSha256: bytes.Repeat([]byte{1}, 32), FingerprintSha256: bytes.Repeat([]byte{2}, 32),
	}
	if !drift {
		native.ActiveState, native.SubState = "active", "running"
	}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: "257", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "debian", Product: "debian", Version: "13", Architecture: "amd64"}}
	observation := &resourcev1.ResourceObservation{Ref: proto.CloneOf(ref), Metadata: &resourcev1.ObservationMetadata{BootId: native.GetBootId(), ExecutorIncarnation: uuid.NewString(), ObservedAt: timestamppb.New(now), Backend: backend, NativeRevision: bytes.Repeat([]byte{2}, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_SystemdService{SystemdService: native}}
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		t.Fatal(err)
	}
	observationDigest, err := resource.ObservationDigest(observation)
	if err != nil {
		t.Fatal(err)
	}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(ref), Operation: intent.GetOperation(), DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:], Backend: backend, Before: observation, OwnershipRevisionSha256: make([]byte, 32),
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED},
		Plan:   &resourcev1.ResourcePlan_SystemdService{SystemdService: &resourcev1.SystemdServicePlan{Desired: proto.CloneOf(service), Before: native, ChangeRuntime: drift}}}
	envelope := []byte("opaque-intent-" + intent.GetActionId())
	digest := sha256.Sum256(envelope)
	record := &agentv1.ResourceExecutionRecord{
		FormatVersion: 1, InstallationId: f.authority.GetInstallationId(), IntentEnvelope: envelope, IntentSha256: digest[:], Intent: intent, NativePlan: plan,
		AcceptedRoot: proto.CloneOf(f.trust.GetRoot()), AcceptedDelegationEnvelope: bytes.Clone(f.trust.GetDelegationEnvelope()), AcceptedAt: timestamppb.New(now),
		State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE,
	}
	if !drift {
		record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
		record.CompletedAt = timestamppb.New(now)
		record.Verification = serviceConverged(record)
		return record
	}
	planDigest, err := resource.PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	record.Challenge = &agentv1.ResourceExecutionChallenge{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(),
		DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: sequence, RecoveryEpoch: 1, IntentSha256: bytes.Clone(digest[:]), NativePlanSha256: planDigest[:],
		Nonce: bytes.Repeat([]byte{3}, 32), BootId: native.GetBootId(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)),
		Ref: proto.CloneOf(ref), Operation: intent.GetOperation(),
	}
	record.ChallengeProof = []byte("opaque-device-proof")
	record.ChallengeCertificatePem = bytes.Repeat([]byte("C"), 96)
	record.ChallengeBoottimeNs = 30_000_000_000
	return record
}

func serviceQueued(record *agentv1.ResourceExecutionRecord) *agentv1.ResourceExecutionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED
	next.StartGrantEnvelope = []byte("opaque-start-" + record.GetIntent().GetActionId())
	digest := sha256.Sum256(next.GetStartGrantEnvelope())
	next.StartGrantSha256 = digest[:]
	next.GrantAcceptedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(time.Second))
	return next
}

func serviceRunning(record *agentv1.ResourceExecutionRecord) *agentv1.ResourceExecutionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING
	next.StartedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(2 * time.Second))
	return next
}

func serviceConverged(record *agentv1.ResourceExecutionRecord) *resourcev1.ResourceVerification {
	observation := proto.CloneOf(record.GetNativePlan().GetBefore())
	native := observation.GetSystemdService()
	native.ActiveState, native.SubState = "active", "running"
	planDigest, _ := resource.PlanDigest(record.GetNativePlan())
	return &resourcev1.ResourceVerification{Ref: proto.CloneOf(observation.GetRef()), DesiredSha256: bytes.Clone(record.GetNativePlan().GetDesiredSha256()), PlanSha256: planDigest[:], After: observation, Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
		Checks: &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{Observation: native, RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, JobCompleted: true, Converged: true}}}
}

func serviceCompleted(record *agentv1.ResourceExecutionRecord) *agentv1.ResourceExecutionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
	next.CompletedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(3 * time.Second))
	next.Verification = serviceConverged(record)
	return next
}

func assertServiceRecord(t *testing.T, store *Store, expected *agentv1.ResourceExecutionRecord, revision int64) {
	t.Helper()
	got, gotRevision, err := store.LoadResourceAction(t.Context(), expected.GetIntent().GetActionId())
	if err != nil || gotRevision != revision || !proto.Equal(got, expected) {
		t.Fatalf("service record changed: revision=%d want=%d err=%v", gotRevision, revision, err)
	}
}

func TestResourceActionSequenceSupersessionAndRunningBusy(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	first := f.record(t, 1, "example.service", true)
	if revision, err := f.store.AcceptResourceAction(ctx, 1, 2, first); err != nil || revision != 1 {
		t.Fatalf("accept first: revision=%d err=%v", revision, err)
	}
	for _, replay := range []*agentv1.ResourceExecutionRecord{proto.CloneOf(first), f.record(t, 1, "example.service", true)} {
		if _, err := f.store.AcceptResourceAction(ctx, 1, 2, replay); !errors.Is(err, ErrResourceActionRejected) {
			t.Fatalf("sequence/action replay accepted: %v", err)
		}
	}
	queued := serviceQueued(first)
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	second := f.record(t, 2, "example.service", true)
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, second); err != nil {
		t.Fatal(err)
	}
	superseded := proto.CloneOf(queued)
	superseded.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED
	superseded.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED
	superseded.CompletedAt = proto.CloneOf(second.GetAcceptedAt())
	assertServiceRecord(t, f.store, superseded, 3)
	if _, err := f.store.UpdateResourceAction(ctx, 3, 1, 2, serviceRunning(queued)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("superseded work started: %v", err)
	}
	queuedSecond := serviceQueued(second)
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, queuedSecond); err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(queuedSecond)
	if _, err := f.store.UpdateResourceAction(ctx, 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	third := f.record(t, 3, "example.service", true)
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, third); !errors.Is(err, ErrResourceActionBusy) {
		t.Fatalf("running resource superseded: %v", err)
	}
	assertServiceRecord(t, f.store, running, 3)
	if _, err := f.store.UpdateResourceAction(ctx, 3, 1, 2, serviceCompleted(running)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, third); err != nil {
		t.Fatalf("busy rejection consumed sequence: %v", err)
	}
	got, revision, err := f.store.NextUnfinishedResourceAction(ctx, "")
	if err != nil || revision != 1 || !proto.Equal(got, third) {
		t.Fatalf("unfinished cursor: revision=%d err=%v", revision, err)
	}
	if _, _, err := f.store.NextUnfinishedResourceAction(ctx, third.GetIntent().GetActionId()); !errors.Is(err, ErrResourceActionNotFound) {
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
	if _, err := reopened.AcceptResourceAction(ctx, 1, 2, f.record(t, 2, "example.service", false)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("restart lost sequence floor: %v", err)
	}
}

func TestResourceActionCASRevocationAndCompletion(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	record := f.record(t, 1, "example.service", true)
	for _, revisions := range [][2]int64{{0, 2}, {1, 1}} {
		if _, err := f.store.AcceptResourceAction(ctx, revisions[0], revisions[1], record); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale accept fence: %v", err)
		}
	}
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	for _, revisions := range [][3]int64{{2, 1, 2}, {1, 2, 2}, {1, 1, 1}} {
		if _, err := f.store.UpdateResourceAction(ctx, revisions[0], revisions[1], revisions[2], queued); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale update fence: %v", err)
		}
		assertServiceRecord(t, f.store, record, 1)
	}
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(queued)
	if _, err := f.store.UpdateResourceAction(ctx, 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	other := f.record(t, 1, "other.service", true)
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, other); err != nil {
		t.Fatal(err)
	}
	waiting := f.record(t, 1, "waiting.service", true)
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, waiting); err != nil {
		t.Fatal(err)
	}
	waiting = serviceQueued(waiting)
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, waiting); err != nil {
		t.Fatal(err)
	}
	revoked := proto.CloneOf(f.trust)
	revoked.DelegationVersion++
	revoked.MinimumRecoveryEpoch++
	revoked.DelegationEnvelope = []byte("replacement-delegation")
	if _, err := f.store.UpdateExecutionTrust(ctx, 2, revoked); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, serviceQueued(other)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale trust did not conflict: %v", err)
	}
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 3, serviceQueued(other)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("revoked action queued: %v", err)
	}
	assertServiceRecord(t, f.store, other, 1)
	if _, err := f.store.UpdateResourceAction(ctx, 2, 1, 3, serviceRunning(waiting)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("revoked queued action crossed effect boundary: %v", err)
	}
	assertServiceRecord(t, f.store, waiting, 2)
	completed := serviceCompleted(running)
	if _, err := f.store.UpdateResourceAction(ctx, 3, 1, 2, completed); !errors.Is(err, ErrConflict) {
		t.Fatalf("completion ignored CAS: %v", err)
	}
	if revision, err := f.store.UpdateResourceAction(ctx, 3, 1, 3, completed); err != nil || revision != 4 {
		t.Fatalf("revocation prevented historical completion: revision=%d err=%v", revision, err)
	}
	assertServiceRecord(t, f.store, completed, 4)
}

func TestResourceActionImmutableEvidenceAndTerminalRetries(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, record); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*agentv1.ResourceExecutionRecord){
		"intent":     func(r *agentv1.ResourceExecutionRecord) { r.Intent.ActorId = uuid.NewString() },
		"root":       func(r *agentv1.ResourceExecutionRecord) { r.AcceptedRoot.Threshold = 2 },
		"delegation": func(r *agentv1.ResourceExecutionRecord) { r.AcceptedDelegationEnvelope = []byte("changed") },
		"accepted time": func(r *agentv1.ResourceExecutionRecord) {
			r.AcceptedAt = timestamppb.New(r.GetAcceptedAt().AsTime().Add(time.Millisecond))
		},
		"challenge proof":       func(r *agentv1.ResourceExecutionRecord) { r.ChallengeProof = []byte("changed") },
		"challenge certificate": func(r *agentv1.ResourceExecutionRecord) { r.ChallengeCertificatePem[0]++ },
		"deadline":              func(r *agentv1.ResourceExecutionRecord) { r.ChallengeBoottimeNs++ },
		"unknown field":         func(r *agentv1.ResourceExecutionRecord) { r.Intent.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			next := serviceQueued(record)
			mutate(next)
			if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, next); !errors.Is(err, ErrResourceActionRejected) {
				t.Fatalf("immutable change accepted: %v", err)
			}
			assertServiceRecord(t, f.store, record, 1)
		})
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateResourceAction(ctx, 1, 1, 2, queued); err != nil {
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
		if _, err := f.store.UpdateResourceAction(ctx, 2, 1, 2, next); !errors.Is(err, ErrResourceActionRejected) {
			t.Fatalf("%s rewrite accepted: %v", field, err)
		}
	}
	running := serviceRunning(queued)
	if _, err := f.store.UpdateResourceAction(ctx, 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateResourceAction(ctx, 3, 1, 2, running); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("RUNNING replay accepted: %v", err)
	}
	changedStart := serviceCompleted(running)
	changedStart.StartedAt = timestamppb.New(running.GetStartedAt().AsTime().Add(time.Millisecond))
	if _, err := f.store.UpdateResourceAction(ctx, 3, 1, 2, changedStart); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("started_at rewritten: %v", err)
	}
	completed := serviceCompleted(running)
	if _, err := f.store.UpdateResourceAction(ctx, 3, 1, 2, completed); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		assertServiceRecord(t, f.store, completed, 4)
		if _, err := f.store.UpdateResourceAction(ctx, 4, 1, 2, completed); !errors.Is(err, ErrResourceActionRejected) {
			t.Fatalf("terminal rewrite accepted: %v", err)
		}
	}
	loaded, _, err := f.store.LoadResourceAction(ctx, completed.GetIntent().GetActionId())
	if err != nil {
		t.Fatal(err)
	}
	loaded.StartGrantEnvelope[0]++
	assertServiceRecord(t, f.store, completed, 4)
}

func TestResourceActionTerminalTransitionsRetainEvidence(t *testing.T) {
	for _, from := range []agentv1.ResourceExecutionState{
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING,
	} {
		for _, to := range []agentv1.ResourceExecutionState{
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED,
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED,
			agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN,
		} {
			t.Run(fmt.Sprintf("%s/%s", from, to), func(t *testing.T) {
				f := newServiceJournalFixture(t)
				current := f.record(t, 1, "example.service", true)
				revision, err := f.store.AcceptResourceAction(t.Context(), 1, 2, current)
				if err != nil {
					t.Fatal(err)
				}
				if from >= agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
					current = serviceQueued(current)
					revision, err = f.store.UpdateResourceAction(t.Context(), revision, 1, 2, current)
					if err != nil {
						t.Fatal(err)
					}
				}
				if from == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
					current = serviceRunning(current)
					revision, err = f.store.UpdateResourceAction(t.Context(), revision, 1, 2, current)
					if err != nil {
						t.Fatal(err)
					}
				}
				next := proto.CloneOf(current)
				next.State = to
				next.CompletedAt = timestamppb.New(current.GetAcceptedAt().AsTime().Add(3 * time.Second))
				next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED
				if to == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED {
					next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED
				}
				allowed := to == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED ||
					(from == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING && to == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN) ||
					(from != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING && to != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN)
				newRevision, err := f.store.UpdateResourceAction(t.Context(), revision, 1, 2, next)
				if !allowed {
					if !errors.Is(err, ErrResourceActionRejected) {
						t.Fatalf("illegal transition accepted: %v", err)
					}
					assertServiceRecord(t, f.store, current, revision)
					return
				}
				if err != nil || newRevision != revision+1 {
					t.Fatalf("terminal transition: revision=%d err=%v", newRevision, err)
				}
				assertServiceRecord(t, f.store, next, newRevision)
				if _, err := f.store.UpdateResourceAction(t.Context(), newRevision, 1, 2, next); !errors.Is(err, ErrResourceActionRejected) {
					t.Fatalf("terminal evidence rewritten: %v", err)
				}
			})
		}
	}
}

func TestResourceActionEnrollmentFenceBeforeEffect(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(f.authority)
	device, generation := uuid.NewString(), uuid.NewString()
	changed.DeviceId, changed.EnrollmentGeneration = &device, &generation
	if _, err := f.store.Update(t.Context(), 1, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, serviceRunning(queued)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale enrollment revision accepted: %v", err)
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 2, 2, serviceRunning(queued)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("old enrollment crossed effect boundary: %v", err)
	}
	assertServiceRecord(t, f.store, queued, 2)
	failed := proto.CloneOf(queued)
	failed.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
	failed.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_AUTHORITY
	failed.CompletedAt = timestamppb.New(queued.GetAcceptedAt().AsTime().Add(3 * time.Second))
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 2, 2, failed); err != nil {
		t.Fatalf("enrollment change prevented terminal evidence: %v", err)
	}
	assertServiceRecord(t, f.store, failed, 3)
}

func TestResourceActionNoDriftIdentityAndConcurrentSequence(t *testing.T) {
	f := newServiceJournalFixture(t)
	ctx := t.Context()
	noop := f.record(t, 1, "converged.service", false)
	if revision, err := f.store.AcceptResourceAction(ctx, 1, 2, noop); err != nil || revision != 1 {
		t.Fatalf("no-op acceptance: revision=%d err=%v", revision, err)
	}
	assertServiceRecord(t, f.store, noop, 1)
	wrongTarget := f.record(t, 1, "example.service", false)
	wrongTarget.Intent.DeviceId = uuid.NewString()
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, wrongTarget); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("wrong enrollment target accepted: %v", err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		record := f.record(t, 1, "example.service", true)
		group.Go(func() { _, err := f.store.AcceptResourceAction(ctx, 1, 2, record); results <- err })
	}
	group.Wait()
	close(results)
	var accepted, rejected int
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrResourceActionRejected) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent sequence winners=%d rejected=%d", accepted, rejected)
	}
}

func TestResourceActionCapacityRollbackAndCanceledContext(t *testing.T) {
	for _, dimension := range []string{"record_count", "record_bytes"} {
		t.Run(dimension, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			first := f.record(t, 1, "example.service", true)
			if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, first); err != nil {
				t.Fatal(err)
			}
			// Saturate only the accounting boundary, avoiding 65K unrelated
			// fixtures. Startup corruption tests independently check its totals.
			limit := maximumResourceActions
			if dimension == "record_bytes" {
				limit = maximumResourceActionTotalBytes
			}
			if _, err := f.store.db.Exec(fmt.Sprintf("UPDATE resource_action_usage SET %s = ? WHERE id = 1", dimension), limit); err != nil {
				t.Fatal(err)
			}
			second := f.record(t, 2, "example.service", true)
			if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, second); !errors.Is(err, ErrResourceActionCapacity) {
				t.Fatalf("capacity did not reject: %v", err)
			}
			assertServiceRecord(t, f.store, first, 1)
			if _, _, err := f.store.LoadResourceAction(t.Context(), second.GetIntent().GetActionId()); !errors.Is(err, ErrResourceActionNotFound) {
				t.Fatalf("capacity inserted partial record: %v", err)
			}
		})
	}
	f := newServiceJournalFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptResourceAction(ctx, 1, 2, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled accept: %v", err)
	}
	if _, _, err := f.store.LoadResourceAction(ctx, record.GetIntent().GetActionId()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load: %v", err)
	}
	if _, _, err := f.store.NextUnfinishedResourceAction(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan: %v", err)
	}
}

func TestResourceActionCompletionPreservesWallClockRollback(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := f.record(t, 1, "example.service", true)
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	queued := serviceQueued(record)
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatal(err)
	}
	running := serviceRunning(queued)
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatal(err)
	}
	completed := serviceCompleted(running)
	completed.CompletedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(-time.Hour))
	completed.Verification.After.GetSystemdService().ObservedAt = proto.CloneOf(completed.GetCompletedAt())
	completed.Verification.After.Metadata.ObservedAt = proto.CloneOf(completed.GetCompletedAt())
	if _, err := f.store.UpdateResourceAction(t.Context(), 3, 1, 2, completed); err != nil {
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

func TestResourceActionReservationsAllowCompletionAtCapacity(t *testing.T) {
	f := newServiceJournalFixture(t)
	const count = maximumResourceActionTotalBytes / maximumResourceActionBytes
	var retained [3]*agentv1.ResourceExecutionRecord
	for i := range count {
		record := f.record(t, 1, fmt.Sprintf("capacity-%04d.service", i), true)
		if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
			t.Fatalf("accept reserved action %d: %v", i, err)
		}
		if i < len(retained) {
			retained[i] = record
		}
	}
	assertResourceActionCapacity(t, f.store, count, maximumResourceActionTotalBytes)
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
	assertResourceActionCapacity(t, f.store, count, maximumResourceActionTotalBytes)
	overflow := f.record(t, 1, "overflow.service", true)
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, overflow); !errors.Is(err, ErrResourceActionCapacity) {
		t.Fatalf("new work exceeded reserved capacity: %v", err)
	}
	replacement := f.record(t, 2, retained[2].GetIntent().GetDesired().GetRef().GetCanonicalKey(), true)
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, replacement); !errors.Is(err, ErrResourceActionCapacity) {
		t.Fatalf("supersession omitted retained terminal evidence: %v", err)
	}
	assertServiceRecord(t, f.store, retained[2], 1)
	assertResourceActionCapacity(t, f.store, count, maximumResourceActionTotalBytes)

	queued := serviceQueued(retained[0])
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, queued); err != nil {
		t.Fatalf("reserved action could not queue at capacity: %v", err)
	}
	assertResourceActionCapacity(t, f.store, count, maximumResourceActionTotalBytes)
	running := serviceRunning(queued)
	if _, err := f.store.UpdateResourceAction(t.Context(), 2, 1, 2, running); err != nil {
		t.Fatalf("reserved action could not start at capacity: %v", err)
	}
	assertResourceActionCapacity(t, f.store, count, maximumResourceActionTotalBytes)
	reopen()
	assertServiceRecord(t, f.store, running, 3)
	assertResourceActionCapacity(t, f.store, count, maximumResourceActionTotalBytes)
	completed := serviceCompleted(running)
	if _, err := f.store.UpdateResourceAction(t.Context(), 3, 1, 2, completed); err != nil {
		t.Fatalf("reserved native outcome could not complete at capacity: %v", err)
	}
	charged := int64(maximumResourceActionTotalBytes - maximumResourceActionBytes + proto.Size(completed))
	assertResourceActionCapacity(t, f.store, count, charged)

	expired := proto.CloneOf(retained[1])
	expired.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
	expired.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED
	expired.CompletedAt = timestamppb.New(expired.GetAcceptedAt().AsTime().Add(time.Second))
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, expired); err != nil {
		t.Fatalf("prepared restart expiry could not release reservation: %v", err)
	}
	charged += int64(proto.Size(expired) - maximumResourceActionBytes)
	assertResourceActionCapacity(t, f.store, count, charged)

	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, replacement); err != nil {
		t.Fatalf("supersession could not reuse released capacity: %v", err)
	}
	superseded := proto.CloneOf(retained[2])
	superseded.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED
	superseded.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED
	superseded.CompletedAt = proto.CloneOf(replacement.GetAcceptedAt())
	// Replacing an unfinished action trades its reservation for the new one,
	// plus the exact size of the retained SUPERSEDED evidence.
	charged += int64(proto.Size(superseded))
	assertResourceActionCapacity(t, f.store, count+1, charged)
	assertServiceRecord(t, f.store, superseded, 2)
	assertServiceRecord(t, f.store, replacement, 1)
	reopen()
	assertResourceActionCapacity(t, f.store, count+1, charged)
	assertServiceRecord(t, f.store, completed, 4)
	assertServiceRecord(t, f.store, expired, 2)
	assertServiceRecord(t, f.store, superseded, 2)
	assertServiceRecord(t, f.store, replacement, 1)
}

func assertResourceActionCapacity(t *testing.T, store *Store, count, chargedBytes int64) {
	t.Helper()
	usage, err := store.queries.ReadResourceActionUsage(t.Context())
	if err != nil || usage.RecordCount != count || usage.RecordBytes != chargedBytes {
		t.Fatalf("stored capacity count=%d bytes=%d want count=%d bytes=%d err=%v", usage.RecordCount, usage.RecordBytes, count, chargedBytes, err)
	}
	totals, err := store.queries.ResourceActionTotals(t.Context())
	if err != nil || totals.RecordCount != count || totals.RecordBytes != chargedBytes {
		t.Fatalf("aggregate capacity count=%d bytes=%d want count=%d bytes=%d err=%v", totals.RecordCount, totals.RecordBytes, count, chargedBytes, err)
	}
}
