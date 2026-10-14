// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// These fixtures test structural persistence, not signatures. Runtime tests use
// real DSSE keys; the journal never interprets opaque fixture bytes as authority.
func journalActionRecord(t *testing.T, f serviceJournalFixture, sequence uint64) *agentv1.DeviceActionRecord {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
	i := &agentv1.DeviceActionIntent{DeploymentId: f.trust.GetRoot().GetDeploymentId(), DeviceId: f.authority.GetDeviceId(), EnrollmentGeneration: f.authority.GetEnrollmentGeneration(), ActionId: uuid.NewString(), ActorId: uuid.NewString(), ActionSequence: sequence, RecoveryEpoch: 1, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Minute)), Spec: spec, SpecSha256: journalActionDigest(t, spec)}
	plan := &agentv1.DeviceActionPlan{Spec: proto.CloneOf(spec), ActionId: i.GetActionId(), Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(now), Supported: true}}
	envelope := []byte("opaque signed intent " + i.GetActionId())
	digest := sha256.Sum256(envelope)
	challenge := &agentv1.DeviceActionChallenge{DeploymentId: i.GetDeploymentId(), DeviceId: i.GetDeviceId(), EnrollmentGeneration: i.GetEnrollmentGeneration(), ActionId: i.GetActionId(), ActionSequence: sequence, RecoveryEpoch: 1, IntentSha256: digest[:], SpecSha256: i.GetSpecSha256(), NativePlanSha256: journalActionDigest(t, plan), Nonce: bytes.Repeat([]byte{7}, 32), BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), NativePlan: proto.CloneOf(plan)}
	return &agentv1.DeviceActionRecord{FormatVersion: 1, InstallationId: f.authority.GetInstallationId(), IntentEnvelope: envelope, IntentSha256: digest[:], Intent: i, NativePlan: plan, AcceptedRoot: proto.CloneOf(f.trust.GetRoot()), AcceptedDelegationEnvelope: bytes.Clone(f.trust.GetDelegationEnvelope()), AcceptedAt: timestamppb.New(now), State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED, Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE, Challenge: challenge, ChallengeProof: []byte("opaque device proof"), ChallengeBoottimeNs: uint64(time.Hour + 30*time.Second), ChallengeCertificatePem: bytes.Repeat([]byte{'C'}, 96)}
}

func journalActionDigest(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return digest[:]
}
func journalActionRunning(record *agentv1.DeviceActionRecord) *agentv1.DeviceActionRecord {
	next := proto.CloneOf(record)
	next.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING
	next.StartGrantEnvelope = []byte("opaque signed start " + record.GetIntent().GetActionId())
	digest := sha256.Sum256(next.GetStartGrantEnvelope())
	next.StartGrantSha256 = digest[:]
	next.StartedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(time.Second))
	next.GrantAcceptedAt = proto.CloneOf(next.StartedAt)
	return next
}

func TestDeviceActionJournalConsumesOnlyOnceAndRetainsAcrossOpen(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := journalActionRecord(t, f, 1)
	if revision, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, record); err != nil || revision != 1 {
		t.Fatalf("accept: revision=%d err=%v", revision, err)
	}
	for _, duplicate := range []*agentv1.DeviceActionRecord{proto.CloneOf(record), journalActionRecord(t, f, 1)} {
		if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, duplicate); !errors.Is(err, ErrDeviceActionRejected) {
			t.Fatalf("duplicate ID/sequence accepted: %v", err)
		}
	}
	running := journalActionRunning(record)
	results := make(chan error, 2)
	var calls sync.WaitGroup
	for range 2 {
		calls.Go(func() { _, err := f.store.UpdateDeviceAction(t.Context(), 1, 1, 2, running); results <- err })
	}
	calls.Wait()
	close(results)
	accepted, rejected := 0, 0
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
		t.Fatalf("consume winners=%d conflicts=%d", accepted, rejected)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	got, revision, err := reopened.LoadDeviceAction(t.Context(), record.GetIntent().GetActionId())
	if err != nil || revision != 2 || !proto.Equal(got, running) {
		t.Fatalf("durable consumed evidence changed: revision=%d err=%v", revision, err)
	}
	unknown := proto.CloneOf(running)
	unknown.State, unknown.Failure = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED
	unknown.CompletedAt = timestamppb.New(record.GetAcceptedAt().AsTime().Add(2 * time.Second))
	if _, err := reopened.UpdateDeviceAction(t.Context(), 2, 1, 2, unknown); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.UpdateDeviceAction(t.Context(), 3, 1, 2, running); !errors.Is(err, ErrDeviceActionRejected) {
		t.Fatalf("unknown action replayed: %v", err)
	}
}

func TestDeviceActionJournalRejectsQueueAndChangedEvidence(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := journalActionRecord(t, f, 1)
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	running := journalActionRunning(record)
	if _, err := f.store.UpdateDeviceAction(t.Context(), 1, 1, 3, running); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed trust fence accepted: %v", err)
	}
	changed := proto.CloneOf(running)
	changed.NativePlan.Before.Reason = "changed after challenge"
	if _, err := f.store.UpdateDeviceAction(t.Context(), 1, 1, 2, changed); !errors.Is(err, ErrDeviceActionRejected) {
		t.Fatalf("changed native plan accepted: %v", err)
	}
	queued := proto.CloneOf(running)
	queued.State, queued.StartedAt = agentv1.DeviceActionState_DEVICE_ACTION_STATE_QUEUED, nil
	if _, err := f.store.UpdateDeviceAction(t.Context(), 1, 1, 2, queued); !errors.Is(err, ErrDeviceActionRejected) {
		t.Fatalf("offline queue admitted: %v", err)
	}
	got, revision, err := f.store.LoadDeviceAction(t.Context(), record.GetIntent().GetActionId())
	if err != nil || revision != 1 || !proto.Equal(got, record) {
		t.Fatalf("rejection changed evidence: revision=%d err=%v", revision, err)
	}
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, journalActionRecord(t, f, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, journalActionRecord(t, f, 2)); !errors.Is(err, ErrDeviceActionRejected) {
		t.Fatalf("lower sequence admitted: %v", err)
	}
}

func TestDeviceActionJournalTamperFailsClosed(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := journalActionRecord(t, f, 1)
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.ExecContext(t.Context(), "UPDATE device_actions SET state = 6 WHERE action_id = ?", record.GetIntent().GetActionId()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.LoadDeviceAction(t.Context(), record.GetIntent().GetActionId()); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("tampered column accepted: %v", err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("tampered installation reopened: %v", err)
	}
}

func TestDeviceActionJournalDeletionCannotRestoreStartAuthority(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := journalActionRecord(t, f, 1)
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.ExecContext(t.Context(), "DELETE FROM device_actions WHERE action_id = ?", record.GetIntent().GetActionId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptDeviceAction(t.Context(), 1, 2, record); !errors.Is(err, ErrRecoveryHold) {
		t.Fatalf("deleted record restored start authority: %v", err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("deleted action escaped accounting on reopen: %v", err)
	}
}
