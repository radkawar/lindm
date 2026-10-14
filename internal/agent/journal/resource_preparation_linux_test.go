// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func pendingPackageRecord(t *testing.T, f serviceJournalFixture) *agentv1.ResourceExecutionRecord {
	t.Helper()
	record := f.record(t, 1, "example.service", true)
	record.Intent.Desired = &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: "deb/example/amd64"}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, NativeName: "example", Architecture: "amd64"}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Version: &resourcev1.NativePackageDesired_Exact{Exact: &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: "1.0-1"}}}, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: "apt/" + uuid.NewString()}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA}}}
	record.Intent.Preparation = &agentv1.ResourceExecutionPreparation{Deadline: proto.CloneOf(record.GetIntent().GetExpiresAt()), MaxCacheBytes: 1 << 20}
	record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING
	record.NativePlan, record.Challenge = nil, nil
	record.ChallengeProof, record.ChallengeCertificatePem = nil, nil
	record.ChallengeBoottimeNs = 0
	return record
}

func TestResourcePreparingAdmissionReservationAndRestart(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := pendingPackageRecord(t, f)
	if revision, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil || revision != 1 {
		t.Fatalf("admit preparing: %v", err)
	}
	usage, err := f.store.queries.ReadResourceActionUsage(t.Context())
	if err != nil || usage.RecordBytes != maximumResourceActionBytes || usage.RecordCount != 1 {
		t.Fatal("preparation did not reserve complete lifecycle capacity")
	}
	pending, revision, err := f.store.NextUnfinishedResourceAction(t.Context(), "")
	if err != nil || revision != 1 || !proto.Equal(pending, record) {
		t.Fatal("PREPARING was treated as terminal by journal cursor")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	assertServiceRecord(t, reopened, record, 1)
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
	next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
	next.CompletedAt = proto.CloneOf(record.GetIntent().GetExpiresAt())
	next.PreparationOutcome = &agentv1.ResourcePreparationOutcome{Preparation: proto.CloneOf(record.GetIntent().GetPreparation()), Failure: next.GetFailure()}
	if _, err := reopened.UpdateResourceAction(t.Context(), 1, 1, 2, next); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.NextUnfinishedResourceAction(t.Context(), ""); !errors.Is(err, ErrResourceActionNotFound) {
		t.Fatal("effect-free terminal result retained pending reservation")
	}
	usage, err = reopened.queries.ReadResourceActionUsage(t.Context())
	if err != nil || usage.RecordBytes != int64(proto.Size(next)) {
		t.Fatal("terminal preparation did not release action reservation")
	}
	if _, err := reopened.UpdateResourceAction(t.Context(), 2, 1, 2, record); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatal("terminal stage was replayed")
	}
}

func TestResourcePreparingRejectsInventedEvidenceAndReboundLimits(t *testing.T) {
	for _, damage := range []string{"plan", "terminal-without-outcome", "grant", "deadline", "quota", "digest"} {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			record := pendingPackageRecord(t, f)
			if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
				t.Fatal(err)
			}
			next := proto.CloneOf(record)
			next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
			next.CompletedAt = proto.CloneOf(record.GetIntent().GetExpiresAt())
			next.PreparationOutcome = &agentv1.ResourcePreparationOutcome{Preparation: proto.CloneOf(record.GetIntent().GetPreparation()), Failure: next.GetFailure()}
			switch damage {
			case "plan":
				next.NativePlan = f.record(t, 2, "foreign.service", true).GetNativePlan()
			case "terminal-without-outcome":
				next.PreparationOutcome = nil
			case "grant":
				next.StartGrantEnvelope = []byte("unearned-start")
			case "deadline":
				next.Intent.Preparation.Deadline.Seconds--
				next.PreparationOutcome.Preparation.Deadline.Seconds--
			case "quota":
				next.Intent.Preparation.MaxCacheBytes++
				next.PreparationOutcome.Preparation.MaxCacheBytes++
			case "digest":
				next.IntentSha256[0]++
			}
			if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, next); !errors.Is(err, ErrResourceActionRejected) {
				t.Fatalf("accepted damaged preparation %s: %v", damage, err)
			}
			assertServiceRecord(t, f.store, record, 1)
		})
	}
}

func TestResourcePreparingDigestCorruptionFailsRestartClosed(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := pendingPackageRecord(t, f)
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	record.IntentSha256[0]++
	encoded, err := proto.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	db := openFixtureDB(t, f.directory, "rw")
	if _, err := db.Exec(`UPDATE resource_actions SET record = ?`, encoded); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(t.Context(), f.directory); !errors.Is(err, ErrRecoveryHold) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("corrupt durable preparation resumed: %v", err)
	}
}

func TestResourceNeverPreparedCancellationIsDurableDenialOnly(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := pendingPackageRecord(t, f)
	if err := f.store.CancelUnpreparedResourceAction(t.Context(), 1, record.GetIntent().GetActionId(), record.GetIntentSha256()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelUnpreparedResourceAction(t.Context(), 1, record.GetIntent().GetActionId(), record.GetIntentSha256()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelUnpreparedResourceAction(t.Context(), 1, record.GetIntent().GetActionId(), bytes.Repeat([]byte{7}, 32)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatal("conflicting cancellation digest accepted")
	}
	usage, err := f.store.queries.ReadResourceActionUsage(t.Context())
	if err != nil || usage.RecordCount != 0 || usage.RecordBytes != 0 {
		t.Fatal("never-prepared denial fabricated native action history")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.AcceptResourceAction(t.Context(), 1, 2, record); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatal("restart lost late-prepare cancellation fence")
	}
	other := proto.CloneOf(record)
	other.Intent.ActionId = uuid.NewString()
	if _, err := reopened.AcceptResourceAction(t.Context(), 1, 2, other); err != nil {
		t.Fatalf("cancellation advanced unrelated resource floor: %v", err)
	}
}
