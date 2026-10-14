// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal/journaldb"
)

func readOnlyFinding(t *testing.T, f serviceJournalFixture, sequence uint64) *agentv1.ResourceExecutionRecord {
	t.Helper()
	record := f.record(t, sequence, "example.service", false)
	record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
	record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION
	record.Verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	record.Verification.After.GetSystemdService().ActiveState = "inactive"
	record.Verification.After.GetSystemdService().SubState = "dead"
	record.Verification.GetSystemdService().RuntimeMatches = false
	record.Verification.GetSystemdService().Converged = false
	return record
}

func TestReadOnlyFailuresRetainEvidenceWithoutOwnershipEffectHistory(t *testing.T) {
	f := newServiceJournalFixture(t)
	var first, last *agentv1.ResourceExecutionRecord
	for sequence := uint64(1); sequence <= 258; sequence++ {
		record := readOnlyFinding(t, f, sequence)
		if first == nil {
			first = record
		}
		last = record
		if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
			t.Fatalf("accept read-only finding %d: %v", sequence, err)
		}
	}
	usage, err := f.store.queries.ReadResourceActionUsage(t.Context())
	if err != nil || usage.RecordCount != 257 {
		t.Fatalf("read-only failure retention not bounded: %v", err)
	}
	if _, _, err := f.store.LoadResourceAction(t.Context(), first.GetIntent().GetActionId()); !errors.Is(err, ErrResourceActionNotFound) {
		t.Fatal("old non-floor finding was not pruned")
	}
	intent := last.GetIntent()
	effects, err := f.store.queries.ResourceOwnershipHistoricalEffects(t.Context(), journaldb.ResourceOwnershipHistoricalEffectsParams{DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Kind: int64(intent.GetDesired().GetRef().GetKind()), CanonicalKey: intent.GetDesired().GetRef().GetCanonicalKey()})
	if err != nil || effects != 0 {
		t.Fatal("read-only failure falsely blocked future ownership acquisition")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	assertServiceRecord(t, reopened, last, 1)
	if _, _, err := reopened.NextUnfinishedResourceAction(t.Context(), ""); !errors.Is(err, ErrResourceActionNotFound) {
		t.Fatal("read-only terminal finding queued effect work")
	}
	if _, err := reopened.AcceptResourceAction(t.Context(), 1, 2, readOnlyFinding(t, f, 257)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatal("pruning read-only failures lost monotonic sequence floor")
	}
}

func TestReadOnlyFailuresRequireBoundNativePostconditionEvidence(t *testing.T) {
	for _, damage := range []string{"effectful-plan", "missing-verification", "wrong-failure", "invented-success", "corrupt-digest"} {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			record := readOnlyFinding(t, f, 1)
			switch damage {
			case "effectful-plan":
				record.NativePlan.GetSystemdService().ChangeRuntime = true
			case "missing-verification":
				record.Verification = nil
			case "wrong-failure":
				record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
			case "invented-success":
				record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
				record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
			case "corrupt-digest":
				record.Verification.PlanSha256[0]++
			}
			if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); !errors.Is(err, ErrResourceActionRejected) {
				t.Fatalf("invalid read-only finding admitted: %v", err)
			}
		})
	}
}

func TestReadOnlyPostconditionFailureRetainsClockRollbackEvidence(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := readOnlyFinding(t, f, 1)
	record.CompletedAt = proto.CloneOf(record.GetAcceptedAt())
	record.CompletedAt.Seconds--
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil {
		t.Fatal(err)
	}
	assertServiceRecord(t, f.store, record, 1)
}
