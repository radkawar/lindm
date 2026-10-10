package journal

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func resourceAdmissionRecord(t *testing.T, f serviceJournalFixture, sequence uint64) *agentv1.ResourceExecutionRecord {
	t.Helper()
	record := f.record(t, sequence, "example.service", false)
	metadata := record.GetNativePlan().GetBefore().GetMetadata()
	record.Intent.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	record.NativePlan, record.Verification = nil, nil
	record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
	record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED
	record.AdmissionRefusal = &agentv1.ResourceAdmissionRefusal{
		Ref: proto.CloneOf(record.GetIntent().GetDesired().GetRef()), Operation: record.GetIntent().GetOperation(),
		Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN,
		BootId: metadata.GetBootId(), ExecutorIncarnation: metadata.GetExecutorIncarnation(), NativeEvidenceUnavailable: true,
	}
	return record
}

func TestAdmissionRefusalRetainsSequenceFenceWithoutOwnership(t *testing.T) {
	f := newServiceJournalFixture(t)
	record := resourceAdmissionRecord(t, f, 1)
	if revision, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); err != nil || revision != 1 {
		t.Fatalf("accept refusal: %d %v", revision, err)
	}
	assertServiceRecord(t, f.store, record, 1)
	intent := record.GetIntent()
	if _, err := f.store.LoadResourceOwnership(t.Context(), intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration(), intent.GetDesired().GetRef()); !errors.Is(err, ErrResourceOwnershipNotFound) {
		t.Fatalf("refusal invented ownership: %v", err)
	}
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, f.record(t, 1, "example.service", true)); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("refusal did not advance resource floor: %v", err)
	}
	if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, f.record(t, 2, "example.service", true)); err != nil {
		t.Fatalf("refusal blocked new signed sequence: %v", err)
	}
	if _, err := f.store.UpdateResourceAction(t.Context(), 1, 1, 2, record); !errors.Is(err, ErrResourceActionRejected) {
		t.Fatalf("terminal refusal allowed transition: %v", err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.store, err = Open(t.Context(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	assertServiceRecord(t, f.store, record, 1)
}

func TestAdmissionRefusalRejectsFabricatedNativeAndEffectEvidence(t *testing.T) {
	for _, damage := range []string{"wrong-ref", "wrong-operation", "success", "native-plan", "verification", "start", "missing-reason", "observation-claimed", "missing-executor", "wrong-failure", "challenge"} {
		t.Run(damage, func(t *testing.T) {
			f := newServiceJournalFixture(t)
			record := resourceAdmissionRecord(t, f, 1)
			valid := f.record(t, 1, "example.service", true)
			switch damage {
			case "wrong-ref":
				record.AdmissionRefusal.Ref.CanonicalKey = "another.service"
			case "wrong-operation":
				record.AdmissionRefusal.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE
			case "success":
				record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
				record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
			case "native-plan":
				record.NativePlan = valid.GetNativePlan()
			case "verification":
				record.Verification = serviceConverged(valid)
			case "start":
				record.StartedAt = proto.CloneOf(record.GetAcceptedAt())
			case "missing-reason":
				record.AdmissionRefusal.Reason = agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSPECIFIED
			case "observation-claimed":
				record.AdmissionRefusal.NativeEvidenceUnavailable = false
			case "missing-executor":
				record.AdmissionRefusal.ExecutorIncarnation = ""
			case "wrong-failure":
				record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION
			case "challenge":
				record.Challenge = valid.GetChallenge()
				record.ChallengeProof = valid.GetChallengeProof()
				record.ChallengeBoottimeNs = valid.GetChallengeBoottimeNs()
				record.ChallengeCertificatePem = valid.GetChallengeCertificatePem()
			}
			if _, err := f.store.AcceptResourceAction(t.Context(), 1, 2, record); !errors.Is(err, ErrResourceActionRejected) {
				t.Fatalf("accepted %s refusal evidence: %v", damage, err)
			}
		})
	}
}

func TestAdmissionRefusalRequiresCurrentJournalFences(t *testing.T) {
	for _, fence := range []struct{ authority, trust int64 }{{2, 2}, {1, 1}} {
		f := newServiceJournalFixture(t)
		if _, err := f.store.AcceptResourceAction(t.Context(), fence.authority, fence.trust, resourceAdmissionRecord(t, f, 1)); err == nil {
			t.Fatal("refusal bypassed current authority/trust CAS")
		}
	}
}
