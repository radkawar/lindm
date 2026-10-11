package device

import (
	"testing"

	"lindm/internal/device/dispatch"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
)

func TestResourceAdmissionRefusalCannotBecomeNativeEvidence(t *testing.T) {
	intent := &agentv1.ResourceExecutionIntent{Desired: qualifiedServiceResource().GetDesired(), Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE}
	status := &agentv1.ResourceExecutionStatus{State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED, AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(), Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN, NativeEvidenceUnavailable: true}}
	if err := dispatch.ResourceResultBinding(intent, status); err != nil {
		t.Fatal(err)
	}
	if state, _ := dispatch.ReleaseResultState(status); state != "baseline_unknown" {
		t.Fatalf("refusal claimed release: %s", state)
	}
	for _, change := range []func(*agentv1.ResourceExecutionStatus){
		func(s *agentv1.ResourceExecutionStatus) { s.AdmissionRefusal.Ref.CanonicalKey = "another.service" },
		func(s *agentv1.ResourceExecutionStatus) {
			s.AdmissionRefusal.Operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE
		},
		func(s *agentv1.ResourceExecutionStatus) {
			s.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
		},
		func(s *agentv1.ResourceExecutionStatus) { s.Before = &resourcev1.ResourceObservation{} },
		func(s *agentv1.ResourceExecutionStatus) { s.Verification = &resourcev1.ResourceVerification{} },
		func(s *agentv1.ResourceExecutionStatus) { s.ReadOnly = true },
		func(s *agentv1.ResourceExecutionStatus) {
			s.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
		},
	} {
		changed := proto.CloneOf(status)
		change(changed)
		if err := dispatch.ResourceResultBinding(intent, changed); err == nil {
			t.Fatal("accepted mismatched or fabricated refusal evidence")
		}
	}
}

func TestReleaseAuthorityHeadIsNotHistoricalSourceAssignment(t *testing.T) {
	source, head, release := uuid.New(), uuid.New(), uuid.New()
	action := devicedb.ResourceAction{AssignmentID: source, ReleaseID: &release}
	intent := &agentv1.ResourceExecutionIntent{DesiredRevision: head.String(), Operation: resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE, Ownership: &agentv1.ResourceOwnershipBinding{AssignmentId: head.String()}}
	got, err := dispatch.ResourceActionHead(action, intent)
	if err != nil || got != head {
		t.Fatalf("release used historical actor/head: %s %v", got, err)
	}
	intent.Ownership.AssignmentId = source.String()
	if _, err := dispatch.ResourceActionHead(action, intent); err == nil {
		t.Fatal("release ownership bypassed current head fence")
	}
	action.ReleaseID = nil
	if _, err := dispatch.ResourceActionHead(action, intent); err == nil {
		t.Fatal("unassociated release admitted as reconcile action")
	}
}
