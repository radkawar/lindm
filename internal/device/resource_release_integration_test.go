//go:build integration

package device

import (
	"crypto/sha256"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Synthetic authenticated refusal evidence exercises the server protocol only;
// it never claims the fixture observed or restored a native baseline.
func resourceRefusalResult(t *testing.T, f *dispatchFixture, work *devicev1.ResourceWork) *devicev1.ReportResourceResultRequest {
	t.Helper()
	intent := f.intent(t, work)
	now := time.Now().UTC().Add(-time.Second)
	stamp := timestamppb.New(now)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	status := &agentv1.ResourceExecutionStatus{
		ActionId: work.GetActionId(), IntentSha256: digest[:], State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
		Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED, AcceptedAt: stamp, CompletedAt: stamp,
		AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(), Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_BASELINE_UNKNOWN, BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), NativeEvidenceUnavailable: true},
	}
	attestation := &agentv1.ResourceExecutionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SessionEpoch: 1, ActionRevision: 1, Nonce: work.GetResultNonce(), IssuedAt: stamp, ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status}
	return &devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), AttestationEnvelope: f.sign(t, attestation, f.key), CertificatePem: f.certificate}
}

func TestResourceReleaseUsesOriginalOwnershipAndCurrentHeadFence(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	item := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	item.DependsOn = nil
	publishDispatchResources(t, f, item)
	assigned := f.assign(t, nil)
	original := f.work(t)
	originalIntent := f.intent(t, original)
	if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(f.result(t, original, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, false))); err != nil {
		t.Fatal(err)
	}
	clear := f.assignmentRequest(proto.String(assigned.GetAssignmentId()))
	clear.Target, clear.Clear = nil, true
	cleared, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear))
	if err != nil {
		t.Fatal(err)
	}
	pending := complianceState(t, f).GetReleases()
	if len(pending) != 1 || pending[0].GetState() != "pending" || pending[0].GetCompletedAt() != nil {
		t.Fatalf("release was not honestly pending: %v", pending)
	}
	work := f.work(t)
	intent := f.intent(t, work)
	if intent.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE || intent.GetDesiredRevision() != cleared.Msg.GetAssignment().GetAssignmentId() || intent.GetOwnership().GetAssignmentId() != intent.GetDesiredRevision() || intent.GetResourceSequence() <= originalIntent.GetResourceSequence() || !proto.Equal(intent.GetDesired(), originalIntent.GetDesired()) || !proto.Equal(intent.GetOwnership().GetSources()[0], originalIntent.GetOwnership().GetSources()[0]) {
		t.Fatal("release lost original desired/source, current head or sequence")
	}
	request := resourceRefusalResult(t, f, work)
	for range 2 {
		result, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
		if err != nil || !result.Msg.GetClosed() {
			t.Fatalf("signed release refusal failed exact replay: %v", err)
		}
	}
	releases := complianceState(t, f).GetReleases()
	if len(releases) != 1 || releases[0].GetState() != "baseline_unknown" || releases[0].GetCompletedAt() != nil || releases[0].GetReason() != "ownership_baseline_unavailable" {
		t.Fatalf("refusal fabricated cleanup: %v", releases)
	}
	assertNoResourceWork(t, f)
	var disposition int16
	if err := f.pool.QueryRow(t.Context(), "SELECT disposition FROM resource_assignment_resources WHERE assignment_id=$1 AND resource_id=$2", assigned.GetAssignmentId(), item.GetResourceId()).Scan(&disposition); err != nil || disposition != 3 {
		t.Fatalf("release corrupted original proof: %d %v", disposition, err)
	}
}

func TestResourceReleaseReassignmentRejectsOldStartAndDoesNotReleaseNewOwner(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	item := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	item.DependsOn = nil
	publishDispatchResources(t, f, item)
	assigned := f.assign(t, nil)
	clear := f.assignmentRequest(proto.String(assigned.GetAssignmentId()))
	clear.Target, clear.Clear = nil, true
	cleared, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(clear))
	if err != nil {
		t.Fatal(err)
	}
	work := f.work(t)
	f.assign(t, proto.String(cleared.Msg.GetAssignment().GetAssignmentId()))
	_, err = f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(&devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}))
	dispatchError(t, err, connect.CodeFailedPrecondition, "resource_action_closed")
	next := f.intent(t, f.work(t))
	if next.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		t.Fatal("reassigned resource was released")
	}
	releases := complianceState(t, f).GetReleases()
	if len(releases) != 1 || releases[0].GetState() != "release_conflict" || releases[0].GetReason() != "resource_reassigned" {
		t.Fatalf("reassignment did not fence pending release: %v", releases)
	}
}

func clearResourceAssignment(t *testing.T, f *dispatchFixture, assignment *adminv1.ResourceAssignment) *adminv1.ResourceAssignment {
	t.Helper()
	request := f.assignmentRequest(proto.String(assignment.GetAssignmentId()))
	request.Target, request.Clear = nil, true
	response, err := f.service.SetResourceAssignment(f.adminCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetAssignment()
}

func TestGrantedResourceReleaseRetainsOneOpenEffectAcrossHeadReplacement(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	item := proto.CloneOf(f.revision.GetSpec().GetResources()[1])
	item.DependsOn = nil
	publishDispatchResources(t, f, item)
	assigned := f.assign(t, nil)
	cleared := clearResourceAssignment(t, f, assigned)
	work := f.work(t)
	f.start(t, work)
	f.assign(t, proto.String(cleared.GetAssignmentId()))
	replayed := f.work(t)
	if replayed.GetActionId() != work.GetActionId() || len(replayed.GetStartGrantEnvelope()) == 0 {
		t.Fatal("new head displaced an issued release effect")
	}
	// Device-signed protocol fixture only: no native systemd restoration claim.
	request := f.result(t, replayed, 1, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, true)
	for range 2 {
		result, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request))
		if err != nil || !result.Msg.GetClosed() {
			t.Fatalf("release completion failed exact replay: %v", err)
		}
	}
	releases := complianceState(t, f).GetReleases()
	if len(releases) != 1 || releases[0].GetState() != "released" || releases[0].GetCompletedAt() == nil {
		t.Fatalf("authenticated release completion was not retained: %v", releases)
	}
	next := f.intent(t, f.work(t))
	if next.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE || next.GetResourceSequence() <= f.intent(t, work).GetResourceSequence() {
		t.Fatal("closed release did not unblock newer reconcile monotonically")
	}
}
