//go:build integration

package device

import (
	"crypto/sha256"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

// A device-attested native-busy staging refusal (dpkg held by another
// frontend such as a release upgrade) is recorded as an explicit BLOCKED hold,
// mints no replacement work inside the reconcile interval and is re-dispatched
// once the interval has passed.
func TestNativeBusyPreparationIsAnExplicitRetriedHold(t *testing.T) {
	f, head := newPreparationDispatchFixture(t)
	work := f.work(t)
	intent := f.intent(t, work)
	digest := sha256.Sum256(work.GetIntentEnvelope())
	now := time.Now().UTC().Add(-time.Second)
	busy := agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY
	status := &agentv1.ResourceExecutionStatus{ActionId: work.GetActionId(), IntentSha256: digest[:], State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, Failure: busy, AcceptedAt: timestamppb.New(now), CompletedAt: timestamppb.New(now),
		PreparationOutcome: &agentv1.ResourcePreparationOutcome{Preparation: proto.CloneOf(intent.GetPreparation()), Failure: busy}}
	attestation := &agentv1.ResourceExecutionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		SessionEpoch: 1, ActionRevision: 1, Nonce: work.GetResultNonce(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: status}
	response, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(&devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), AttestationEnvelope: f.sign(t, attestation, f.key), CertificatePem: f.certificate}))
	if err != nil || !response.Msg.GetClosed() {
		t.Fatalf("native-busy result was not a terminal report: %v", err)
	}
	state := complianceState(t, f).GetResources()[0]
	if state.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED || state.GetReason() != resourceReasonNativeBusy || state.GetObservedAt() == nil || state.GetLastVerifiedAt() != nil || state.GetLatestAction().GetStatus().GetFailure() != busy {
		t.Fatalf("native-busy refusal was not an explicit hold: %v", state)
	}
	if next := f.work(t); next != nil {
		t.Fatal("hold was retried inside the reconcile interval")
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE resource_assignment_resources SET observed_at = observed_at - (reconcile.seconds * interval '1 second') FROM (SELECT reconcile_interval_seconds AS seconds FROM resource_assignments WHERE id = $1) reconcile WHERE assignment_id = $1", head.GetAssignmentId()); err != nil {
		t.Fatal(err)
	}
	retry := f.work(t)
	if retry == nil || retry.GetActionId() == work.GetActionId() {
		t.Fatal("hold was not re-dispatched after the reconcile interval")
	}
}
