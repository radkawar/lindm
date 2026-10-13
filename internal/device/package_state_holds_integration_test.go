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

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Rows the executor refused for device-local tool or package state (a stock
// Fedora 44 dnf5 below the package floor, a missing tool or unit) are
// dispatched again when the device commits a package snapshot with different
// content, such as after an OS update run upgraded dnf5; an unchanged
// snapshot and unrelated refusal reasons hold.
func TestPackageStateHoldsAreRedispatchedOnPackageChange(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	f.assign(t, nil)
	refuse := func(reason agentv1.ResourceAdmissionRefusalReason, detail string) string {
		t.Helper()
		work := f.work(t)
		if work == nil {
			t.Fatal("held row was not dispatched again")
		}
		intent := f.intent(t, work)
		now := time.Now().UTC().Add(-time.Second)
		stamp := timestamppb.New(now)
		digest := sha256.Sum256(work.GetIntentEnvelope())
		failure := agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED
		if reason == agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION {
			failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION
		}
		attestation := &agentv1.ResourceExecutionAttestation{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), SessionEpoch: 1, ActionRevision: 1, Nonce: work.GetResultNonce(), IssuedAt: stamp, ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), Status: &agentv1.ResourceExecutionStatus{
			ActionId: work.GetActionId(), IntentSha256: digest[:], State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
			Failure: failure, AcceptedAt: stamp, CompletedAt: stamp,
			AdmissionRefusal: &agentv1.ResourceAdmissionRefusal{Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(), Reason: reason, Detail: detail, BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), NativeEvidenceUnavailable: true},
		}}
		request := &devicev1.ReportResourceResultRequest{SessionEpoch: 1, ActionId: work.GetActionId(), CertificatePem: f.certificate, AttestationEnvelope: f.sign(t, attestation, f.key)}
		if _, err := f.service.ReportResourceResult(f.deviceCtx, connect.NewRequest(request)); err != nil {
			t.Fatal(err)
		}
		return intent.GetDesired().GetRef().GetCanonicalKey()
	}
	held := func(key string) (int16, string) {
		t.Helper()
		var disposition int16
		var reason string
		if err := f.pool.QueryRow(t.Context(), "SELECT disposition, reason FROM resource_assignment_resources WHERE canonical_key=$1", key).Scan(&disposition, &reason); err != nil {
			t.Fatal(err)
		}
		return disposition, reason
	}
	sequence := uint64(0)
	publish := func(names ...string) {
		t.Helper()
		// Snapshot admission is rate limited; age the previous one.
		if _, err := f.pool.Exec(t.Context(), "UPDATE enrollment_generations SET last_package_admission_at=clock_timestamp()-interval '10 minutes' WHERE id=$1", f.principal.GenerationID); err != nil {
			t.Fatal(err)
		}
		sequence++
		packages := make([]*inventoryv1.Package, len(names))
		for i, name := range names {
			packages[i] = &inventoryv1.Package{Name: name, Version: "5.4.1.0-1.fc44", Architecture: "x86_64", Manager: "rpm"}
		}
		raw := packageBatch(t, packages...)
		manifest := snapshotManifest(t, f.principal.GenerationID.String(), sequence, time.Now().UTC(), [][]byte{raw})
		generation := f.principal.GenerationID.String()
		if _, err := f.service.BeginPackageSnapshot(f.deviceCtx, connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{EnrollmentGeneration: generation, SessionEpoch: 1, Manifest: manifest})); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.PutPackageBatch(f.deviceCtx, connect.NewRequest(&devicev1.PutPackageBatchRequest{EnrollmentGeneration: generation, SessionEpoch: 1, SnapshotId: manifest.GetSnapshotId(), BatchIndex: 0, Batch: raw})); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.CommitPackageSnapshot(f.deviceCtx, connect.NewRequest(&devicev1.CommitPackageSnapshotRequest{EnrollmentGeneration: generation, SessionEpoch: 1, Manifest: manifest})); err != nil {
			t.Fatal(err)
		}
	}

	outdated := agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE
	key := refuse(outdated, "native_tool_outdated")
	if disposition, reason := held(key); disposition != 6 || reason != "native_tool_outdated" {
		t.Fatalf("refusal recorded as %d %s", disposition, reason)
	}
	if f.work(t) != nil {
		t.Fatal("package-state hold was dispatched without a change")
	}
	// The generation's first snapshot is a change.
	publish("dnf5", "rpm")
	if disposition, _ := held(key); disposition != 1 {
		t.Fatal("first package snapshot did not release the hold")
	}
	refuse(outdated, "native_tool_outdated")
	publish("dnf5", "rpm")
	if disposition, _ := held(key); disposition != 6 {
		t.Fatal("unchanged package snapshot released the hold")
	}
	publish("dnf5", "dnf5-plugin-automatic", "rpm")
	if disposition, _ := held(key); disposition != 1 {
		t.Fatal("changed package snapshot did not release the hold")
	}
	// Precondition holds (BLOCKED) are released the same way.
	refuse(agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_PRECONDITION, "native_tool_missing")
	if disposition, reason := held(key); disposition != 5 || reason != "native_tool_missing" {
		t.Fatalf("precondition refusal recorded as %d %s", disposition, reason)
	}
	publish("dnf5", "rpm")
	if disposition, _ := held(key); disposition != 1 {
		t.Fatal("changed package snapshot did not release the precondition hold")
	}
	// A refusal that no package change can resolve stays held.
	refuse(outdated, "")
	publish("dnf5", "rpm", "cups")
	if disposition, reason := held(key); disposition != 6 || reason != "native_unsupported" {
		t.Fatalf("unrelated refusal became %d %s", disposition, reason)
	}
}
