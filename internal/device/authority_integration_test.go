// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func signedSessionRequest(t *testing.T, svc *Service, principal core.DevicePrincipal, key ed25519.PrivateKey, predecessor uint64) *devicev1.AcquireSessionRequest {
	t.Helper()
	proof, err := svc.Authority.Sign(t.Context(), &agentv1.SessionAcquisition{
		DeploymentId: svc.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(),
		RequestId: uuid.NewString(), PredecessorEpoch: predecessor, Incarnation: uuid.NewString(), BootId: uuid.NewString(),
		InstallationId: principal.DeviceID.String(),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &devicev1.AcquireSessionRequest{AuthorityProof: proof}
}

func acquireTestSession(t *testing.T, ctx context.Context, svc *Service, principal core.DevicePrincipal, key ed25519.PrivateKey, predecessor uint64) (*devicev1.AcquireSessionRequest, *devicev1.AcquireSessionResponse) {
	t.Helper()
	request := signedSessionRequest(t, svc, principal, key, predecessor)
	response, err := svc.AcquireSession(core.WithDevicePrincipal(ctx, principal), connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetSessionEpoch() != predecessor+1 {
		t.Fatalf("session epoch = %d after predecessor %d", response.Msg.GetSessionEpoch(), predecessor)
	}
	return request, response.Msg
}

func signedRenewalRequest(t *testing.T, svc *Service, principal core.DevicePrincipal, key ed25519.PrivateKey, epoch uint64, csr []byte) *devicev1.RenewIdentityRequest {
	t.Helper()
	digest := sha256.Sum256(csr)
	proof, err := svc.Authority.Sign(t.Context(), &agentv1.RenewalIntent{
		DeploymentId: svc.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(),
		IssuanceRequestId: uuid.NewString(), PresentedCertificateSha256: principal.Fingerprint, CsrSha256: digest[:], SessionEpoch: epoch,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &devicev1.RenewIdentityRequest{CsrPem: csr, AuthorityProof: proof}
}

func TestSessionAuthorityReplayFenceAndHold(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key := ed25519Key(t)
	_, _, _, enrollment := enrollDevice(t, ctx, svc, ownerCtx, key)
	leaf := parseCertPEM(t, enrollment.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := core.WithDevicePrincipal(ctx, principal)
	first, firstReceipt := acquireTestSession(t, ctx, svc, principal, key, 0)
	second, secondReceipt := acquireTestSession(t, ctx, svc, principal, key, 1)
	for _, expected := range []struct {
		request *devicev1.AcquireSessionRequest
		receipt *devicev1.AcquireSessionResponse
	}{{first, firstReceipt}, {second, secondReceipt}} {
		actual, err := svc.AcquireSession(deviceCtx, connect.NewRequest(expected.request))
		if err != nil || !proto.Equal(actual.Msg, expected.receipt) {
			t.Fatalf("exact session replay changed receipt: %v", err)
		}
	}
	if _, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("old heartbeat epoch: %v", err)
	}
	old := hostObservation(principal.GenerationID.String(), 1, "old")
	old.SessionEpoch = 1
	if _, err := svc.ReportHostObservation(deviceCtx, connect.NewRequest(old)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("old observation epoch: %v", err)
	}
	current, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 2}))
	if err != nil || current.Msg.GetHostSequence() != 0 || current.Msg.GetPackageSequence() != 0 {
		t.Fatalf("heartbeat allocated an inventory sequence: %v", err)
	}
	conflict := signedSessionRequest(t, svc, principal, key, 1)
	if _, err := svc.AcquireSession(deviceCtx, connect.NewRequest(conflict)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different consumed predecessor: %v", err)
	}
	var state, generationState string
	var epoch, holds int64
	if err := conn.QueryRow(ctx, `SELECT d.state, g.state, g.session_epoch FROM devices d JOIN enrollment_generations g ON g.id=d.current_generation_id WHERE d.id=$1`, principal.DeviceID).Scan(&state, &generationState, &epoch); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2`, auditkind.DeviceRecoveryHold.String(), principal.DeviceID.String()).Scan(&holds); err != nil {
		t.Fatal(err)
	}
	if state != core.StateRecoveryHold || generationState != core.StateRecoveryHold || epoch != 2 || holds != 1 {
		t.Fatalf("hold was not durably committed: %q %q epoch=%d audits=%d", state, generationState, epoch, holds)
	}
	if _, err := svc.AcquireSession(deviceCtx, connect.NewRequest(second)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("held generation replay: %v", err)
	}
	listed, err := svc.ListDevices(ownerCtx, connect.NewRequest(&adminv1.ListDevicesRequest{}))
	if err != nil || len(listed.Msg.Devices) != 1 || listed.Msg.Devices[0].GetLifecycleState() != adminv1.DeviceState_DEVICE_STATE_RECOVERY_HOLD {
		t.Fatalf("held identity not visible in API: %v", err)
	}
	if _, err := svc.RevokeDevice(ownerCtx, approvedRevocation(t, svc, ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: principal.DeviceID.String(), Reason: "retire ambiguous identity"})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 2})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked held identity: %v", err)
	}
}

func TestSessionEnvelopeReencodingCannotCreateCloneHold(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := acquireTestSession(t, ctx, svc, principal, key, 0)
	var reencoded bytes.Buffer
	if err := json.Indent(&reencoded, request.AuthorityProof, "", "  "); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reencoded.Bytes(), request.AuthorityProof) {
		t.Fatal("fixture did not change unsigned envelope encoding")
	}
	deviceCtx := core.WithDevicePrincipal(ctx, principal)
	_, err = svc.AcquireSession(deviceCtx, connect.NewRequest(&devicev1.AcquireSessionRequest{AuthorityProof: reencoded.Bytes()}))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed wire request must conflict without creating a clone hold: %v", err)
	}
	state, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1}))
	if err != nil || state.Msg.SessionEpoch != 1 {
		t.Fatalf("unprivileged envelope reencoding changed protected authority: %v", err)
	}
}
