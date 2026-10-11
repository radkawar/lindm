//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func approvedRecovery(t *testing.T, svc *Service, ctx context.Context, request *adminv1.CreateRecoveryEnrollmentGrantRequest) *connect.Request[adminv1.CreateRecoveryEnrollmentGrantRequest] {
	t.Helper()
	created, err := svc.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RecoverDevice{RecoverDevice: request}}))
	if err != nil {
		t.Fatal(err)
	}
	decision := connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "reviewed immutable generation replacement"})
	if _, err := svc.ApproveApproval(ctx, decision); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("self-approved identity recovery: %v", err)
	}
	if _, err := svc.ApproveApproval(approvalReviewer(t, svc, ctx), decision); err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = decision.Msg.GetApprovalId()
	return connect.NewRequest(request)
}

func TestRecoveryEnrollmentReplacesOnlyApprovedGeneration(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key := ed25519Key(t)
	_, _, originalCSR, original := enrollDevice(t, ctx, svc, ownerCtx, key)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, original.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, ctx, svc, principal, key, 0)
	request := &adminv1.CreateRecoveryEnrollmentGrantRequest{RequestId: uuid.NewString(), DeviceId: original.Msg.GetDeviceId(), ExpectedGenerationId: original.Msg.GetEnrollmentGeneration(), LifetimeSeconds: 120, Reason: "replace explicitly selected damaged installation"}
	if _, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unapproved identity replacement: %v", err)
	}
	approved := approvedRecovery(t, svc, ownerCtx, request)
	grant, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, approved)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest := &adminv1.CreateRecoveryEnrollmentGrantRequest{RequestId: uuid.NewString(), DeviceId: request.GetDeviceId(), ExpectedGenerationId: request.GetExpectedGenerationId(), LifetimeSeconds: 120, Reason: "independently approved competing replacement"}
	other, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, approvedRecovery(t, svc, ownerCtx, otherRequest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: grant.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: originalCSR})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("compromised identity key reused: %v", err)
	}
	if _, err := svc.GetSyncState(withDevicePrincipal(ctx, principal), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); err != nil {
		t.Fatalf("failed recovery retired original identity: %v", err)
	}
	newKey := ed25519Key(t)
	enrollRequest := &enrollmentv1.EnrollRequest{GrantSecret: grant.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: mustCSR(t, newKey, &x509.CertificateRequest{})}
	recovered, err := svc.Enroll(ctx, connect.NewRequest(enrollRequest))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Msg.GetDeviceId() != original.Msg.GetDeviceId() || recovered.Msg.GetEnrollmentGeneration() == original.Msg.GetEnrollmentGeneration() {
		t.Fatal("recovery did not preserve device and replace immutable generation")
	}
	replayed, err := svc.Enroll(ctx, connect.NewRequest(enrollRequest))
	if err != nil || !bytes.Equal(replayed.Msg.GetCertificatePem(), recovered.Msg.GetCertificatePem()) {
		t.Fatalf("interrupted recovery did not resume exact issuance: %v", err)
	}
	if _, err := svc.GetSyncState(withDevicePrincipal(ctx, principal), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); err == nil {
		t.Fatal("old generation retained authority after recovery")
	}
	if _, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: other.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("competing stale recovery replaced newer generation: %v", err)
	}
	lost, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, approved)
	if err != nil || !lost.Msg.GetSecretDeliveryUnknown() || lost.Msg.GetSecret() != "" {
		t.Fatalf("recovery issuance retry exposed or replaced bearer: %v", err)
	}
	var devices, generations, revoked int
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM devices), (SELECT count(*) FROM enrollment_generations), (SELECT count(*) FROM device_certificates WHERE status='revoked')`).Scan(&devices, &generations, &revoked); err != nil {
		t.Fatal(err)
	}
	if devices != 1 || generations != 2 || revoked != 1 {
		t.Fatalf("cutover devices=%d generations=%d revoked=%d", devices, generations, revoked)
	}
	newPrincipal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, recovered.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, ctx, svc, newPrincipal, newKey, 0)
}

func TestSignedInstallationConflictDurablyHoldsCurrentEpoch(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)})
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
	acquireTestSession(t, ctx, svc, principal, key, 0)
	// Normal next-boot acquisition keeps the installation and advances the epoch.
	acquireTestSession(t, ctx, svc, principal, key, 1)
	proof, err := svc.authority.Sign(ctx, &agentv1.SessionAcquisition{DeploymentId: svc.deploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), RequestId: uuid.NewString(), PredecessorEpoch: 2, Incarnation: uuid.NewString(), BootId: uuid.NewString(), InstallationId: uuid.NewString()}, key)
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := withDevicePrincipal(ctx, principal)
	if _, err := svc.AcquireSession(deviceCtx, connect.NewRequest(&devicev1.AcquireSessionRequest{AuthorityProof: proof})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different signed installation accepted at current predecessor: %v", err)
	}
	var state, generationState, reason string
	var epoch int64
	if err := conn.QueryRow(ctx, `SELECT d.state,g.state,g.session_epoch,(SELECT details->>'cause' FROM audit_events WHERE action='device.recovery_hold' AND reason='' AND resource_id=d.id::text) FROM devices d JOIN enrollment_generations g ON g.id=d.current_generation_id WHERE d.id=$1`, principal.DeviceID).Scan(&state, &generationState, &epoch, &reason); err != nil {
		t.Fatal(err)
	}
	if state != stateRecoveryHold || generationState != stateRecoveryHold || epoch != 2 || reason != "conflicting_installation_identity" {
		t.Fatalf("clone fence state=%s generation=%s epoch=%d reason=%s", state, generationState, epoch, reason)
	}
	if _, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 2})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("preexisting live session escaped clone hold: %v", err)
	}
}

func TestRecoveryEnrollmentDoesNotOverrideLaterRevocation(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	_, _, _, original := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
	request := func(revoked bool) *adminv1.CreateRecoveryEnrollmentGrantRequest {
		return &adminv1.CreateRecoveryEnrollmentGrantRequest{RequestId: uuid.NewString(), DeviceId: original.Msg.GetDeviceId(), ExpectedGenerationId: original.Msg.GetEnrollmentGeneration(), ExpectedRevoked: revoked, LifetimeSeconds: 120, Reason: "explicitly reviewed identity replacement"}
	}
	staleApproval := approvedRecovery(t, svc, ownerCtx, request(false))
	grant, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, approvedRecovery(t, svc, ownerCtx, request(false)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RevokeDevice(ownerCtx, approvedRevocation(t, svc, ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: original.Msg.GetDeviceId(), Reason: "later incident revocation overrides old recovery authorization"})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, staleApproval); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("approval preceding revocation revived identity: %v", err)
	}
	key := ed25519Key(t)
	csr := mustCSR(t, key, &x509.CertificateRequest{})
	if _, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: grant.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: csr})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("grant preceding revocation revived identity: %v", err)
	}
	var state string
	if err := conn.QueryRow(ctx, "SELECT state FROM devices WHERE id=$1", original.Msg.GetDeviceId()).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != stateRevoked {
		t.Fatal("denied recovery lost the revocation fence")
	}
	fresh, err := svc.CreateRecoveryEnrollmentGrant(ownerCtx, approvedRecovery(t, svc, ownerCtx, request(true)))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: fresh.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: csr}))
	if err != nil || recovered.Msg.GetDeviceId() != original.Msg.GetDeviceId() || recovered.Msg.GetEnrollmentGeneration() == original.Msg.GetEnrollmentGeneration() {
		t.Fatalf("new explicit approval could not recover revoked identity: %v", err)
	}
}
