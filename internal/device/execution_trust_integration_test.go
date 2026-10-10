//go:build integration

package device

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestUnprovisionedExecutionTrustStillFencesDeviceAuthority(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	svc.clock = func() time.Time { return now }
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := withDevicePrincipal(ctx, principal)
	request := func(epoch uint64) *connect.Request[devicev1.GetExecutionTrustRequest] {
		return connect.NewRequest(&devicev1.GetExecutionTrustRequest{SessionEpoch: epoch, RootVersion: 1, RootSha256: make([]byte, sha256.Size)})
	}
	denied := func(callCtx context.Context, epoch uint64, code connect.Code) {
		t.Helper()
		if _, err := svc.GetExecutionTrust(callCtx, request(epoch)); connect.CodeOf(err) != code {
			t.Fatalf("trust fetch with ineligible authority: %v; want %v", err, code)
		}
	}
	allowed := func(callCtx context.Context, epoch uint64) {
		t.Helper()
		response, err := svc.GetExecutionTrust(callCtx, request(epoch))
		if err != nil {
			t.Fatal(err)
		}
		if response.Msg.GetUpdate() != nil || response.Msg.GetRootVersion() != 0 || response.Msg.GetDelegationVersion() != 0 || response.Msg.GetMinimumRecoveryEpoch() != 0 {
			t.Fatal("unprovisioned server invented execution authority")
		}
	}
	denied(ctx, 1, connect.CodeUnauthenticated)
	denied(deviceCtx, 1, connect.CodeFailedPrecondition)
	acquireTestSession(t, ctx, svc, principal, key, 0)
	allowed(deviceCtx, 1)
	acquireTestSession(t, ctx, svc, principal, key, 1)
	denied(deviceCtx, 1, connect.CodeFailedPrecondition)
	allowed(deviceCtx, 2)

	// Trust delivery uses the existing eligible-credential overlap contract,
	// not an immediate cutoff at renewal and not indefinitely cached mTLS auth.
	nextKey := ed25519Key(t)
	renewed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(signedRenewalRequest(t, svc, principal, key, 2, mustCSR(t, nextKey, &x509.CertificateRequest{}))))
	if err != nil {
		t.Fatal(err)
	}
	nextPrincipal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, renewed.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	nextCtx := withDevicePrincipal(ctx, nextPrincipal)
	allowed(deviceCtx, 2)
	allowed(nextCtx, 2)
	now = now.Add(renewalOverlap + time.Second)
	denied(deviceCtx, 2, connect.CodePermissionDenied)
	allowed(nextCtx, 2)

	conflict := signedSessionRequest(t, svc, nextPrincipal, nextKey, 1)
	if _, err := svc.AcquireSession(nextCtx, connect.NewRequest(conflict)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("conflicting predecessor did not enter recovery hold: %v", err)
	}
	denied(nextCtx, 2, connect.CodePermissionDenied)
	if _, err := svc.RevokeDevice(ownerCtx, approvedRevocation(t, svc, ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: principal.DeviceID.String(), Reason: "retire held trust-fetch identity"})); err != nil {
		t.Fatal(err)
	}
	denied(nextCtx, 2, connect.CodePermissionDenied)
}
