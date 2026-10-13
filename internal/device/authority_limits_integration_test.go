//go:build integration

package device

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestSessionConcurrentReplayAndReceiptCapacity(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = func() time.Time { return now }
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.CertificatePem))
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := core.WithDevicePrincipal(ctx, principal)
	request := signedSessionRequest(t, svc, principal, key, 0)
	type outcome struct {
		response *connect.Response[devicev1.AcquireSessionResponse]
		err      error
	}
	results := make(chan outcome, 12)
	var workers sync.WaitGroup
	for range cap(results) {
		workers.Go(func() {
			response, err := svc.AcquireSession(deviceCtx, connect.NewRequest(request))
			results <- outcome{response, err}
		})
	}
	workers.Wait()
	close(results)
	var original *devicev1.AcquireSessionResponse
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.Msg.SessionEpoch != 1 {
			t.Fatalf("concurrent retry advanced epoch to %d", result.response.Msg.SessionEpoch)
		}
		if original == nil {
			original = result.response.Msg
		} else if !proto.Equal(original, result.response.Msg) {
			t.Fatal("concurrent retry changed its receipt")
		}
	}
	var receipts int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM device_session_receipts WHERE generation_id=$1`, principal.GenerationID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("concurrent acquisition stored %d receipts", receipts)
	}
	if _, err := svc.AcquireSession(deviceCtx, connect.NewRequest(signedSessionRequest(t, svc, principal, key, 2))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("future predecessor accepted: %v", err)
	}
	if _, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); err != nil {
		t.Fatalf("future predecessor created a false clone hold: %v", err)
	}

	// Seed the persisted counter immediately below its boundary without making
	// tens of thousands of boots part of the developer feedback loop.
	if _, err := conn.Exec(ctx, `UPDATE enrollment_generations SET session_epoch=$1 WHERE id=$2`, core.MaxSessionReceipts-1, principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	lastRequest, lastReceipt := acquireTestSession(t, ctx, svc, principal, key, core.MaxSessionReceipts-1)
	if _, err := svc.AcquireSession(deviceCtx, connect.NewRequest(signedSessionRequest(t, svc, principal, key, core.MaxSessionReceipts))); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("receipt cap not enforced: %v", err)
	}
	replayed, err := svc.AcquireSession(deviceCtx, connect.NewRequest(lastRequest))
	if err != nil || !proto.Equal(lastReceipt, replayed.Msg) {
		t.Fatalf("capacity prevented original receipt recovery: %v", err)
	}
	state, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: core.MaxSessionReceipts}))
	if err != nil || state.Msg.SessionEpoch != core.MaxSessionReceipts {
		t.Fatalf("capacity reset or disabled current session: %v", err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM device_session_receipts WHERE generation_id=$1`, principal.GenerationID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 {
		t.Fatalf("capacity failure changed receipt retention: %d", receipts)
	}
}

func TestCompetingSessionSuccessorsCommitRecoveryHold(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = func() time.Time { return now }
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.CertificatePem))
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := core.WithDevicePrincipal(ctx, principal)
	requests := []*devicev1.AcquireSessionRequest{signedSessionRequest(t, svc, principal, key, 0), signedSessionRequest(t, svc, principal, key, 0)}
	results := make(chan error, len(requests))
	var workers sync.WaitGroup
	for _, request := range requests {
		workers.Go(func() { _, err := svc.AcquireSession(deviceCtx, connect.NewRequest(request)); results <- err })
	}
	workers.Wait()
	accepted, denied := 0, 0
	for range requests {
		err := <-results
		switch {
		case err == nil:
			accepted++
		case connect.CodeOf(err) == connect.CodePermissionDenied:
			denied++
		default:
			t.Fatalf("unexpected competing acquisition outcome: %v", err)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatalf("competing acquisitions: accepted=%d denied=%d", accepted, denied)
	}
	if _, err := svc.GetSyncState(deviceCtx, connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("competing successor hold was rolled back: %v", err)
	}
	var deviceState, generationState string
	var epoch, audits int64
	if err := conn.QueryRow(ctx, `SELECT d.state,g.state,g.session_epoch,(SELECT count(*) FROM audit_events WHERE action=$3 AND resource_id=$2) FROM devices d JOIN enrollment_generations g ON g.id=d.current_generation_id WHERE d.id=$1`, principal.DeviceID, principal.DeviceID.String(), auditkind.DeviceRecoveryHold.String()).Scan(&deviceState, &generationState, &epoch, &audits); err != nil {
		t.Fatal(err)
	}
	if deviceState != "recovery_hold" || generationState != "recovery_hold" || epoch != 1 || audits != 1 {
		t.Fatalf("incomplete durable clone fence: %s/%s epoch=%d audit=%d", deviceState, generationState, epoch, audits)
	}
}

func TestRenewalReceiptCapacityPreservesOriginalIssuance(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = func() time.Time { return now }
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key, nextKey := ed25519Key(t), ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.CertificatePem))
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := core.WithDevicePrincipal(ctx, principal)
	acquireTestSession(t, ctx, svc, principal, key, 0)
	if _, err := conn.Exec(ctx, `UPDATE enrollment_generations SET renewal_issuance_count=$1 WHERE id=$2`, core.MaxRenewalReceipts-1, principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	request := signedRenewalRequest(t, svc, principal, key, 1, mustCSR(t, nextKey, &x509.CertificateRequest{}))
	renewed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(renewed.Msg, replayed.Msg) {
		t.Fatalf("capacity lost original issuance: %v", err)
	}
	nextPrincipal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, renewed.Msg.CertificatePem))
	if err != nil {
		t.Fatal(err)
	}
	nextRequest := signedRenewalRequest(t, svc, nextPrincipal, nextKey, 1, mustCSR(t, ed25519Key(t), &x509.CertificateRequest{}))
	if _, err := svc.RenewIdentity(core.WithDevicePrincipal(ctx, nextPrincipal), connect.NewRequest(nextRequest)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("renewal receipt cap not enforced: %v", err)
	}
	var issuances, certificates int
	if err := conn.QueryRow(ctx, `SELECT renewal_issuance_count,(SELECT count(*) FROM device_certificates WHERE device_id=$1) FROM enrollment_generations WHERE id=$2`, principal.DeviceID, principal.GenerationID).Scan(&issuances, &certificates); err != nil {
		t.Fatal(err)
	}
	if issuances != core.MaxRenewalReceipts || certificates != 2 {
		t.Fatalf("capacity failure mutated issuance authority: count=%d certificates=%d", issuances, certificates)
	}
}
