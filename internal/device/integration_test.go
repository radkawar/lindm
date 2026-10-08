//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestDurableEnrollmentBoundaries(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, signer := testCA(t, time.Now().Add(90*24*time.Hour))
	deployment := uuid.New()
	svc, err := New(pool, Config{DeploymentID: deployment.String(), CACertificate: ca, CAKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	auditor := insertPrincipal(t, ctx, conn, "auditor")
	ownerCtx := identity.WithPrincipal(ctx, owner)
	auditorCtx := identity.WithPrincipal(ctx, auditor)

	if _, err := svc.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("missing principal: %v", err)
	}
	if _, err := svc.CreateEnrollmentGrant(auditorCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{
		RequestId: uuid.NewString(), LifetimeSeconds: 60, Reason: "auditor",
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("auditor grant: %v", err)
	}

	requestID := uuid.NewString()
	first, err := svc.CreateEnrollmentGrant(ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{
		RequestId: requestID, LifetimeSeconds: 120, Reason: "install lab image",
	}))
	if err != nil {
		t.Fatal(err)
	}
	secret := first.Msg.GetSecret()
	grantID := first.Msg.GetGrantId()
	expires := first.Msg.GetExpiresAt().AsTime()
	if secret == "" || first.Msg.GetSecretDeliveryUnknown() {
		t.Fatal("first grant response did not deliver the secret")
	}
	replay, err := svc.CreateEnrollmentGrant(ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{
		RequestId: requestID, LifetimeSeconds: 120, Reason: "install lab image",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if replay.Msg.GetSecret() != "" || !replay.Msg.GetSecretDeliveryUnknown() || replay.Msg.GetGrantId() != grantID || !replay.Msg.GetExpiresAt().AsTime().Equal(expires) {
		t.Fatal("replay recovered or changed the grant")
	}
	if _, err := svc.CreateEnrollmentGrant(ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{
		RequestId: requestID, LifetimeSeconds: 180, Reason: "different",
	})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed payload: %v", err)
	}
	assertSecretAbsent(t, ctx, conn, secret)

	key := p256Key(t)
	csr := mustCSR(t, key, &x509.CertificateRequest{})
	txID := uuid.NewString()
	enrolled, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: txID, CsrPem: csr,
	}))
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: txID, CsrPem: csr,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Msg.GetDeviceId() != enrolled.Msg.GetDeviceId() || !bytes.Equal(resumed.Msg.GetCertificatePem(), enrolled.Msg.GetCertificatePem()) {
		t.Fatal("lost enrollment response did not resume the same certificate")
	}
	if _, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: uuid.NewString(), CsrPem: csr,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different transaction: %v", err)
	}
	if _, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: txID, CsrPem: mustCSR(t, p256Key(t), &x509.CertificateRequest{}),
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different key: %v", err)
	}

	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatalf("issued cert rejected before renewal: %v", err)
	}
	assertRenewalFence(t, ctx, conn, svc, principal)
	assertConcurrentRenewal(t, ctx, conn, svc, ownerCtx)
	deviceCtx := withDevicePrincipal(ctx, devicePrincipal{
		DeviceID:      uuid.MustParse(enrolled.Msg.GetDeviceId()),
		GenerationID:  uuid.MustParse(enrolled.Msg.GetEnrollmentGeneration()),
		CertificateID: certificateID(t, ctx, conn, leaf),
	})
	boot := uuid.NewString()
	generation := enrolled.Msg.GetEnrollmentGeneration()
	deviceID := enrolled.Msg.GetDeviceId()
	if _, err := svc.ReportInventory(deviceCtx, connect.NewRequest(inventory(generation, boot, 1, "alpha"))); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReportInventory(deviceCtx, connect.NewRequest(inventory(generation, boot, 1, "alpha"))); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReportInventory(deviceCtx, connect.NewRequest(inventory(generation, boot, 1, "beta"))); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("changed sequence content: %v", err)
	}
	if got := deviceHostname(t, ctx, conn, deviceID); got != "alpha" {
		t.Fatalf("conflict overwrote hostname %q", got)
	}
	if _, err := svc.ReportInventory(deviceCtx, connect.NewRequest(inventory(generation, boot, 2, "beta"))); err != nil {
		t.Fatal(err)
	}
	old, err := svc.ReportInventory(deviceCtx, connect.NewRequest(inventory(generation, boot, 1, "alpha")))
	if err != nil {
		t.Fatal(err)
	}
	if old.Msg.GetAcceptedSequence() != 2 || deviceHostname(t, ctx, conn, deviceID) != "beta" {
		t.Fatal("old sequence overwrote newer facts")
	}
	if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(&adminv1.RevokeDeviceRequest{
		RequestId: uuid.NewString(), DeviceId: deviceID, Reason: "stolen",
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf); err == nil {
		t.Fatal("revoked certificate still authenticated")
	}
}

func (s *Service) authenticateDeviceRequest(r *http.Request, leaf *x509.Certificate) (devicePrincipal, error) {
	r.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf},
		VerifiedChains:    [][]*x509.Certificate{{leaf, s.ca}},
	}
	now := s.now()
	got, deviceID, generationID, err := s.presentedIdentity(r, now)
	if err != nil {
		return devicePrincipal{}, err
	}
	return s.bindCertificate(r.Context(), got, deviceID, generationID, now)
}

func inventory(generation, boot string, seq uint64, host string) *devicev1.ReportInventoryRequest {
	return &devicev1.ReportInventoryRequest{
		EnrollmentGeneration: generation,
		BootId:               boot,
		Sequence:             seq,
		Hostname:             host,
		OsId:                 "debian",
		OsVersion:            "12",
		Architecture:         "amd64",
		PackagesComplete:     true,
		Packages:             []*devicev1.Package{{Name: "openssh", Version: "1:9.2p1-2", Architecture: "amd64", Manager: "apt"}},
	}
}

func insertPrincipal(t *testing.T, ctx context.Context, conn *pgx.Conn, role string) identity.Principal {
	t.Helper()
	id := uuid.New()
	issuer := "https://idp.example"
	subject := "subject-" + id.String()
	pinned := ""
	if role == identity.RoleOwner {
		pinned = identity.RoleOwner
	}
	if _, err := conn.Exec(ctx, `INSERT INTO principals (id, issuer, subject, pinned_role) VALUES ($1, $2, $3, $4)`, id, issuer, subject, pinned); err != nil {
		t.Fatal(err)
	}
	return identity.Principal{ID: id, Issuer: issuer, Subject: subject, Role: role}
}

func assertSecretAbsent(t *testing.T, ctx context.Context, conn *pgx.Conn, secret string) {
	t.Helper()
	var found int
	err := conn.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT reason AS value FROM enrollment_grants
			UNION ALL SELECT revoke_reason FROM enrollment_grants
			UNION ALL SELECT reason FROM audit_events
			UNION ALL SELECT encode(token_hash, 'escape') FROM enrollment_grants
			UNION ALL SELECT encode(request_digest, 'escape') FROM device_admin_requests
		) rows
		WHERE position($1 in value) > 0`, secret).Scan(&found)
	if err != nil {
		t.Fatal(err)
	}
	if found != 0 {
		t.Fatal("plaintext grant secret was persisted")
	}
}

func deviceHostname(t *testing.T, ctx context.Context, conn *pgx.Conn, id string) string {
	t.Helper()
	var host string
	if err := conn.QueryRow(ctx, `SELECT hostname FROM devices WHERE id = $1`, id).Scan(&host); err != nil {
		t.Fatal(err)
	}
	return host
}

func certificateID(t *testing.T, ctx context.Context, conn *pgx.Conn, leaf *x509.Certificate) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	sum := sha256.Sum256(leaf.Raw)
	if err := conn.QueryRow(ctx, `SELECT id FROM device_certificates WHERE fingerprint = $1`, sum[:]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertRenewalFence(t *testing.T, ctx context.Context, conn *pgx.Conn, svc *Service, principal devicePrincipal) {
	t.Helper()
	csrB := mustCSR(t, p256Key(t), &x509.CertificateRequest{})
	deviceCtx := withDevicePrincipal(ctx, principal)
	renewed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: csrB}))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: csrB}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renewed.Msg.GetCertificatePem(), replay.Msg.GetCertificatePem()) {
		t.Fatal("overlapping certificate did not replay the issued renewal")
	}
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: mustCSR(t, p256Key(t), &x509.CertificateRequest{})})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("overlapping certificate minted a new key: %v", err)
	}
	if got := activeCertificatePEM(t, ctx, conn, principal.DeviceID); !bytes.Equal(got, renewed.Msg.GetCertificatePem()) {
		t.Fatal("rejected renewal displaced the active certificate")
	}
}

func assertConcurrentRenewal(t *testing.T, ctx context.Context, conn *pgx.Conn, svc *Service, ownerCtx context.Context) {
	t.Helper()
	created, err := svc.CreateEnrollmentGrant(ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{
		RequestId: uuid.NewString(), LifetimeSeconds: 120, Reason: "concurrent renewal",
	}))
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: created.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: mustCSR(t, p256Key(t), &x509.CertificateRequest{}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := withDevicePrincipal(ctx, principal)
	csrs := [][]byte{
		mustCSR(t, p256Key(t), &x509.CertificateRequest{}),
		mustCSR(t, p256Key(t), &x509.CertificateRequest{}),
	}
	results := make([]struct {
		pem []byte
		err error
	}, len(csrs))
	var wg sync.WaitGroup
	for i := range csrs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: csrs[i]}))
			if err != nil {
				results[i].err = err
				return
			}
			results[i].pem = append([]byte(nil), resp.Msg.GetCertificatePem()...)
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, result := range results {
		if result.err == nil {
			if winner >= 0 {
				t.Fatal("concurrent renewals both issued a certificate")
			}
			winner = i
			continue
		}
		if connect.CodeOf(result.err) != connect.CodePermissionDenied {
			t.Fatalf("concurrent renewal error: %v", result.err)
		}
	}
	if winner < 0 {
		t.Fatal("concurrent renewals produced no certificate")
	}
	if got := activeCertificatePEM(t, ctx, conn, principal.DeviceID); !bytes.Equal(got, results[winner].pem) {
		t.Fatal("concurrent renewal displaced the winning certificate")
	}
	replay, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: csrs[winner]}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replay.Msg.GetCertificatePem(), results[winner].pem) {
		t.Fatal("lost concurrent renewal response was not replayed")
	}
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: mustCSR(t, p256Key(t), &x509.CertificateRequest{})})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("retired certificate minted another key after concurrent renewal: %v", err)
	}
}

func activeCertificatePEM(t *testing.T, ctx context.Context, conn *pgx.Conn, deviceID uuid.UUID) []byte {
	t.Helper()
	var pemText string
	if err := conn.QueryRow(ctx, `SELECT pem FROM device_certificates WHERE device_id = $1 AND status = 'active'`, deviceID).Scan(&pemText); err != nil {
		t.Fatal(err)
	}
	return []byte(pemText)
}

func TestEnrollmentReplayAfterRenewal(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, signer := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	t.Run("same key", func(t *testing.T) {
		assertEnrollmentReplayAfterRenewal(t, ctx, svc, ownerCtx, true)
	})
	t.Run("different key", func(t *testing.T) {
		assertEnrollmentReplayAfterRenewal(t, ctx, svc, ownerCtx, false)
	})
	t.Run("retired issuance", func(t *testing.T) {
		assertRetiredEnrollmentReplayRejected(t, ctx, conn, svc, ownerCtx)
	})
	t.Run("revoked device", func(t *testing.T) {
		assertRevokedDeviceEnrollmentReplayRejected(t, ctx, svc, ownerCtx)
	})
}

func assertEnrollmentReplayAfterRenewal(t *testing.T, ctx context.Context, svc *Service, ownerCtx context.Context, sameKey bool) {
	t.Helper()
	key := p256Key(t)
	secret, txID, csr, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	renewKey := key
	if !sameKey {
		renewKey = p256Key(t)
	}
	renewed, err := svc.RenewIdentity(withDevicePrincipal(ctx, principal), connect.NewRequest(&devicev1.RenewIdentityRequest{
		CsrPem: mustCSR(t, renewKey, &x509.CertificateRequest{}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed.Msg.GetCertificatePem(), enrolled.Msg.GetCertificatePem()) {
		t.Fatal("renewal did not issue a distinct certificate")
	}
	replay, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: txID, CsrPem: csr,
	}))
	if err != nil {
		t.Fatalf("enrollment replay after renewal: %v", err)
	}
	if replay.Msg.GetDeviceId() != enrolled.Msg.GetDeviceId() || replay.Msg.GetEnrollmentGeneration() != enrolled.Msg.GetEnrollmentGeneration() {
		t.Fatal("enrollment replay changed device identity")
	}
	if !bytes.Equal(replay.Msg.GetCertificatePem(), enrolled.Msg.GetCertificatePem()) || bytes.Equal(replay.Msg.GetCertificatePem(), renewed.Msg.GetCertificatePem()) {
		t.Fatal("enrollment replay substituted the renewed certificate")
	}
	if enrolled.Msg.GetExpiresAt() == nil || replay.Msg.GetExpiresAt() == nil || !replay.Msg.GetExpiresAt().AsTime().Equal(enrolled.Msg.GetExpiresAt().AsTime()) {
		t.Fatal("enrollment replay changed certificate expiration")
	}
}

func assertRetiredEnrollmentReplayRejected(t *testing.T, ctx context.Context, conn *pgx.Conn, svc *Service, ownerCtx context.Context) {
	t.Helper()
	secret, txID, csr, enrolled := enrollDevice(t, ctx, svc, ownerCtx, p256Key(t))
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := svc.RenewIdentity(withDevicePrincipal(ctx, principal), connect.NewRequest(&devicev1.RenewIdentityRequest{
		CsrPem: mustCSR(t, p256Key(t), &x509.CertificateRequest{}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	renewedLeaf := parseCertPEM(t, renewed.Msg.GetCertificatePem())
	renewedPrincipal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), renewedLeaf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.RenewIdentity(withDevicePrincipal(ctx, renewedPrincipal), connect.NewRequest(&devicev1.RenewIdentityRequest{
		CsrPem: mustCSR(t, p256Key(t), &x509.CertificateRequest{}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: txID, CsrPem: csr,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied || rpcReason(err) != "certificate_rejected" {
		t.Fatalf("retired issuance replay = %v, reason %q", err, rpcReason(err))
	}
	if got := activeCertificatePEM(t, ctx, conn, uuid.MustParse(enrolled.Msg.GetDeviceId())); !bytes.Equal(got, second.Msg.GetCertificatePem()) {
		t.Fatal("rejected enrollment replay changed the active certificate")
	}
}

func assertRevokedDeviceEnrollmentReplayRejected(t *testing.T, ctx context.Context, svc *Service, ownerCtx context.Context) {
	t.Helper()
	secret, txID, csr, enrolled := enrollDevice(t, ctx, svc, ownerCtx, p256Key(t))
	if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(&adminv1.RevokeDeviceRequest{
		RequestId: uuid.NewString(), DeviceId: enrolled.Msg.GetDeviceId(), Reason: "stolen",
	})); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: secret, TransactionId: txID, CsrPem: csr,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied || rpcReason(err) != "device_revoked" {
		t.Fatalf("revoked device replay = %v, reason %q", err, rpcReason(err))
	}
}

func enrollDevice(t *testing.T, ctx context.Context, svc *Service, ownerCtx context.Context, key crypto.Signer) (string, string, []byte, *connect.Response[enrollmentv1.EnrollResponse]) {
	t.Helper()
	created, err := svc.CreateEnrollmentGrant(ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{
		RequestId: uuid.NewString(), LifetimeSeconds: 120, Reason: "enrollment replay",
	}))
	if err != nil {
		t.Fatal(err)
	}
	csr := mustCSR(t, key, &x509.CertificateRequest{})
	txID := uuid.NewString()
	enrolled, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: created.Msg.GetSecret(), TransactionId: txID, CsrPem: csr,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return created.Msg.GetSecret(), txID, csr, enrolled
}

func rpcReason(err error) string {
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr.Message()
	}
	return ""
}
