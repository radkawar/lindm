//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
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

	key := ed25519Key(t)
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
		GrantSecret: secret, TransactionId: txID, CsrPem: mustCSR(t, ed25519Key(t), &x509.CertificateRequest{}),
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different key: %v", err)
	}

	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatalf("issued cert rejected before renewal: %v", err)
	}
	acquireTestSession(t, ctx, svc, principal, key, 0)
	assertRenewalFence(t, ctx, conn, svc, principal, key)
	assertConcurrentRenewal(t, ctx, conn, svc, ownerCtx)
	deviceCtx := withDevicePrincipal(ctx, principal)
	generation := enrolled.Msg.GetEnrollmentGeneration()
	deviceID := enrolled.Msg.GetDeviceId()
	alpha := hostObservation(generation, 1, "alpha")
	if _, err := svc.ReportHostObservation(deviceCtx, connect.NewRequest(alpha)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReportHostObservation(deviceCtx, connect.NewRequest(alpha)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReportHostObservation(deviceCtx, connect.NewRequest(hostObservation(generation, 1, "beta"))); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("changed sequence content: %v", err)
	}
	if got := deviceHostname(t, ctx, conn, deviceID); got != "alpha" {
		t.Fatalf("conflict overwrote hostname %q", got)
	}
	svc.clock = func() time.Time { return time.Now().Add(snapshotAttemptInterval) }
	if _, err := svc.ReportHostObservation(deviceCtx, connect.NewRequest(hostObservation(generation, 2, "beta"))); err != nil {
		t.Fatal(err)
	}
	old, err := svc.ReportHostObservation(deviceCtx, connect.NewRequest(hostObservation(generation, 1, "alpha")))
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

func hostObservation(generation string, seq uint64, host string) *devicev1.ReportHostObservationRequest {
	when := time.Now().UTC()
	return &devicev1.ReportHostObservationRequest{
		EnrollmentGeneration: generation,
		SessionEpoch:         1,
		Sequence:             seq,
		Observation: &inventoryv1.HostObservation{
			StartedAt: timestamppb.New(when), FinishedAt: timestamppb.New(when),
			BootId:         observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, uuid.NewString()),
			Hostname:       observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, host),
			OsId:           observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "debian"),
			OsVersion:      observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "12"),
			Architecture:   observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "amd64"),
			KernelRelease:  observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, "6.8.0"),
			HardwareVendor: observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, ""),
			HardwareModel:  observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, ""),
			HardwareSerial: observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, ""),
		},
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

func assertRenewalFence(t *testing.T, ctx context.Context, conn *pgx.Conn, svc *Service, principal devicePrincipal, key ed25519.PrivateKey) {
	t.Helper()
	csrB := mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})
	deviceCtx := withDevicePrincipal(ctx, principal)
	request := signedRenewalRequest(t, svc, principal, key, 1, csrB)
	renewed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renewed.Msg.GetCertificatePem(), replay.Msg.GetCertificatePem()) {
		t.Fatal("overlapping certificate did not replay the issued renewal")
	}
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(signedRenewalRequest(t, svc, principal, key, 1, mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})))); connect.CodeOf(err) != connect.CodePermissionDenied {
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
	key := ed25519Key(t)
	enrolled, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: created.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: mustCSR(t, key, &x509.CertificateRequest{}),
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
	acquireTestSession(t, ctx, svc, principal, key, 0)
	csrs := [][]byte{
		mustCSR(t, ed25519Key(t), &x509.CertificateRequest{}),
		mustCSR(t, ed25519Key(t), &x509.CertificateRequest{}),
	}
	requests := make([]*devicev1.RenewIdentityRequest, len(csrs))
	for i, csr := range csrs {
		requests[i] = signedRenewalRequest(t, svc, principal, key, 1, csr)
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
			resp, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(requests[i]))
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
	replay, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(requests[winner]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replay.Msg.GetCertificatePem(), results[winner].pem) {
		t.Fatal("lost concurrent renewal response was not replayed")
	}
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(signedRenewalRequest(t, svc, principal, key, 1, mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("retired certificate minted another key after concurrent renewal: %v", err)
	}
}

func TestRenewIdentityRechecksExpiryAfterDeviceLock(t *testing.T) {
	for _, status := range []string{"active", "overlapping"} {
		for _, boundary := range []struct {
			name   string
			offset time.Duration
		}{
			{name: "before expiry", offset: -time.Microsecond},
			{name: "at expiry"},
			{name: "after expiry", offset: time.Microsecond},
		} {
			t.Run(status+"/"+boundary.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				pool, conn := testdb.Open(t)
				start := time.Now().UTC().Truncate(time.Second)
				ca, signer := testCA(t, start.Add(90*24*time.Hour))
				svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: signer})
				if err != nil {
					t.Fatal(err)
				}
				var clock atomic.Int64
				clock.Store(start.UnixMicro())
				svc.clock = func() time.Time { return time.UnixMicro(clock.Load()) }
				owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
				ownerCtx := identity.WithPrincipal(ctx, owner)
				key := ed25519Key(t)
				_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
				deviceID := uuid.MustParse(enrolled.Msg.GetDeviceId())
				leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
				renewAt := start.Add(time.Minute)
				if status == "overlapping" {
					// Exercise replay with overlap capped by certificate expiry,
					// rather than the usual overlap deadline.
					renewAt = leaf.NotAfter.Add(-time.Minute)
				}
				clock.Store(renewAt.UnixMicro())
				principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
				if err != nil {
					t.Fatal(err)
				}
				acquireTestSession(t, ctx, svc, principal, key, 0)
				nextKey := ed25519Key(t)
				csr := mustCSR(t, nextKey, &x509.CertificateRequest{})
				request := signedRenewalRequest(t, svc, principal, key, 1, csr)
				renewed, err := svc.RenewIdentity(withDevicePrincipal(ctx, principal), connect.NewRequest(request))
				if err != nil {
					t.Fatal(err)
				}
				if status == "active" {
					leaf = parseCertPEM(t, renewed.Msg.GetCertificatePem())
					csr = mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})
					principal, err = svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
					if err != nil {
						t.Fatal(err)
					}
					request = signedRenewalRequest(t, svc, principal, nextKey, 1, csr)
				}
				// Keep an older overlapping row present so a rejected active
				// renewal must not retire it, even though its window has elapsed.
				clock.Store(leaf.NotAfter.Add(-2 * time.Microsecond).UnixMicro())
				snapshot := func() (string, string) {
					t.Helper()
					var certificates, audits string
					if err := conn.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id)::text
						FROM device_certificates c WHERE device_id = $1`, deviceID).Scan(&certificates); err != nil {
						t.Fatal(err)
					}
					if err := conn.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id)::text
						FROM audit_events a WHERE resource_id = $1`, deviceID.String()).Scan(&audits); err != nil {
						t.Fatal(err)
					}
					return certificates, audits
				}
				beforeCertificates, beforeAudits := snapshot()
				lock, err := conn.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if err := lock.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
						t.Error(err)
					}
				})
				var lockedID uuid.UUID
				if err := lock.QueryRow(ctx, `SELECT id FROM devices WHERE id = $1 FOR UPDATE`, deviceID).Scan(&lockedID); err != nil {
					t.Fatal(err)
				}
				type result struct {
					response *connect.Response[devicev1.RenewIdentityResponse]
					err      error
				}
				results := make(chan result, 1)
				go func() {
					r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
					principal, err := svc.authenticateDeviceRequest(r, leaf)
					if err != nil {
						results <- result{err: err}
						return
					}
					response, err := svc.RenewIdentity(withDevicePrincipal(ctx, principal), connect.NewRequest(request))
					results <- result{response: response, err: err}
				}()
				// Advance the service clock only once PostgreSQL confirms the
				// authenticated renewal is waiting on this device row lock.
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					var waiting bool
					err := pool.QueryRow(ctx, `SELECT EXISTS (
						SELECT 1 FROM pg_stat_activity
						WHERE $1::integer = ANY(pg_blocking_pids(pid))
					)`, int32(conn.PgConn().PID())).Scan(&waiting)
					if err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case got := <-results:
						t.Fatalf("renewal completed before the device lock was released: %v", got.err)
					case <-ticker.C:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				clock.Store(leaf.NotAfter.Add(boundary.offset).UnixMicro())
				if err := lock.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				var got result
				select {
				case got = <-results:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if boundary.offset >= 0 {
					if got.response != nil || connect.CodeOf(got.err) != connect.CodePermissionDenied || rpcReason(got.err) != "certificate_rejected" {
						t.Fatalf("expired %s renewal: response=%v error=%v", status, got.response != nil, got.err)
					}
				} else {
					if got.err != nil {
						t.Fatalf("valid %s renewal: %v", status, got.err)
					}
					if got.response == nil {
						t.Fatal("valid renewal returned no response")
					}
					if status == "overlapping" && (!bytes.Equal(got.response.Msg.GetCertificatePem(), renewed.Msg.GetCertificatePem()) ||
						!got.response.Msg.GetExpiresAt().AsTime().Equal(renewed.Msg.GetExpiresAt().AsTime())) {
						t.Fatal("valid replay did not return the already-issued certificate")
					}
				}
				afterCertificates, afterAudits := snapshot()
				if boundary.offset >= 0 || status == "overlapping" {
					if afterCertificates != beforeCertificates {
						t.Fatal("rejected renewal or replay issued, retired, or modified a certificate")
					}
					if afterAudits != beforeAudits {
						t.Fatal("rejected renewal or replay modified audit events")
					}
					return
				}
				if bytes.Equal(got.response.Msg.GetCertificatePem(), renewed.Msg.GetCertificatePem()) ||
					!bytes.Equal(activeCertificatePEM(t, ctx, conn, deviceID), got.response.Msg.GetCertificatePem()) {
					t.Fatal("valid active renewal did not issue and persist a new certificate")
				}
				var total, active, overlapping, revoked, audits int
				if err := conn.QueryRow(ctx, `SELECT count(*),
					count(*) FILTER (WHERE status = 'active'),
					count(*) FILTER (WHERE status = 'overlapping'),
					count(*) FILTER (WHERE status = 'revoked')
					FROM device_certificates WHERE device_id = $1`, deviceID).Scan(&total, &active, &overlapping, &revoked); err != nil {
					t.Fatal(err)
				}
				if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events
					WHERE resource_id = $1 AND action = $2`, deviceID.String(), actionDeviceRenew).Scan(&audits); err != nil {
					t.Fatal(err)
				}
				if total != 3 || active != 1 || overlapping != 1 || revoked != 1 || audits != 2 {
					t.Fatalf("valid renewal: certificates=%d active=%d overlapping=%d revoked=%d renewal audits=%d", total, active, overlapping, revoked, audits)
				}
			})
		}
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
	key := ed25519Key(t)
	secret, txID, csr, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, ctx, svc, principal, key, 0)
	renewKey := key
	if !sameKey {
		renewKey = ed25519Key(t)
	}
	renewed, err := svc.RenewIdentity(withDevicePrincipal(ctx, principal), connect.NewRequest(signedRenewalRequest(t, svc, principal, key, 1, mustCSR(t, renewKey, &x509.CertificateRequest{}))))
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
	key := ed25519Key(t)
	secret, txID, csr, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, ctx, svc, principal, key, 0)
	nextKey := ed25519Key(t)
	renewed, err := svc.RenewIdentity(withDevicePrincipal(ctx, principal), connect.NewRequest(signedRenewalRequest(t, svc, principal, key, 1, mustCSR(t, nextKey, &x509.CertificateRequest{}))))
	if err != nil {
		t.Fatal(err)
	}
	renewedLeaf := parseCertPEM(t, renewed.Msg.GetCertificatePem())
	renewedPrincipal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), renewedLeaf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.RenewIdentity(withDevicePrincipal(ctx, renewedPrincipal), connect.NewRequest(signedRenewalRequest(t, svc, renewedPrincipal, nextKey, 1, mustCSR(t, ed25519Key(t), &x509.CertificateRequest{}))))
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
	secret, txID, csr, enrolled := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
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
