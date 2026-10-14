// SPDX-License-Identifier: Apache-2.0

//go:build integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	"lindm/internal/identity"
	"lindm/internal/pki"
	"lindm/internal/testdb"
)

func TestRenewalProofAndLostIssuanceRetrieval(t *testing.T) {
	parallelDeviceIntegration(t)
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	now := time.Now().UTC().Truncate(time.Second)
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	svc.Clock = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	ownerCtx := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	key, nextKey := ed25519Key(t), ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, key)
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	deviceCtx := core.WithDevicePrincipal(ctx, principal)
	acquireTestSession(t, ctx, svc, principal, key, 0)
	csr := mustCSR(t, nextKey, &x509.CertificateRequest{})
	request := signedRenewalRequest(t, svc, principal, key, 1, csr)
	originalClaim := new(agentv1.RenewalIntent)
	if err := svc.Authority.Verify(ctx, request.AuthorityProof, originalClaim, 1, principal.PublicKey); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		change func(*agentv1.RenewalIntent)
		code   connect.Code
	}{
		{"other deployment", func(c *agentv1.RenewalIntent) { c.DeploymentId = uuid.NewString() }, connect.CodePermissionDenied},
		{"other device", func(c *agentv1.RenewalIntent) { c.DeviceId = uuid.NewString() }, connect.CodePermissionDenied},
		{"other generation", func(c *agentv1.RenewalIntent) { c.EnrollmentGeneration = uuid.NewString() }, connect.CodePermissionDenied},
		{"other certificate", func(c *agentv1.RenewalIntent) { c.PresentedCertificateSha256 = make([]byte, sha256.Size) }, connect.CodePermissionDenied},
		{"unacquired epoch", func(c *agentv1.RenewalIntent) { c.SessionEpoch = 2 }, connect.CodeFailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim := proto.CloneOf(originalClaim)
			tc.change(claim)
			proof, err := svc.Authority.Sign(ctx, claim, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: csr, AuthorityProof: proof})); connect.CodeOf(err) != tc.code {
				t.Fatalf("authority substitution: %v", err)
			}
		})
	}
	wrongSigner := signedRenewalRequest(t, svc, principal, ed25519Key(t), 1, csr)
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(wrongSigner)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unprotected signing key: %v", err)
	}
	swapped := proto.CloneOf(request)
	swapped.CsrPem = mustCSR(t, ed25519Key(t), &x509.CertificateRequest{})
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(swapped)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("transport-selected CSR: %v", err)
	}
	var certificates int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id=$1`, principal.DeviceID).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if certificates != 1 {
		t.Fatalf("rejected proofs minted %d certificates", certificates)
	}

	renewed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(renewed.Msg, replayed.Msg) {
		t.Fatalf("renewal replay changed original issuance: %v", err)
	}
	changedClaim := proto.CloneOf(originalClaim)
	changedDigest := sha256.Sum256(swapped.CsrPem)
	changedClaim.CsrSha256 = changedDigest[:]
	changedProof, err := svc.Authority.Sign(ctx, changedClaim, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(&devicev1.RenewIdentityRequest{CsrPem: swapped.CsrPem, AuthorityProof: changedProof})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed issuance-request reuse: %v", err)
	}

	// The old identity can no longer authenticate, but the protected staged key
	// must still retrieve exactly its already-issued certificate over HTTPS.
	now = now.Add(core.RenewalOverlap + time.Second)
	clock.Store(now.UnixNano())
	if _, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf); err == nil {
		t.Fatal("old identity authenticated beyond overlap")
	}
	if _, err := svc.RenewIdentity(deviceCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expired overlap minted/replayed authority: %v", err)
	}
	path, handler := svc.EnrollmentHandler()
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	client := enrollmentv1connect.NewEnrollmentServiceClient(server.Client(), server.URL)
	claim := &agentv1.IssuanceRetrieval{DeploymentId: svc.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), IssuanceRequestId: originalClaim.IssuanceRequestId}
	proof, err := svc.Authority.Sign(ctx, claim, nextKey)
	if err != nil {
		t.Fatal(err)
	}
	retrieve := &enrollmentv1.RetrieveIssuanceRequest{AuthorityProof: proof}
	for _, wrong := range []bool{false, true} {
		candidate := proto.CloneOf(claim)
		candidateKey := nextKey
		if wrong {
			candidateKey = ed25519Key(t)
		} else {
			candidate.IssuanceRequestId = uuid.NewString()
		}
		badProof, err := svc.Authority.Sign(ctx, candidate, candidateKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.RetrieveIssuance(ctx, connect.NewRequest(&enrollmentv1.RetrieveIssuanceRequest{AuthorityProof: badProof})); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("unknown issuance/wrong protected key was distinguishable or accepted: %v", err)
		}
	}
	recovered, err := client.RetrieveIssuance(ctx, connect.NewRequest(retrieve))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Msg.CertificatePem, renewed.Msg.CertificatePem) || !proto.Equal(recovered.Msg.ExpiresAt, renewed.Msg.ExpiresAt) {
		t.Fatal("retrieval substituted or extended the original issuance")
	}
	public := ed25519.PublicKey(nextKey[ed25519.SeedSize:])
	if _, err := pki.VerifyDeviceCertificatePEM(recovered.Msg.CertificatePem, public, ca, svc.DeploymentID, principal.DeviceID, principal.GenerationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.VerifyDeviceCertificatePEM(recovered.Msg.CertificatePem, principal.PublicKey, ca, svc.DeploymentID, principal.DeviceID, principal.GenerationID, now); err == nil {
		t.Fatal("executor certificate import accepted another protected key")
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id=$1`, principal.DeviceID).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if certificates != 2 {
		t.Fatalf("retrieval minted additional certificates: %d", certificates)
	}

	validNow := now
	now = recovered.Msg.ExpiresAt.AsTime()
	clock.Store(now.UnixNano())
	if _, err := client.RetrieveIssuance(ctx, connect.NewRequest(retrieve)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expired issuance recovered: %v", err)
	}
	now = validNow
	clock.Store(now.UnixNano())
	newPrincipal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, recovered.Msg.CertificatePem))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireSession(core.WithDevicePrincipal(ctx, newPrincipal), connect.NewRequest(signedSessionRequest(t, svc, newPrincipal, nextKey, 0))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("conflicting successor did not hold generation: %v", err)
	}
	if _, err := client.RetrieveIssuance(ctx, connect.NewRequest(retrieve)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("held issuance recovered: %v", err)
	}
	if _, err := svc.RevokeDevice(ownerCtx, approvedRevocation(t, svc, ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: principal.DeviceID.String(), Reason: "retire held key"})); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RetrieveIssuance(ctx, connect.NewRequest(retrieve)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("revoked issuance recovered: %v", err)
	}
}
