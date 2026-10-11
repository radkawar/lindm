//go:build integration

package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/internal/device/secrets"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/secretseal"
	"lindm/internal/testdb"
)

func recipientKey(t *testing.T) []byte {
	t.Helper()
	private, err := secretseal.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := secretseal.PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func encryptionKeyClaim(t *testing.T, svc *Service, principal core.DevicePrincipal, recipient []byte) *agentv1.DeviceEncryptionKeyAttestation {
	t.Helper()
	identity, err := core.PublicKeyFingerprint(principal.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.DeviceEncryptionKeyAttestation{
		DeploymentId: svc.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(),
		IdentityPublicKeySha256: identity, KemId: secretseal.KEMID, KdfId: secretseal.KDFID, AeadId: secretseal.AEADID,
		PublicKey: recipient, CreatedAt: timestamppb.Now(),
	}
}

func registerKey(t *testing.T, svc *Service, principal core.DevicePrincipal, claim *agentv1.DeviceEncryptionKeyAttestation, signer ed25519.PrivateKey, epoch uint64) (*devicev1.RegisterEncryptionKeyResponse, error) {
	t.Helper()
	envelope, err := svc.Authority.Sign(t.Context(), claim, signer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := svc.RegisterEncryptionKey(core.WithDevicePrincipal(t.Context(), principal), connect.NewRequest(&devicev1.RegisterEncryptionKeyRequest{SessionEpoch: epoch, AttestationEnvelope: envelope}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func currentKey(t *testing.T, ctx context.Context, conn *pgx.Conn, generation uuid.UUID) ([]byte, error) {
	t.Helper()
	return secrets.CurrentDeviceEncryptionKey(ctx, devicedb.New(conn), generation)
}

func TestRegisterEncryptionKeyBindsPresentedIdentity(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, caKey := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, pool)})
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
	if _, err := currentKey(t, ctx, conn, principal.GenerationID); !errors.Is(err, secrets.ErrDeviceEncryptionKeyUnavailable) {
		t.Fatalf("unregistered generation has a delivery key: %v", err)
	}

	recipient := recipientKey(t)
	valid := encryptionKeyClaim(t, svc, principal, recipient)
	otherIdentity, err := core.PublicKeyFingerprint(ed25519Key(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceEncryptionKeyAttestation)
		signer ed25519.PrivateKey
		epoch  uint64
		code   connect.Code
	}{
		{"other signer", nil, ed25519Key(t), 1, connect.CodePermissionDenied},
		{"other deployment", func(c *agentv1.DeviceEncryptionKeyAttestation) { c.DeploymentId = uuid.NewString() }, key, 1, connect.CodePermissionDenied},
		{"other device", func(c *agentv1.DeviceEncryptionKeyAttestation) { c.DeviceId = uuid.NewString() }, key, 1, connect.CodePermissionDenied},
		{"other generation", func(c *agentv1.DeviceEncryptionKeyAttestation) { c.EnrollmentGeneration = uuid.NewString() }, key, 1, connect.CodePermissionDenied},
		{"spki mismatch", func(c *agentv1.DeviceEncryptionKeyAttestation) { c.IdentityPublicKeySha256 = otherIdentity }, key, 1, connect.CodePermissionDenied},
		{"unacquired epoch", nil, key, 2, connect.CodeFailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim := proto.CloneOf(valid)
			if tc.change != nil {
				tc.change(claim)
			}
			if _, err := registerKey(t, svc, principal, claim, tc.signer, tc.epoch); connect.CodeOf(err) != tc.code {
				t.Fatalf("registration = %v, want %v", err, tc.code)
			}
		})
	}
	var rows int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM device_encryption_keys`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("rejected attestations stored %d keys", rows)
	}

	registered, err := registerKey(t, svc, principal, valid, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(registered.GetPublicKeySha256(), secretseal.KeyID(recipient)) || !bytes.Equal(registered.GetCertificateSha256(), principal.Fingerprint) {
		t.Fatal("registration response does not bind the key and presented certificate")
	}
	// A fresh attestation of the same key (new created_at) is an exact replay.
	replay := proto.CloneOf(valid)
	replay.CreatedAt = timestamppb.New(time.Now().Add(time.Second))
	if again, err := registerKey(t, svc, principal, replay, key, 1); err != nil || !proto.Equal(again, registered) {
		t.Fatalf("replay was not idempotent: %v", err)
	}
	if _, err := registerKey(t, svc, principal, encryptionKeyClaim(t, svc, principal, recipientKey(t)), key, 1); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("second key for one identity: %v", err)
	}
	var audits int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'device_encryption_key.registered' AND resource_id = $1`, principal.GenerationID.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("registration audited %d times", audits)
	}
	if got, err := currentKey(t, ctx, conn, principal.GenerationID); err != nil || !bytes.Equal(got, recipient) {
		t.Fatalf("current delivery key = %x, %v", got, err)
	}

	// Renewal: the old certificate overlaps, so its key stays current until the
	// successor identity registers its own key under the same session.
	nextKey := ed25519Key(t)
	renewed, err := svc.RenewIdentity(core.WithDevicePrincipal(ctx, principal), connect.NewRequest(signedRenewalRequest(t, svc, principal, key, 1, mustCSR(t, nextKey, &x509.CertificateRequest{}))))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := currentKey(t, ctx, conn, principal.GenerationID); err != nil || !bytes.Equal(got, recipient) {
		t.Fatalf("overlapping certificate lost its delivery key: %x, %v", got, err)
	}
	next, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, renewed.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	// The successor key cannot reuse the predecessor identity's attestation.
	if _, err := registerKey(t, svc, next, encryptionKeyClaim(t, svc, principal, recipientKey(t)), key, 1); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("predecessor identity registered for successor certificate: %v", err)
	}
	if _, err := registerKey(t, svc, next, encryptionKeyClaim(t, svc, next, recipient), nextKey, 1); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("one recipient key registered under two identities: %v", err)
	}
	successor := recipientKey(t)
	if _, err := registerKey(t, svc, next, encryptionKeyClaim(t, svc, next, successor), nextKey, 1); err != nil {
		t.Fatal(err)
	}
	if got, err := currentKey(t, ctx, conn, principal.GenerationID); err != nil || !bytes.Equal(got, successor) {
		t.Fatalf("delivery key did not follow renewal: %x, %v", got, err)
	}

	if _, err := svc.RevokeDevice(ownerCtx, approvedRevocation(t, svc, ownerCtx, &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: principal.DeviceID.String(), Reason: "retire device key"})); err != nil {
		t.Fatal(err)
	}
	if _, err := currentKey(t, ctx, conn, principal.GenerationID); !errors.Is(err, secrets.ErrDeviceEncryptionKeyUnavailable) {
		t.Fatalf("revoked generation still receives deliveries: %v", err)
	}
	if _, err := registerKey(t, svc, next, encryptionKeyClaim(t, svc, next, successor), nextKey, 1); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked device registered a key: %v", err)
	}
}
