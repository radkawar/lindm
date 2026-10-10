package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
)

// MaxDeviceClockSkew bounds control-plane acceptance of device-signed wall
// timestamps. Server-held single-use nonces and leases still expire on server
// time; this tolerance never extends those independent freshness fences.
const MaxDeviceClockSkew = 2 * time.Minute

// ErrDeviceClockSkew means authenticated device timestamps lie outside the
// consumer's explicit clock tolerance.
var ErrDeviceClockSkew = errors.New("device_clock_skew")

// ResourceAttestationBinding is the consumer's independently trusted request
// context. Nonce must be chosen unpredictably by that consumer, not by the relay.
type ResourceAttestationBinding struct {
	DeploymentID, DeviceID, EnrollmentGeneration uuid.UUID
	SessionEpoch                                 uint64
	ActionID                                     uuid.UUID
	IntentSHA256                                 [32]byte
	Nonce                                        [32]byte
}

// VerifyResourceAttestation authenticates a short-lived snapshot of retained
// service execution evidence using the independently pinned device CA. A current
// same-identity certificate may attest history recorded under an older key.
//
// The result is not a fresh native observation, current compliance, or permission
// to execute. The consumer must separately enforce current device revocation,
// desired-head and authorization policy. Retained observation timestamps are not
// bounded by issuance: the device wall clock may have moved backwards.
// clockSkew must be explicitly selected by the consumer; zero remains strict.
func (a *Authority) VerifyResourceAttestation(ctx context.Context, envelope, certificatePEM []byte, deviceCA *x509.Certificate, expected *ResourceAttestationBinding, now time.Time, clockSkew time.Duration) (*agentv1.ResourceExecutionAttestation, error) {
	if clockSkew < 0 {
		return nil, errors.New("invalid device clock tolerance")
	}
	if expected == nil || expected.DeploymentID == uuid.Nil || expected.DeviceID == uuid.Nil || expected.EnrollmentGeneration == uuid.Nil || expected.ActionID == uuid.Nil || expected.SessionEpoch == 0 {
		return nil, errors.New("invalid service attestation binding")
	}
	if len(envelope) == 0 || len(envelope) > 262144 {
		return nil, errors.New("invalid service attestation size")
	}
	if len(certificatePEM) == 0 || len(certificatePEM) > 16384 || deviceCA == nil {
		return nil, errors.New("invalid service attestation certificate input")
	}
	cert, public, err := verifyDeviceProofCertificate(certificatePEM, deviceCA, expected.DeploymentID, expected.DeviceID, expected.EnrollmentGeneration, now)
	if err != nil {
		return nil, err
	}
	attestation := new(agentv1.ResourceExecutionAttestation)
	if err := a.Verify(ctx, envelope, attestation, 1, public); err != nil {
		return nil, err
	}
	status := attestation.GetStatus()
	if attestation.GetDeploymentId() != expected.DeploymentID.String() || attestation.GetDeviceId() != expected.DeviceID.String() || attestation.GetEnrollmentGeneration() != expected.EnrollmentGeneration.String() || attestation.GetSessionEpoch() != expected.SessionEpoch || status.GetActionId() != expected.ActionID.String() || !bytes.Equal(status.GetIntentSha256(), expected.IntentSHA256[:]) || !bytes.Equal(attestation.GetNonce(), expected.Nonce[:]) {
		return nil, errors.New("service attestation binding rejected")
	}
	issued, expires := attestation.GetIssuedAt().AsTime(), attestation.GetExpiresAt().AsTime()
	if issued.After(now.Add(clockSkew)) || !now.Add(-clockSkew).Before(expires) {
		return nil, ErrDeviceClockSkew
	}
	if expires.After(cert.NotAfter) {
		return nil, errors.New("service attestation validity rejected")
	}
	return attestation, nil
}

func verifyDeviceProofCertificate(certificatePEM []byte, deviceCA *x509.Certificate, deploymentID, deviceID, generation uuid.UUID, now time.Time) (*x509.Certificate, ed25519.PublicKey, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > 16384 || deviceCA == nil {
		return nil, nil, errors.New("invalid device proof certificate input")
	}
	encoded := bytes.TrimSpace(certificatePEM)
	if !bytes.HasPrefix(encoded, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(encoded, []byte("-----BEGIN ")) != 1 {
		return nil, nil, errors.New("expected one device proof certificate")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("expected one device proof certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errors.New("invalid device proof certificate")
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("device proof requires an Ed25519 certificate")
	}
	cert, err := pki.VerifyDeviceCertificatePEM(encoded, public, deviceCA, deploymentID, deviceID, generation, now)
	if err != nil {
		return nil, nil, err
	}
	return cert, public, nil
}
