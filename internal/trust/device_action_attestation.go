package trust

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// DeviceActionAttestationBinding is independently trusted consumer context.
// Nonce comes from that consumer and must be consumed transactionally.
type DeviceActionAttestationBinding struct {
	DeploymentID, DeviceID, EnrollmentGeneration uuid.UUID
	SessionEpoch                                 uint64
	ActionID                                     uuid.UUID
	IntentSHA256                                 [32]byte
	Nonce                                        [32]byte
}

// VerifyDeviceActionAttestation authenticates protected history, never fresh
// native observation or start authority. Consumers still enforce revocation,
// current session and one-use result nonce under their own transaction fences.
func (a *Authority) VerifyDeviceActionAttestation(ctx context.Context, envelope, certificatePEM []byte, deviceCA *x509.Certificate, expected *DeviceActionAttestationBinding, now time.Time, clockSkew time.Duration) (*agentv1.DeviceActionAttestation, error) {
	if clockSkew < 0 {
		return nil, errors.New("invalid device clock tolerance")
	}
	if expected == nil || expected.DeploymentID == uuid.Nil || expected.DeviceID == uuid.Nil || expected.EnrollmentGeneration == uuid.Nil || expected.ActionID == uuid.Nil || expected.SessionEpoch == 0 {
		return nil, errors.New("invalid device action attestation binding")
	}
	if len(envelope) == 0 || len(envelope) > 65536 {
		return nil, errors.New("invalid device action attestation size")
	}
	cert, public, err := verifyDeviceProofCertificate(certificatePEM, deviceCA, expected.DeploymentID, expected.DeviceID, expected.EnrollmentGeneration, now)
	if err != nil {
		return nil, err
	}
	attestation := new(agentv1.DeviceActionAttestation)
	if err := a.Verify(ctx, envelope, attestation, 1, public); err != nil {
		return nil, err
	}
	status := attestation.GetStatus()
	if attestation.GetDeploymentId() != expected.DeploymentID.String() || attestation.GetDeviceId() != expected.DeviceID.String() || attestation.GetEnrollmentGeneration() != expected.EnrollmentGeneration.String() || attestation.GetSessionEpoch() != expected.SessionEpoch || status.GetActionId() != expected.ActionID.String() || !bytes.Equal(status.GetIntentSha256(), expected.IntentSHA256[:]) || !bytes.Equal(attestation.GetNonce(), expected.Nonce[:]) {
		return nil, errors.New("device action attestation binding rejected")
	}
	issued, expires := attestation.GetIssuedAt().AsTime(), attestation.GetExpiresAt().AsTime()
	if issued.After(now.Add(clockSkew)) || !now.Add(-clockSkew).Before(expires) {
		return nil, ErrDeviceClockSkew
	}
	if expires.After(cert.NotAfter) {
		return nil, errors.New("device action attestation validity rejected")
	}
	return attestation, nil
}
