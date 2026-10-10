//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
)

// Historical evidence is authenticated at its original acceptance times. Current
// revocations gate new effects, never rewrite the past or authorize replay.
func (s *Service) verifyDeviceActionRecord(ctx context.Context, loaded *bound, r *agentv1.DeviceActionRecord) error {
	if s.admit(r) != nil || r.GetInstallationId() != loaded.state.GetInstallationId() || !deviceActionTarget(loaded, r.GetIntent()) || !bytes.Equal(digestBytes(r.GetIntentEnvelope()), r.GetIntentSha256()) || !proto.Equal(r.GetIntent().GetSpec(), r.GetNativePlan().GetSpec()) || !r.GetNativePlan().GetBefore().GetSupported() || r.GetNativePlan().GetActionId() != r.GetIntent().GetActionId() {
		return errRecoveryHold
	}
	accepted := r.GetAcceptedAt().AsTime()
	delegation, err := loaded.execution.verifier.VerifyDelegation(ctx, r.GetAcceptedRoot(), r.GetAcceptedDelegationEnvelope(), 0, 0, accepted)
	if err != nil {
		return historicalServiceError(ctx)
	}
	intent, err := loaded.execution.verifier.VerifyDeviceActionIntent(ctx, r.GetAcceptedRoot(), delegation, r.GetIntentEnvelope(), accepted)
	if err != nil || !proto.Equal(intent, r.GetIntent()) {
		return historicalServiceError(ctx)
	}
	if err := s.verifyDeviceActionChallenge(ctx, loaded, r); err != nil {
		return err
	}
	if len(r.GetStartGrantEnvelope()) != 0 {
		if !bytes.Equal(digestBytes(r.GetStartGrantEnvelope()), r.GetStartGrantSha256()) || r.GetStartedAt() == nil || !proto.Equal(r.GetGrantAcceptedAt(), r.GetStartedAt()) {
			return errRecoveryHold
		}
		if _, err := loaded.execution.verifier.VerifyDeviceActionStart(ctx, r.GetAcceptedRoot(), delegation, r.GetStartGrantEnvelope(), intent, r.GetChallenge(), r.GetStartedAt().AsTime()); err != nil {
			return historicalServiceError(ctx)
		}
	}
	if err := s.verifyRecoveryBootHistory(ctx, loaded, r, delegation); err != nil {
		return err
	}
	if len(r.GetEscrowReceiptEnvelope()) != 0 {
		if r.GetReceiptRoot() == nil || r.GetEscrowConfirmedAt() == nil {
			return errRecoveryHold
		}
		receiptAt := r.GetEscrowConfirmedAt().AsTime()
		receiptDelegation, err := loaded.execution.verifier.VerifyDelegation(ctx, r.GetReceiptRoot(), r.GetReceiptDelegationEnvelope(), 0, 0, receiptAt)
		if err != nil {
			return historicalServiceError(ctx)
		}
		if _, err := loaded.execution.verifier.VerifyDeviceActionEscrowReceipt(ctx, r.GetReceiptRoot(), receiptDelegation, r.GetEscrowReceiptEnvelope(), r, receiptAt); err != nil {
			return historicalServiceError(ctx)
		}
	}
	return nil
}

func (s *Service) verifyDeviceActionChallenge(ctx context.Context, loaded *bound, r *agentv1.DeviceActionRecord) error {
	c, i := r.GetChallenge(), r.GetIntent()
	planDigest, err := digestMessage(r.GetNativePlan())
	if err != nil || c == nil || c.GetDeploymentId() != i.GetDeploymentId() || c.GetDeviceId() != i.GetDeviceId() || c.GetEnrollmentGeneration() != i.GetEnrollmentGeneration() || c.GetActionId() != i.GetActionId() || c.GetActionSequence() != i.GetActionSequence() || c.GetRecoveryEpoch() != i.GetRecoveryEpoch() || !bytes.Equal(c.GetIntentSha256(), r.GetIntentSha256()) || !bytes.Equal(c.GetSpecSha256(), i.GetSpecSha256()) || !bytes.Equal(c.GetNativePlanSha256(), planDigest) || !proto.Equal(c.GetNativePlan(), r.GetNativePlan()) || !proto.Equal(c.GetIssuedAt(), r.GetAcceptedAt()) || c.GetExpiresAt().AsTime().After(i.GetExpiresAt().AsTime()) {
		return errRecoveryHold
	}
	if _, err := canonicalUUID(c.GetBootId()); err != nil {
		return errRecoveryHold
	}
	if _, err := canonicalUUID(c.GetExecutorIncarnation()); err != nil {
		return errRecoveryHold
	}
	if r.GetChallengeBoottimeNs() < uint64(c.GetExpiresAt().AsTime().Sub(c.GetIssuedAt().AsTime())) {
		return errRecoveryHold
	}
	block, rest := pem.Decode(r.GetChallengeCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errRecoveryHold
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errRecoveryHold
	}
	public, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errRecoveryHold
	}
	deployment, device, generation, err := enrollmentIDs(i.GetDeploymentId(), i.GetDeviceId(), i.GetEnrollmentGeneration())
	if err != nil {
		return errRecoveryHold
	}
	if _, err := pki.VerifyDeviceCertificatePEM(r.GetChallengeCertificatePem(), public, loaded.bootstrap.DeviceCA, deployment, device, generation, c.GetIssuedAt().AsTime()); err != nil {
		return errRecoveryHold
	}
	verified := new(agentv1.DeviceActionChallenge)
	if err := s.authority.Verify(ctx, r.GetChallengeProof(), verified, 1, public); err != nil || !proto.Equal(verified, c) {
		return historicalServiceError(ctx)
	}
	if len(r.GetHandoffProof()) != 0 {
		_, err := s.verifyRecoveryHandoff(ctx, r, public)
		return err
	}
	return nil
}

func (s *Service) loadDeviceAction(ctx context.Context, loaded *bound, actionID string) (*agentv1.DeviceActionRecord, int64, error) {
	record, revision, err := s.store.LoadDeviceAction(ctx, actionID)
	if err != nil {
		return nil, 0, s.serviceStoreError(err)
	}
	if record.GetIntent().GetActionId() != actionID {
		s.noteTrustDamage()
		return nil, 0, errRecoveryHold
	}
	if err := s.verifyDeviceActionRecord(ctx, loaded, record); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return nil, 0, err
	}
	return record, revision, nil
}

func (s *Service) updateDeviceAction(ctx context.Context, loaded *bound, revision int64, next *agentv1.DeviceActionRecord) error {
	if err := s.verifyDeviceActionRecord(ctx, loaded, next); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errInternal
	}
	_, err := s.store.UpdateDeviceAction(ctx, revision, loaded.revision, loaded.execution.revision, next)
	return s.serviceStoreError(err)
}

// AttestDeviceAction signs only protected historical facts with current device
// identity/session and the caller's fresh nonce. The relay cannot invent status.
func (s *Service) AttestDeviceAction(ctx context.Context, req *connect.Request[agentv1.AttestDeviceActionRequest]) (*connect.Response[agentv1.AttestDeviceActionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	if s.liveRoot != nil {
		return s.attestLiveRoot(ctx, req.Msg)
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	if err := s.serviceIdentitySession(loaded); err != nil {
		return nil, mapError(err)
	}
	record, revision, err := s.loadDeviceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if revision <= 0 {
		s.noteTrustDamage()
		return nil, mapError(errRecoveryHold)
	}
	now := s.now()
	if !certUsable(loaded.cert, now) {
		return nil, mapError(errIdentityExpired)
	}
	expires := now.Add(30 * time.Second)
	if loaded.cert.NotAfter.Before(expires) {
		expires = loaded.cert.NotAfter
	}
	attestation := &agentv1.DeviceActionAttestation{DeploymentId: loaded.bootstrap.Root.GetDeploymentId(), DeviceId: loaded.state.GetDeviceId(), EnrollmentGeneration: loaded.state.GetEnrollmentGeneration(), SessionEpoch: loaded.state.GetSessionEpoch(), ActionRevision: uint64(revision), Nonce: bytes.Clone(req.Msg.GetNonce()), IssuedAt: protoTimestamp(now), ExpiresAt: protoTimestamp(expires), Status: deviceActionStatus(record)}
	envelope, err := s.authority.Sign(ctx, attestation, loaded.identityKey)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.AttestDeviceActionResponse{AttestationEnvelope: envelope, CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: loaded.cert.Raw})}), nil
}
