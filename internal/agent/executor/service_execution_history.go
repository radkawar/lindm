//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/pki"
)

// verifyServiceRecord authenticates evidence at its original acceptance times.
// Current revocation is deliberately not consulted here: it gates new effects,
// not the integrity of a retained receipt. The root was authenticated when the
// protected record was accepted; its retained delegation is reauthenticated.
func (s *Service) verifyServiceRecord(ctx context.Context, loaded *bound, record *agentv1.ServiceExecutionRecord) error {
	if s.admit(record) != nil || record.GetInstallationId() != loaded.state.GetInstallationId() || !serviceTarget(loaded, record.GetIntent()) {
		return errRecoveryHold
	}
	if !bytes.Equal(digestBytes(record.GetIntentEnvelope()), record.GetIntentSha256()) || serviceprovider.ValidatePlan(record.GetNativePlan()) != nil {
		return errRecoveryHold
	}
	accepted := record.GetAcceptedAt().AsTime()
	delegation, err := loaded.execution.verifier.VerifyDelegation(ctx, record.GetAcceptedRoot(), record.GetAcceptedDelegationEnvelope(), 0, 0, accepted)
	if err != nil {
		return historicalServiceError(ctx)
	}
	intent, err := loaded.execution.verifier.VerifyServiceIntent(ctx, record.GetAcceptedRoot(), delegation, record.GetIntentEnvelope(), accepted)
	if err != nil || !proto.Equal(intent, record.GetIntent()) || !proto.Equal(intent.GetDesired(), record.GetNativePlan().GetDesired()) {
		return historicalServiceError(ctx)
	}
	if record.GetVerification() != nil && serviceprovider.ValidateVerification(record.GetNativePlan(), record.GetVerification()) != nil {
		return errRecoveryHold
	}
	if serviceDrift(record.GetNativePlan()) {
		if err := s.verifyServiceChallenge(ctx, loaded, record); err != nil {
			return err
		}
	} else if record.GetChallenge() != nil || record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED || record.GetStartedAt() != nil || len(record.GetStartGrantEnvelope()) != 0 || !record.GetVerification().GetConverged() {
		return errRecoveryHold
	}
	if len(record.GetStartGrantEnvelope()) != 0 {
		grantAt := record.GetGrantAcceptedAt().AsTime()
		if !bytes.Equal(digestBytes(record.GetStartGrantEnvelope()), record.GetStartGrantSha256()) {
			return errRecoveryHold
		}
		if _, err := loaded.execution.verifier.VerifyServiceStart(ctx, record.GetAcceptedRoot(), delegation, record.GetStartGrantEnvelope(), intent, record.GetChallenge(), grantAt); err != nil {
			return historicalServiceError(ctx)
		}
	}
	if started := record.GetStartedAt(); started != nil {
		if len(record.GetStartGrantEnvelope()) == 0 {
			return errRecoveryHold
		}
		if _, err := loaded.execution.verifier.VerifyServiceStart(ctx, record.GetAcceptedRoot(), delegation, record.GetStartGrantEnvelope(), intent, record.GetChallenge(), started.AsTime()); err != nil {
			return historicalServiceError(ctx)
		}
	}
	if serviceDrift(record.GetNativePlan()) && record.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED && record.GetStartedAt() == nil {
		return errRecoveryHold
	}
	return nil
}

func (s *Service) verifyServiceChallenge(ctx context.Context, loaded *bound, record *agentv1.ServiceExecutionRecord) error {
	challenge, intent := record.GetChallenge(), record.GetIntent()
	planDigest, err := digestMessage(record.GetNativePlan())
	if err != nil || challenge == nil || challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), record.GetIntentSha256()) || !bytes.Equal(challenge.GetNativePlanSha256(), planDigest) || challenge.GetBootId() != record.GetNativePlan().GetBefore().GetBootId() || !proto.Equal(challenge.GetIssuedAt(), record.GetAcceptedAt()) || challenge.GetExpiresAt().AsTime().After(intent.GetExpiresAt().AsTime()) {
		return errRecoveryHold
	}
	if _, err := canonicalUUID(challenge.GetBootId()); err != nil {
		return errRecoveryHold
	}
	if _, err := canonicalUUID(challenge.GetExecutorIncarnation()); err != nil {
		return errRecoveryHold
	}
	if record.GetChallengeBoottimeNs() < uint64(challenge.GetExpiresAt().AsTime().Sub(challenge.GetIssuedAt().AsTime())) {
		return errRecoveryHold
	}
	block, rest := pem.Decode(record.GetChallengeCertificatePem())
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
	deployment, device, generation, err := enrollmentIDs(intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration())
	if err != nil {
		return errRecoveryHold
	}
	if _, err := pki.VerifyDeviceCertificatePEM(record.GetChallengeCertificatePem(), public, loaded.bootstrap.DeviceCA, deployment, device, generation, challenge.GetIssuedAt().AsTime()); err != nil {
		return errRecoveryHold
	}
	verified := new(agentv1.ServiceExecutionChallenge)
	if err := s.authority.Verify(ctx, record.GetChallengeProof(), verified, 1, public); err != nil || !proto.Equal(verified, challenge) {
		return historicalServiceError(ctx)
	}
	return nil
}

func historicalServiceError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errRecoveryHold
}

// All helpers below are called under Service.mu (or before New publishes it).
func (s *Service) loadServiceAction(ctx context.Context, loaded *bound, actionID string) (*agentv1.ServiceExecutionRecord, int64, error) {
	record, revision, err := s.store.LoadServiceAction(ctx, actionID)
	if err != nil {
		return nil, 0, s.serviceStoreError(err)
	}
	if record.GetIntent().GetActionId() != actionID {
		s.noteTrustDamage()
		return nil, 0, errRecoveryHold
	}
	if err := s.verifyServiceRecord(ctx, loaded, record); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return nil, 0, err
	}
	return record, revision, nil
}

func (s *Service) updateServiceAction(ctx context.Context, loaded *bound, revision int64, next *agentv1.ServiceExecutionRecord) error {
	if err := s.verifyServiceRecord(ctx, loaded, next); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errInternal
	}
	_, err := s.store.UpdateServiceAction(ctx, revision, loaded.revision, loaded.execution.revision, next)
	return s.serviceStoreError(err)
}

func (s *Service) serviceStoreError(err error) error {
	if errors.Is(err, journal.ErrRecoveryHold) {
		s.noteTrustDamage()
		return errRecoveryHold
	}
	return err
}
