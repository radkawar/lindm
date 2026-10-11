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
	"lindm/internal/pki"
	"lindm/internal/resource"
)

// verifyResourceRecord authenticates evidence at its original acceptance times.
// Current revocation is deliberately not consulted here: it gates new effects,
// not the integrity of a retained receipt. The root was authenticated when the
// protected record was accepted; its retained delegation is reauthenticated.
func (s *Service) verifyResourceRecord(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord) error {
	if s.admit(record) != nil || record.GetInstallationId() != loaded.state.GetInstallationId() || !resourceTarget(loaded, record.GetIntent()) {
		return errRecoveryHold
	}
	if !bytes.Equal(digestBytes(record.GetIntentEnvelope()), record.GetIntentSha256()) || !validateRetainedSecrets(record) {
		return errRecoveryHold
	}
	accepted := record.GetAcceptedAt().AsTime()
	delegation, err := loaded.execution.verifier.VerifyDelegation(ctx, record.GetAcceptedRoot(), record.GetAcceptedDelegationEnvelope(), 0, 0, accepted)
	if err != nil {
		return historicalResourceError(ctx)
	}
	intent, err := loaded.execution.verifier.VerifyResourceIntent(ctx, record.GetAcceptedRoot(), delegation, record.GetIntentEnvelope(), accepted)
	if err != nil || !proto.Equal(intent, record.GetIntent()) {
		return historicalResourceError(ctx)
	}
	if refusal := record.GetAdmissionRefusal(); refusal != nil {
		// The authenticated intent and schema bind this terminal rejection, not
		// a claim that the resource was observed or that its absence is success.
		if _, err := canonicalUUID(refusal.GetBootId()); err != nil {
			return errRecoveryHold
		}
		if _, err := canonicalUUID(refusal.GetExecutorIncarnation()); err != nil {
			return errRecoveryHold
		}
		return nil
	}
	if record.GetNativePlan() == nil {
		// Schema guards admit only authenticated, effect-free preparation here.
		if intent.GetPreparation() == nil || !accepted.Before(intent.GetPreparation().GetDeadline().AsTime()) {
			return errRecoveryHold
		}
		return nil
	}
	if validateResourcePlan(record.GetNativePlan()) != nil || !proto.Equal(intent.GetDesired(), resource.PlanDesired(record.GetNativePlan())) {
		return errRecoveryHold
	}
	if record.GetVerification() != nil && validateResourceVerification(record.GetNativePlan(), record.GetVerification()) != nil {
		return errRecoveryHold
	}
	if validateFirewallEvidence(record) != nil {
		return errRecoveryHold
	}
	if resourceDrift(record.GetNativePlan()) {
		if err := s.verifyResourceChallenge(ctx, loaded, record); err != nil {
			return err
		}
	} else if record.GetChallenge() != nil || (record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED && record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED) || record.GetStartedAt() != nil || len(record.GetStartGrantEnvelope()) != 0 || resource.ValidateReadOnlyVerification(record.GetNativePlan(), record.GetVerification()) != nil {
		return errRecoveryHold
	}
	if len(record.GetStartGrantEnvelope()) != 0 {
		grantAt := record.GetGrantAcceptedAt().AsTime()
		if !bytes.Equal(digestBytes(record.GetStartGrantEnvelope()), record.GetStartGrantSha256()) {
			return errRecoveryHold
		}
		if _, err := loaded.execution.verifier.VerifyResourceStart(ctx, record.GetAcceptedRoot(), delegation, record.GetStartGrantEnvelope(), intent, record.GetChallenge(), grantAt); err != nil {
			return historicalResourceError(ctx)
		}
	}
	if started := record.GetStartedAt(); started != nil {
		if len(record.GetStartGrantEnvelope()) == 0 {
			return errRecoveryHold
		}
		if _, err := loaded.execution.verifier.VerifyResourceStart(ctx, record.GetAcceptedRoot(), delegation, record.GetStartGrantEnvelope(), intent, record.GetChallenge(), started.AsTime()); err != nil {
			return historicalResourceError(ctx)
		}
	}
	if resourceDrift(record.GetNativePlan()) && record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED && record.GetStartedAt() == nil {
		return errRecoveryHold
	}
	return nil
}

func (s *Service) verifyResourceChallenge(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord) error {
	challenge, intent := record.GetChallenge(), record.GetIntent()
	planDigest, err := resource.PlanDigest(record.GetNativePlan())
	if err != nil || challenge == nil || !proto.Equal(challenge.GetRef(), intent.GetDesired().GetRef()) || challenge.GetOperation() != intent.GetOperation() || challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), record.GetIntentSha256()) || !bytes.Equal(challenge.GetNativePlanSha256(), planDigest[:]) || challenge.GetBootId() != record.GetNativePlan().GetBefore().GetMetadata().GetBootId() || challenge.GetIssuedAt().AsTime().Before(record.GetAcceptedAt().AsTime()) || challenge.GetExpiresAt().AsTime().After(intent.GetExpiresAt().AsTime()) {
		return errRecoveryHold
	}
	if intent.GetPreparation() == nil && !proto.Equal(challenge.GetIssuedAt(), record.GetAcceptedAt()) {
		return errRecoveryHold
	}
	if preparation := intent.GetPreparation(); preparation != nil && challenge.GetExpiresAt().AsTime().After(preparation.GetDeadline().AsTime()) {
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
	verified := new(agentv1.ResourceExecutionChallenge)
	if err := s.authority.Verify(ctx, record.GetChallengeProof(), verified, 1, public); err != nil || !proto.Equal(verified, challenge) {
		return historicalResourceError(ctx)
	}
	return nil
}

func historicalResourceError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errRecoveryHold
}

// All helpers below are called under Service.mu (or before New publishes it).
func (s *Service) loadResourceAction(ctx context.Context, loaded *bound, actionID string) (*agentv1.ResourceExecutionRecord, int64, error) {
	record, revision, err := s.store.LoadResourceAction(ctx, actionID)
	if err != nil {
		return nil, 0, s.resourceStoreError(err)
	}
	if record.GetIntent().GetActionId() != actionID {
		s.noteTrustDamage()
		return nil, 0, errRecoveryHold
	}
	if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return nil, 0, err
	}
	return record, revision, nil
}

func (s *Service) updateResourceAction(ctx context.Context, loaded *bound, revision int64, next *agentv1.ResourceExecutionRecord) error {
	// Sealed deliveries are retained only while a native use may still follow.
	if next.GetCompletedAt() != nil {
		next.SealedSecrets = nil
	}
	if err := s.verifyResourceRecord(ctx, loaded, next); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errInternal
	}
	_, err := s.store.UpdateResourceAction(ctx, revision, loaded.revision, loaded.execution.revision, next)
	return s.resourceStoreError(err)
}

func (s *Service) resourceStoreError(err error) error {
	if errors.Is(err, journal.ErrRecoveryHold) {
		s.noteTrustDamage()
		return errRecoveryHold
	}
	return err
}
