//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
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
	_, err = verifyChallengeCustody(ctx, s, loaded, record, new(agentv1.ResourceExecutionChallenge))
	return err
}

func historicalResourceError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errRecoveryHold
}

// All helpers below are called under Service.mu (or before New publishes it).
func (s *Service) loadResourceAction(ctx context.Context, loaded *bound, actionID string) (*agentv1.ResourceExecutionRecord, int64, error) {
	return resourceAction.loadAction(ctx, s, loaded, actionID)
}

func (s *Service) updateResourceAction(ctx context.Context, loaded *bound, revision int64, next *agentv1.ResourceExecutionRecord) error {
	// Sealed deliveries are retained only while a native use may still follow.
	if next.GetCompletedAt() != nil {
		next.SealedSecrets = nil
	}
	return resourceAction.update(ctx, s, loaded, revision, next)
}

func (s *Service) resourceStoreError(err error) error {
	if errors.Is(err, journal.ErrRecoveryHold) {
		s.noteTrustDamage()
		return errRecoveryHold
	}
	return err
}
