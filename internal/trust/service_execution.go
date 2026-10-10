package trust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// VerifyServiceIntent authenticates preflight authority, never permission to
// mutate native state. Root and delegation must be previously authenticated
// outputs of this verifier; they cannot be selected by an untrusted caller.
// The executor separately checks device/generation/resource rollback fences.
func (v *ExecutionVerifier) VerifyServiceIntent(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, now time.Time) (*agentv1.ServiceExecutionIntent, error) {
	keys, err := v.serviceKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, now)
	if err != nil {
		return nil, err
	}
	intent := new(agentv1.ServiceExecutionIntent)
	if len(envelope) > 16384 {
		return nil, errors.New("service intent exceeds size limit")
	}
	if err := v.authority.Verify(ctx, envelope, intent, 1, keys...); err != nil {
		return nil, err
	}
	if err := v.serviceIntentBinding(root, delegation, intent, now); err != nil {
		return nil, err
	}
	return intent, nil
}

// VerifyServiceStart verifies a separately delegated start signature and exact
// root-generated challenge. It does not consume the challenge or check its local
// CLOCK_BOOTTIME deadline: the executor must do both durably at the effect gate.
// Intent and challenge must come from the protected, authenticated action record.
func (v *ExecutionVerifier) VerifyServiceStart(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, intent *agentv1.ServiceExecutionIntent, challenge *agentv1.ServiceExecutionChallenge, now time.Time) (*agentv1.ServiceExecutionStartGrant, error) {
	keys, err := v.serviceKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, now)
	if err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(intent); err != nil {
		return nil, err
	}
	if err := v.serviceIntentBinding(root, delegation, intent, now); err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(challenge); err != nil {
		return nil, err
	}
	if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() {
		return nil, errors.New("service challenge target binding rejected")
	}
	if !validServiceInterval(now, challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime(), intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime()) {
		return nil, errors.New("service challenge validity rejected")
	}
	if len(envelope) > 16384 {
		return nil, errors.New("service start grant exceeds size limit")
	}
	grant := new(agentv1.ServiceExecutionStartGrant)
	if err := v.authority.Verify(ctx, envelope, grant, 1, keys...); err != nil {
		return nil, err
	}
	if !proto.Equal(grant.GetChallenge(), challenge) || grant.GetActorId() != intent.GetActorId() || grant.GetAuthorizationVersion() != intent.GetAuthorizationVersion() || grant.GetRootVersion() != root.GetVersion() || grant.GetDelegationVersion() != delegation.GetVersion() {
		return nil, errors.New("service start grant binding rejected")
	}
	if !validServiceInterval(now, grant.GetNotBefore().AsTime(), grant.GetExpiresAt().AsTime(), challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime()) {
		return nil, errors.New("service start grant validity rejected")
	}
	return grant, nil
}

func (v *ExecutionVerifier) serviceIntentBinding(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, intent *agentv1.ServiceExecutionIntent, now time.Time) error {
	if intent.GetDeploymentId() != v.deploymentID || intent.GetRootVersion() != root.GetVersion() || intent.GetDelegationVersion() != delegation.GetVersion() || intent.GetRecoveryEpoch() < delegation.GetMinimumRecoveryEpoch() {
		return errors.New("service intent authority binding rejected")
	}
	if !validServiceInterval(now, intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) {
		return errors.New("service intent validity rejected")
	}
	return nil
}

func (v *ExecutionVerifier) serviceKeys(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, role agentv1.ExecutionSignerRole, now time.Time) ([]ed25519.PublicKey, error) {
	return v.capabilityKeys(root, delegation, role, "systemd.service.v1", now)
}

func (v *ExecutionVerifier) capabilityKeys(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, role agentv1.ExecutionSignerRole, capability string, now time.Time) ([]ed25519.PublicKey, error) {
	if _, err := v.rootKeys(root, now); err != nil {
		return nil, err
	}
	if err := v.authority.validateExecutionMessage(delegation); err != nil {
		return nil, err
	}
	if delegation.GetDeploymentId() != v.deploymentID || delegation.GetRootVersion() != root.GetVersion() || !validServiceInterval(now, delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime(), root.GetNotBefore().AsTime(), root.GetExpiresAt().AsTime()) {
		return nil, errors.New("service delegation binding or validity rejected")
	}
	keys := make([]ed25519.PublicKey, 0, len(delegation.GetDelegates()))
	for _, delegate := range delegation.GetDelegates() {
		if delegate.GetRole() != role || !slices.Contains(delegate.GetCapabilities(), capability) {
			continue
		}
		key, err := v.executionKey(delegate.GetKey())
		if err != nil {
			return nil, err
		}
		for _, rootKey := range root.GetKeys() {
			if rootKey.GetKeyId() == delegate.GetKey().GetKeyId() {
				return nil, errors.New("offline root key cannot authorize online service work")
			}
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no current signer for service capability and role")
	}
	return keys, nil
}

func validServiceInterval(now, begin, end, outerBegin, outerEnd time.Time) bool {
	return !now.Before(begin) && now.Before(end) && !begin.Before(outerBegin) && !end.After(outerEnd)
}
