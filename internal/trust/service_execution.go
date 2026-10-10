package trust

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/resource"
)

// VerifyResourceIntent authenticates preflight authority, never permission to
// mutate native state. Root and delegation must be previously authenticated
// outputs of this verifier; they cannot be selected by an untrusted caller.
// The executor separately checks device/generation/resource rollback fences.
func (v *ExecutionVerifier) VerifyResourceIntent(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, now time.Time) (*agentv1.ResourceExecutionIntent, error) {
	if len(envelope) == 0 || len(envelope) > 131072 {
		return nil, errors.New("invalid resource intent size")
	}
	// This untrusted parse selects an exact key scope only. Authority.Verify
	// independently authenticates and validates the original envelope below.
	var selection struct {
		Payload []byte `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &selection); err != nil {
		return nil, errors.New("invalid resource intent envelope")
	}
	candidate := new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(selection.Payload, candidate); err != nil {
		return nil, errors.New("invalid resource intent payload")
	}
	if err := resource.ValidateDesired(candidate.GetDesired()); err != nil {
		return nil, err
	}
	capability, err := resource.Capability(candidate.GetDesired().GetRef().GetKind())
	if err != nil {
		return nil, err
	}
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, capability, now)
	if err != nil {
		return nil, err
	}
	intent := new(agentv1.ResourceExecutionIntent)
	if err := v.authority.Verify(ctx, envelope, intent, 1, keys...); err != nil {
		return nil, err
	}
	if err := v.serviceIntentBinding(root, delegation, intent, now); err != nil {
		return nil, err
	}
	return intent, nil
}

// VerifyResourceStart verifies a separately delegated start signature and exact
// root-generated challenge. It does not consume the challenge or check its local
// CLOCK_BOOTTIME deadline: the executor must do both durably at the effect gate.
// Intent and challenge must come from the protected, authenticated action record.
func (v *ExecutionVerifier) VerifyResourceStart(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, intent *agentv1.ResourceExecutionIntent, challenge *agentv1.ResourceExecutionChallenge, now time.Time) (*agentv1.ResourceExecutionStartGrant, error) {
	capability, err := resource.Capability(intent.GetDesired().GetRef().GetKind())
	if err != nil {
		return nil, err
	}
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, capability, now)
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
	if !proto.Equal(challenge.GetRef(), intent.GetDesired().GetRef()) || challenge.GetOperation() != intent.GetOperation() || challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() {
		return nil, errors.New("service challenge target binding rejected")
	}
	if !validServiceInterval(now, challenge.GetIssuedAt().AsTime(), challenge.GetExpiresAt().AsTime(), intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime()) {
		return nil, errors.New("service challenge validity rejected")
	}
	if len(envelope) > 16384 {
		return nil, errors.New("service start grant exceeds size limit")
	}
	grant := new(agentv1.ResourceExecutionStartGrant)
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

func (v *ExecutionVerifier) serviceIntentBinding(root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, intent *agentv1.ResourceExecutionIntent, now time.Time) error {
	if err := resource.ValidateDesired(intent.GetDesired()); err != nil {
		return err
	}
	if intent.GetDeploymentId() != v.deploymentID || intent.GetRootVersion() != root.GetVersion() || intent.GetDelegationVersion() != delegation.GetVersion() || intent.GetRecoveryEpoch() < delegation.GetMinimumRecoveryEpoch() {
		return errors.New("service intent authority binding rejected")
	}
	if !validServiceInterval(now, intent.GetNotBefore().AsTime(), intent.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) {
		return errors.New("service intent validity rejected")
	}
	return nil
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
