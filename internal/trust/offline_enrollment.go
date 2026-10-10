package trust

import (
	"context"
	"errors"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// OfflineEnrollmentCapability is deliberately separate from native execution.
const OfflineEnrollmentCapability = "enrollment.offline.v1"

// VerifyOfflineChain authenticates portable delegation from the installation's
// already pinned bootstrap. A file never chooses its own initial root.
func (v *ExecutionVerifier) VerifyOfflineChain(ctx context.Context, initial *agentv1.ExecutionRoot, transitions []*agentv1.ExecutionRootTransition, envelope []byte, now time.Time) (*agentv1.ExecutionRoot, *agentv1.ExecutionDelegation, error) {
	root := initial
	for _, transition := range transitions {
		next, err := v.VerifyRootTransition(ctx, root, transition, now)
		if err != nil {
			return nil, nil, err
		}
		root = next
	}
	delegation, err := v.VerifyDelegation(ctx, root, envelope, 0, 0, now)
	return root, delegation, err
}

func (v *ExecutionVerifier) VerifyOfflineAuthorization(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, now time.Time) (*agentv1.OfflineEnrollmentAuthorization, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, OfflineEnrollmentCapability, now)
	if err != nil {
		return nil, err
	}
	value := new(agentv1.OfflineEnrollmentAuthorization)
	if err := v.authority.Verify(ctx, envelope, value, 1, keys...); err != nil {
		return nil, err
	}
	if value.GetDeploymentId() != v.deploymentID || value.GetRootVersion() != root.GetVersion() || value.GetDelegationVersion() != delegation.GetVersion() || !validServiceInterval(now, value.GetNotBefore().AsTime(), value.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) {
		return nil, errors.New("offline enrollment authorization binding or validity rejected")
	}
	return value, nil
}

func (v *ExecutionVerifier) VerifyOfflineResponse(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, now time.Time) (*agentv1.OfflineEnrollmentResponse, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, OfflineEnrollmentCapability, now)
	if err != nil {
		return nil, err
	}
	value := new(agentv1.OfflineEnrollmentResponse)
	if err := v.authority.Verify(ctx, envelope, value, 1, keys...); err != nil {
		return nil, err
	}
	if value.GetRequest().GetDeploymentId() != v.deploymentID || value.GetRootVersion() != root.GetVersion() || value.GetDelegationVersion() != delegation.GetVersion() || !validServiceInterval(now, value.GetNotBefore().AsTime(), value.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) || !validServiceInterval(now, value.GetNotBefore().AsTime(), value.GetExpiresAt().AsTime(), value.GetRequest().GetNotBefore().AsTime(), value.GetRequest().GetExpiresAt().AsTime()) {
		return nil, errors.New("offline enrollment response binding or validity rejected")
	}
	return value, nil
}
