// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"errors"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// CapabilityPolicyCapability is the exact delegated capability under which an
// online PLAN key may sign device capability policies. The offline owner must
// delegate it explicitly; no other capability implies it.
const CapabilityPolicyCapability = "agent.capability-policy.v1"

// ErrCapabilityPolicyBinding reports a correctly signed policy for another
// deployment.
var ErrCapabilityPolicyBinding = errors.New("capability_policy_binding_rejected")

// VerifyCapabilityPolicy authenticates a device capability policy signed by a
// PLAN key that the current delegation authorizes for
// CapabilityPolicyCapability. It binds the verifier's deployment only; the
// executor binds device and enrollment generation to its own identity and
// enforces version monotonicity.
func (v *ExecutionVerifier) VerifyCapabilityPolicy(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, envelope []byte, now time.Time) (*agentv1.AgentCapabilityPolicy, error) {
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, CapabilityPolicyCapability, now)
	if err != nil {
		return nil, err
	}
	value := new(agentv1.AgentCapabilityPolicy)
	if err := v.authority.Verify(ctx, envelope, value, 1, keys...); err != nil {
		return nil, err
	}
	if value.GetDeploymentId() != v.deploymentID {
		return nil, ErrCapabilityPolicyBinding
	}
	return value, nil
}
