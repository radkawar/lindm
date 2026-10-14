// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
)

// VerifyRecoveryTime bootstraps time from protected recovery trust, not the RTC.
// The response timestamp is only a candidate until the START signature binds it
// to this exact request. Callers generate a fresh nonce, measure monotonic RTT,
// consume the result once in process and never persist a bootstrap across boots.
// Statement expiry bounds bootstrap acceptance only. The monotonic clock may
// continue for read-only result reconciliation; every effect must independently
// enforce current credential, grant and delegation expiry.
func (v *ExecutionVerifier) VerifyRecoveryTime(ctx context.Context, root *agentv1.ExecutionRoot, response *recoveryv1.GetRecoveryTimeResponse, request *recoveryv1.GetRecoveryTimeRequest, minimumTime time.Time, elapsed time.Duration) (*agentv1.RecoveryTimeStatement, *agentv1.ExecutionRoot, *agentv1.ExecutionDelegation, error) {
	if err := v.validateRecoveryTime(response, request, elapsed); err != nil {
		return nil, nil, nil, err
	}
	digest, err := ExecutionRootDigest(root)
	if err != nil || root.GetVersion() != request.GetRootVersion() || !bytes.Equal(digest[:], request.GetRootSha256()) {
		return nil, nil, nil, errors.New("recovery time protected root binding rejected")
	}
	candidate := response.GetServerTime().AsTime()
	upper := candidate.Add(elapsed)
	if _, err := v.rootKeys(root, candidate); err != nil {
		return nil, nil, nil, err
	}
	if _, err := v.rootKeys(root, upper); err != nil {
		return nil, nil, nil, err
	}
	current := root
	for _, transition := range response.GetTrustUpdate().GetRootTransitions() {
		current, err = v.VerifyRootTransition(ctx, current, transition, candidate)
		if err != nil {
			return nil, nil, nil, err
		}
		if _, err := v.rootKeys(current, upper); err != nil {
			return nil, nil, nil, err
		}
	}
	// Permit an exact unchanged delegation, never a same-version replacement.
	// The request counters and digest come from the caller's protected state.
	envelope := response.GetTrustUpdate().GetDelegationEnvelope()
	delegation, err := v.VerifyDelegation(ctx, current, envelope, request.GetDelegationVersion()-1, request.GetMinimumRecoveryEpoch(), candidate)
	if err != nil {
		return nil, nil, nil, err
	}
	if delegation.GetVersion() == request.GetDelegationVersion() {
		digest := sha256.Sum256(envelope)
		if current.GetVersion() != root.GetVersion() || delegation.GetMinimumRecoveryEpoch() != request.GetMinimumRecoveryEpoch() || !bytes.Equal(digest[:], request.GetDelegationSha256()) {
			return nil, nil, nil, errors.New("recovery time unchanged delegation binding rejected")
		}
	}
	statement, err := v.verifyRecoveryTimeStatement(ctx, current, delegation, response, request, minimumTime, elapsed)
	if err != nil {
		return nil, nil, nil, err
	}
	return statement, current, delegation, nil
}

// VerifyRecoveryTimeStatement authenticates time against an already verified
// current authority snapshot. Server issuance uses this after reading its DB
// snapshot; recovery clients must use VerifyRecoveryTime to authenticate updates
// from their protected root and enforce their retained counters and digests.
func (v *ExecutionVerifier) VerifyRecoveryTimeStatement(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, response *recoveryv1.GetRecoveryTimeResponse, request *recoveryv1.GetRecoveryTimeRequest, minimumTime time.Time, elapsed time.Duration) (*agentv1.RecoveryTimeStatement, error) {
	if err := v.validateRecoveryTime(response, request, elapsed); err != nil {
		return nil, err
	}
	return v.verifyRecoveryTimeStatement(ctx, root, delegation, response, request, minimumTime, elapsed)
}

func (v *ExecutionVerifier) verifyRecoveryTimeStatement(ctx context.Context, root *agentv1.ExecutionRoot, delegation *agentv1.ExecutionDelegation, response *recoveryv1.GetRecoveryTimeResponse, request *recoveryv1.GetRecoveryTimeRequest, minimumTime time.Time, elapsed time.Duration) (*agentv1.RecoveryTimeStatement, error) {
	candidate := response.GetServerTime().AsTime()
	keys, err := v.capabilityKeys(root, delegation, agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, "device.sanitize.v1", candidate)
	if err != nil {
		return nil, err
	}
	statement := new(agentv1.RecoveryTimeStatement)
	if err := v.authority.Verify(ctx, response.GetTimeEnvelope(), statement, 1, keys...); err != nil {
		return nil, err
	}
	digest, err := DeviceActionDigest(request)
	if err != nil {
		return nil, err
	}
	if statement.GetDeploymentId() != v.deploymentID || !bytes.Equal(statement.GetRequestSha256(), digest[:]) || statement.GetRootVersion() != root.GetVersion() || statement.GetDelegationVersion() != delegation.GetVersion() || !statement.GetServerTime().AsTime().Equal(candidate) {
		return nil, errors.New("recovery time statement binding rejected")
	}
	// Expiry is exclusive. The entire conservative interval must fit, not just
	// its midpoint or the unsigned candidate. No skew allowance widens validity.
	upper := candidate.Add(elapsed)
	if candidate.Before(minimumTime) || !validServiceInterval(candidate, candidate, statement.GetExpiresAt().AsTime(), delegation.GetNotBefore().AsTime(), delegation.GetExpiresAt().AsTime()) || !upper.Before(statement.GetExpiresAt().AsTime()) || !upper.Before(delegation.GetExpiresAt().AsTime()) || !upper.Before(root.GetExpiresAt().AsTime()) {
		return nil, errors.New("recovery time validity or protected minimum rejected")
	}
	return statement, nil
}

func (v *ExecutionVerifier) validateRecoveryTime(response *recoveryv1.GetRecoveryTimeResponse, request *recoveryv1.GetRecoveryTimeRequest, elapsed time.Duration) error {
	if elapsed < 0 || elapsed > 30*time.Second {
		return errors.New("recovery time round trip rejected")
	}
	if err := v.authority.validateExecutionMessage(request); err != nil {
		return err
	}
	return v.authority.validateExecutionMessage(response)
}
