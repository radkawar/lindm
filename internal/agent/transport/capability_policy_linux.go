// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/protodata"
)

// capabilityPolicyTimeout bounds one relay of the signed capability policy.
const capabilityPolicyTimeout = time.Minute

// synchronizeCapabilityPolicy relays the server's signed capability policy to
// the executor. The network process only carries bytes: the executor verifies
// signer, binding and monotonicity. Applied cursors are reported only for an
// ACTIVE policy so an INERT or absent one is always reissued.
func (m *managementLoop) synchronizeCapabilityPolicy(ctx context.Context) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, capabilityPolicyTimeout)
	defer cancel()
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return err
	}
	current, err := rpc(ctx, m.executor.GetCapabilityPolicy, &agentv1.GetCapabilityPolicyRequest{})
	if err != nil {
		return err
	}
	if err := validateManagementMessage(current); err != nil {
		return fmt.Errorf("invalid protected capability policy view: %w", err)
	}
	observation := current.GetObservation()
	// Local registration can change without any signed grant change. Publish the
	// protected view even when issuance fails or the server has nothing to relay.
	defer func() {
		resultErr = errors.Join(resultErr, m.publishCapabilityObservation(ctx, observation))
	}()
	if observation.GetState() == agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_REFUSED_LOCALLY {
		return nil
	}
	request := &devicev1.GetCapabilityPolicyRequest{SessionEpoch: authority.epoch}
	if observation.GetState() == agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE {
		request.AppliedVersion, request.AppliedSha256 = observation.GetAppliedVersion(), observation.GetAppliedSha256()
	}
	desired, err := rpc(ctx, authority.servers.device.GetCapabilityPolicy, request)
	if err != nil {
		return err
	}
	if err := validateManagementMessage(desired); err != nil {
		return fmt.Errorf("invalid server capability policy response: %w", err)
	}
	if reason := desired.GetUnavailableReason(); reason != m.capabilityUnavailable {
		m.capabilityUnavailable = reason
		if reason != "" {
			slog.Warn("capability policy unavailable", "reason", reason)
		}
	}
	if len(desired.GetPolicyEnvelope()) == 0 {
		return nil
	}
	updated, err := rpc(ctx, m.executor.UpdateCapabilityPolicy, &agentv1.UpdateCapabilityPolicyRequest{PolicyEnvelope: desired.GetPolicyEnvelope()})
	if err != nil {
		return err
	}
	if err := validateManagementMessage(updated); err != nil {
		return fmt.Errorf("invalid protected capability policy receipt: %w", err)
	}
	observation = updated.GetObservation()
	slog.Info("capability policy synchronized", "version", updated.GetObservation().GetAppliedVersion())
	return nil
}

func (m *managementLoop) publishCapabilityObservation(ctx context.Context, observation *agentv1.CapabilityPolicyObservation) error {
	if proto.Equal(observation, m.capabilityObserved) {
		return nil
	}
	if m.refreshCapabilities == nil {
		return errors.New("capability observation inventory handoff unavailable")
	}
	if err := m.refreshCapabilities(ctx, observation); err != nil {
		return err
	}
	// The RPC result is owned by this loop and never mutated. The handoff uses
	// it only to coalesce scheduling; uploaded status is re-read from the root.
	m.capabilityObserved = observation
	return nil
}

// attachCapabilityPolicy publishes the executor's capability status
// unmodified. An unreachable executor or invalid response omits it.
func (r *runner) attachCapabilityPolicy(ctx context.Context, host *inventoryv1.HostObservation) {
	ctx, cancel := context.WithTimeout(ctx, patchStatusTimeout)
	defer cancel()
	response, err := rpc(ctx, r.executor.GetCapabilityPolicy, &agentv1.GetCapabilityPolicyRequest{})
	if err != nil || response == nil || protodata.ValidateClosed(response.ProtoReflect()) != nil || protovalidate.Validate(response) != nil {
		host.Details.CapabilityPolicy = nil
		return
	}
	host.Details.CapabilityPolicy = response.GetObservation()
}
