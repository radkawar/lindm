// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

// prepareAndCommitDeviceActionRecovery routes a server hint to the dedicated
// root verifier. The hint grants no authority: only the exact signed intent,
// action-key handoff proof and purpose-separated BOOT grant can authorize reboot.
// Recovery credentials contain a public action key; private custody stays root-local.
func (m *managementLoop) prepareAndCommitDeviceActionRecovery(ctx context.Context, work *devicev1.DeviceActionWork, digest [sha256.Size]byte) (*agentv1.DeviceActionStatus, error) {
	prepared, err := rpc(ctx, m.executor.PrepareDeviceActionRecovery, &agentv1.PrepareDeviceActionRecoveryRequest{IntentEnvelope: work.GetIntentEnvelope()})
	if err != nil {
		return nil, fmt.Errorf("prepare device action recovery: %w", err)
	}
	if err := checkDeviceActionStatus(prepared.GetStatus(), work.GetActionId(), digest); err != nil {
		return nil, err
	}
	if prepared.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		return prepared.GetStatus(), nil
	}
	if err := validateManagementMessage(prepared); err != nil {
		return nil, fmt.Errorf("invalid protected recovery handoff: %w", err)
	}
	credential, grant := work.GetRecoveryCredentialEnvelope(), work.GetRecoveryBootGrantEnvelope()
	if (len(credential) == 0) != (len(grant) == 0) {
		return nil, errors.New("server retained an incomplete recovery credential and boot grant pair")
	}
	if len(credential) == 0 {
		authority, err := establish(ctx, m.executor, &m.cache, m.gate)
		if err != nil {
			return nil, fmt.Errorf("establish recovery registration session: %w", err)
		}
		registered, err := rpc(ctx, authority.servers.device.RegisterDeviceActionRecovery, &devicev1.RegisterDeviceActionRecoveryRequest{
			SessionEpoch: authority.epoch, ActionId: work.GetActionId(),
			HandoffProof: prepared.GetHandoffProof(), CertificatePem: prepared.GetCertificatePem(),
		})
		if err != nil {
			return nil, fmt.Errorf("register device action recovery: %w", err)
		}
		if err := validateManagementMessage(registered); err != nil {
			return nil, fmt.Errorf("invalid recovery registration response: %w", err)
		}
		credential, grant = registered.GetCredentialEnvelope(), registered.GetBootGrantEnvelope()
	}
	// No scheduling delay, new challenge or fresh grant replaces this pair.
	// The executor checks its <=30-second boot deadline and durable consumption.
	committed, err := rpc(ctx, m.executor.CommitDeviceActionRecovery, &agentv1.CommitDeviceActionRecoveryRequest{
		ActionId: work.GetActionId(), CredentialEnvelope: credential, BootGrantEnvelope: grant,
	})
	if err != nil {
		return nil, fmt.Errorf("commit device action recovery: %w", err)
	}
	if err := checkDeviceActionStatus(committed.GetStatus(), work.GetActionId(), digest); err != nil {
		return nil, err
	}
	return committed.GetStatus(), nil
}
