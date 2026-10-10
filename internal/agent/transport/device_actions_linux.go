//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

const (
	deviceActionsPerCycle       = 4
	deviceActionDispatchTimeout = 5 * time.Minute
	deviceActionPollTimeout     = 10 * time.Second
	deviceActionPollInterval    = 500 * time.Millisecond
)

// dispatchDeviceActions has no spool or local queue. The server retains exact
// authority bytes and the root retains consumption/history, including ambiguity.
func (m *managementLoop) dispatchDeviceActions(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, deviceActionDispatchTimeout)
	defer cancel()
	for range deviceActionsPerCycle {
		work, reportOnly, err := m.deviceActionWork(ctx)
		if err != nil || work == nil {
			return err
		}
		closed, err := m.relayDeviceAction(ctx, work, reportOnly)
		if err != nil {
			return fmt.Errorf("relay device action %s: %w", work.GetActionId(), err)
		}
		if !closed || reportOnly {
			return nil
		}
	}
	return nil
}

func (m *managementLoop) deviceActionWork(ctx context.Context) (*devicev1.DeviceActionWork, bool, error) {
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return nil, false, fmt.Errorf("establish device action session: %w", err)
	}
	response, err := rpc(ctx, authority.servers.device.GetDeviceActionWork, &devicev1.GetDeviceActionWorkRequest{SessionEpoch: authority.epoch})
	if err != nil {
		return nil, false, fmt.Errorf("get device action work: %w", err)
	}
	if err := validateManagementMessage(response); err != nil {
		return nil, false, fmt.Errorf("invalid device action work: %w", err)
	}
	return response.GetWork(), authority.connection.GetDeviceActionReportOnly(), nil
}

func (m *managementLoop) relayDeviceAction(ctx context.Context, work *devicev1.DeviceActionWork, reportOnly bool) (bool, error) {
	digest := sha256.Sum256(work.GetIntentEnvelope())
	var status *agentv1.DeviceActionStatus
	var phaseErr error
	if reportOnly {
		status, phaseErr = m.deviceActionStatus(ctx, work.GetActionId(), digest)
		if phaseErr != nil {
			return false, phaseErr
		}
	} else {
		status, phaseErr = m.prepareAndStartDeviceAction(ctx, work, digest)
	}
	if phaseErr != nil {
		// Lost replies never authorize a replacement action or challenge. Query
		// protected history; only PREPARED may consume an exact retained grant.
		var err error
		status, err = m.deviceActionStatus(ctx, work.GetActionId(), digest)
		if err != nil {
			return false, errors.Join(phaseErr, err)
		}
		slog.Warn("device action phase incomplete; reporting protected history", "action_id", work.GetActionId(), "error", phaseErr)
	}
	if !reportOnly && status.GetRefreshInventory() && len(work.GetInventoryReceiptEnvelope()) != 0 && (status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING || status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN) {
		confirmed, err := rpc(ctx, m.executor.ConfirmDeviceActionInventory, &agentv1.ConfirmDeviceActionInventoryRequest{ActionId: work.GetActionId(), ReceiptEnvelope: work.GetInventoryReceiptEnvelope()})
		if err != nil {
			return false, err
		}
		status = confirmed.GetStatus()
		if err := checkDeviceActionStatus(status, work.GetActionId(), digest); err != nil {
			return false, err
		}
	}
	if !reportOnly && status.GetRefreshInventory() && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
		if m.refreshInventory == nil {
			return false, errors.New("inventory refresh transport is unavailable")
		}
		if err := m.refreshInventory(ctx, status); err != nil {
			return false, fmt.Errorf("publish refreshed inventory: %w", err)
		}
		var err error
		status, err = m.deviceActionStatus(ctx, work.GetActionId(), digest)
		if err != nil {
			return false, err
		}
	}
	if !reportOnly && status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW && len(work.GetEscrowReceiptEnvelope()) != 0 {
		var err error
		status, err = m.confirmDeviceActionEscrow(ctx, work, digest, work.GetEscrowReceiptEnvelope())
		if err != nil {
			return false, errors.Join(phaseErr, err)
		}
	}
	if phaseErr == nil || status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		if err := m.pollDeviceAction(ctx, work.GetActionId(), digest, status); err != nil {
			return false, errors.Join(phaseErr, err)
		}
	}
	closed, receipt, err := m.reportDeviceAction(ctx, work)
	if err != nil || closed || len(receipt) == 0 || reportOnly {
		return closed, err
	}
	// A storage receipt is not a fresh start grant. The executor verifies its
	// exact original intent/slot/key binding and alone owns retirement effects.
	status, err = m.deviceActionStatus(ctx, work.GetActionId(), digest)
	if err != nil {
		return false, err
	}
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		return false, nil
	}
	status, err = m.confirmDeviceActionEscrow(ctx, work, digest, receipt)
	if err != nil {
		return false, err
	}
	if err := m.pollDeviceAction(ctx, work.GetActionId(), digest, status); err != nil {
		return false, err
	}
	closed, _, err = m.reportDeviceAction(ctx, work)
	return closed, err
}

func (m *managementLoop) prepareAndStartDeviceAction(ctx context.Context, work *devicev1.DeviceActionWork, digest [sha256.Size]byte) (*agentv1.DeviceActionStatus, error) {
	if work.GetRecoveryHandoff() {
		return m.prepareAndCommitDeviceActionRecovery(ctx, work, digest)
	}
	prepared, err := rpc(ctx, m.executor.PrepareDeviceAction, &agentv1.PrepareDeviceActionRequest{IntentEnvelope: work.GetIntentEnvelope()})
	if err != nil {
		return nil, fmt.Errorf("prepare device action: %w", err)
	}
	status := prepared.GetStatus()
	if err := checkDeviceActionStatus(status, work.GetActionId(), digest); err != nil {
		return nil, err
	}
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED {
		return status, nil
	}
	if len(prepared.GetChallengeProof()) == 0 {
		return nil, errors.New("prepared device action has no challenge proof")
	}
	grant := work.GetStartGrantEnvelope()
	if len(grant) == 0 {
		authority, err := establish(ctx, m.executor, &m.cache, m.gate)
		if err != nil {
			return nil, fmt.Errorf("establish device action start session: %w", err)
		}
		response, err := rpc(ctx, authority.servers.device.AuthorizeDeviceActionStart, &devicev1.AuthorizeDeviceActionStartRequest{
			SessionEpoch: authority.epoch, ActionId: work.GetActionId(), ChallengeProof: prepared.GetChallengeProof(),
		})
		if err != nil {
			return nil, fmt.Errorf("authorize device action start: %w", err)
		}
		if err := validateManagementMessage(response); err != nil {
			return nil, fmt.Errorf("invalid device action start grant: %w", err)
		}
		grant = response.GetStartGrantEnvelope()
	}
	started, err := rpc(ctx, m.executor.StartDeviceAction, &agentv1.StartDeviceActionRequest{ActionId: work.GetActionId(), StartGrantEnvelope: grant})
	if err != nil {
		return nil, fmt.Errorf("start device action: %w", err)
	}
	if err := checkDeviceActionStatus(started.GetStatus(), work.GetActionId(), digest); err != nil {
		return nil, err
	}
	return started.GetStatus(), nil
}

func checkDeviceActionStatus(status *agentv1.DeviceActionStatus, actionID string, digest [sha256.Size]byte) error {
	if err := validateManagementMessage(status); err != nil {
		return fmt.Errorf("invalid protected device action status: %w", err)
	}
	if status.GetActionId() != actionID || !bytes.Equal(status.GetIntentSha256(), digest[:]) {
		return errors.New("protected device action status does not bind the dispatched intent")
	}
	return nil
}

func (m *managementLoop) deviceActionStatus(ctx context.Context, actionID string, digest [sha256.Size]byte) (*agentv1.DeviceActionStatus, error) {
	response, err := rpc(ctx, m.executor.GetDeviceAction, &agentv1.GetDeviceActionRequest{ActionId: actionID})
	if err != nil {
		return nil, fmt.Errorf("get device action: %w", err)
	}
	if err := checkDeviceActionStatus(response.GetStatus(), actionID, digest); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}

func (m *managementLoop) confirmDeviceActionEscrow(ctx context.Context, work *devicev1.DeviceActionWork, digest [sha256.Size]byte, receipt []byte) (*agentv1.DeviceActionStatus, error) {
	response, err := rpc(ctx, m.executor.ConfirmDeviceActionEscrow, &agentv1.ConfirmDeviceActionEscrowRequest{ActionId: work.GetActionId(), ReceiptEnvelope: receipt})
	if err != nil {
		return nil, fmt.Errorf("confirm device action escrow: %w", err)
	}
	if err := checkDeviceActionStatus(response.GetStatus(), work.GetActionId(), digest); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}

func deviceActionTerminal(state agentv1.DeviceActionState) bool {
	switch state {
	case agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED,
		agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED,
		agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN,
		agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED:
		return true
	default:
		return false
	}
}

func (m *managementLoop) pollDeviceAction(parent context.Context, actionID string, digest [sha256.Size]byte, status *agentv1.DeviceActionStatus) error {
	ctx, cancel := context.WithTimeout(parent, deviceActionPollTimeout)
	defer cancel()
	for !deviceActionTerminal(status.GetState()) && status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
		var err error
		status, err = m.deviceActionStatus(ctx, actionID, digest)
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
				return nil
			}
			return err
		}
		if deviceActionTerminal(status.GetState()) || status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW {
			return nil
		}
		timer := time.NewTimer(deviceActionPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return parent.Err()
		case <-timer.C:
		}
	}
	return nil
}

func (m *managementLoop) reportDeviceAction(ctx context.Context, work *devicev1.DeviceActionWork) (bool, []byte, error) {
	fresh, _, err := m.deviceActionWork(ctx)
	if err != nil {
		return false, nil, err
	}
	if fresh == nil || fresh.GetActionId() != work.GetActionId() {
		return false, nil, nil
	}
	if !bytes.Equal(fresh.GetIntentEnvelope(), work.GetIntentEnvelope()) {
		return false, nil, errors.New("server changed the intent of an existing device action")
	}
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return false, nil, fmt.Errorf("establish device action result session: %w", err)
	}
	attested, err := rpc(ctx, m.executor.AttestDeviceAction, &agentv1.AttestDeviceActionRequest{ActionId: work.GetActionId(), Nonce: fresh.GetResultNonce()})
	if err != nil {
		return false, nil, fmt.Errorf("attest device action: %w", err)
	}
	if err := validateManagementMessage(attested); err != nil {
		return false, nil, fmt.Errorf("invalid protected device action attestation: %w", err)
	}
	reported, err := rpc(ctx, authority.servers.device.ReportDeviceActionResult, &devicev1.ReportDeviceActionResultRequest{
		SessionEpoch: authority.epoch, ActionId: work.GetActionId(),
		AttestationEnvelope: attested.GetAttestationEnvelope(), CertificatePem: attested.GetCertificatePem(),
	})
	if err != nil {
		return false, nil, fmt.Errorf("report device action result: %w", err)
	}
	if err := validateManagementMessage(reported); err != nil {
		return false, nil, fmt.Errorf("invalid device action result response: %w", err)
	}
	return reported.GetClosed(), reported.GetEscrowReceiptEnvelope(), nil
}
