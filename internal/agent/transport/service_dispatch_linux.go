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
	serviceActionsPerCycle = 4
	serviceDispatchTimeout = 2 * time.Minute
	servicePollTimeout     = 10 * time.Second
	servicePollInterval    = 500 * time.Millisecond
)

// dispatchServices relays exact signed bytes, not execution authority. Only the
// executor can consume a grant and only the server can close an action. Neither
// queue acceptance nor a historical signed result implies live compliance.
func (m *managementLoop) dispatchServices(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, serviceDispatchTimeout)
	defer cancel()
	for range serviceActionsPerCycle {
		work, err := m.serviceWork(ctx)
		if err != nil || work == nil {
			return err
		}
		closed, err := m.relayServiceAction(ctx, work)
		if err != nil {
			return fmt.Errorf("relay service action %s: %w", work.GetActionId(), err)
		}
		if !closed {
			return nil
		}
	}
	return nil
}

func (m *managementLoop) serviceWork(ctx context.Context) (*devicev1.ServiceWork, error) {
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return nil, fmt.Errorf("establish service work session: %w", err)
	}
	response, err := rpc(ctx, authority.servers.device.GetServiceWork, &devicev1.GetServiceWorkRequest{SessionEpoch: authority.epoch})
	if err != nil {
		return nil, fmt.Errorf("get service work: %w", err)
	}
	if err := validateManagementMessage(response); err != nil {
		return nil, fmt.Errorf("invalid service work: %w", err)
	}
	return response.GetWork(), nil
}

func (m *managementLoop) relayServiceAction(ctx context.Context, work *devicev1.ServiceWork) (bool, error) {
	digest := sha256.Sum256(work.GetIntentEnvelope())
	status, phaseErr := m.prepareAndStartService(ctx, work, digest)
	if phaseErr != nil {
		// Preparation may have committed before its reply was lost, or an
		// existing/expired action may now be history. Lookup never consumes a
		// new effect and must not invent another action or fresh challenge.
		var err error
		status, err = m.serviceStatus(ctx, work.GetActionId(), digest)
		if err != nil {
			return false, errors.Join(phaseErr, err)
		}
		slog.Warn("service execution phase incomplete; reporting protected history", "action_id", work.GetActionId(), "error", phaseErr)
	}
	// A failed start authorization must retry in the next cycle, not spend the
	// remaining challenge lifetime waiting for a PREPARED action to execute.
	if phaseErr == nil || status.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED {
		if err := m.pollServiceExecution(ctx, work.GetActionId(), digest, status); err != nil {
			return false, errors.Join(phaseErr, err)
		}
	}
	return m.reportServiceResult(ctx, work)
}

func (m *managementLoop) prepareAndStartService(ctx context.Context, work *devicev1.ServiceWork, digest [sha256.Size]byte) (*agentv1.ServiceExecutionStatus, error) {
	prepared, err := rpc(ctx, m.executor.PrepareServiceExecution, &agentv1.PrepareServiceExecutionRequest{IntentEnvelope: work.GetIntentEnvelope()})
	if err != nil {
		return nil, fmt.Errorf("prepare service execution: %w", err)
	}
	status := prepared.GetStatus()
	if err := checkServiceStatus(status, work.GetActionId(), digest); err != nil {
		return nil, err
	}
	if status.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED {
		return status, nil
	}
	if len(prepared.GetChallengeProof()) == 0 {
		return nil, errors.New("prepared service execution has no challenge proof")
	}
	grant := work.GetStartGrantEnvelope()
	if len(grant) == 0 {
		authority, err := establish(ctx, m.executor, &m.cache, m.gate)
		if err != nil {
			return nil, fmt.Errorf("establish service start session: %w", err)
		}
		response, err := rpc(ctx, authority.servers.device.AuthorizeServiceStart, &devicev1.AuthorizeServiceStartRequest{
			SessionEpoch: authority.epoch, ActionId: work.GetActionId(), ChallengeProof: prepared.GetChallengeProof(),
		})
		if err != nil {
			return nil, fmt.Errorf("authorize service start: %w", err)
		}
		if err := validateManagementMessage(response); err != nil {
			return nil, fmt.Errorf("invalid service start grant response: %w", err)
		}
		grant = response.GetStartGrantEnvelope()
	}
	// No cadence delay or new authorization intervenes here. A retained grant
	// is replayed exactly; the executor alone decides whether it was consumed
	// already or its short-lived challenge has expired.
	started, err := rpc(ctx, m.executor.StartServiceExecution, &agentv1.StartServiceExecutionRequest{
		ActionId: work.GetActionId(), StartGrantEnvelope: grant,
	})
	if err != nil {
		return nil, fmt.Errorf("start service execution: %w", err)
	}
	if err := checkServiceStatus(started.GetStatus(), work.GetActionId(), digest); err != nil {
		return nil, err
	}
	return started.GetStatus(), nil
}

func checkServiceStatus(status *agentv1.ServiceExecutionStatus, actionID string, digest [sha256.Size]byte) error {
	if err := validateManagementMessage(status); err != nil {
		return fmt.Errorf("invalid protected service status: %w", err)
	}
	if status.GetActionId() != actionID || !bytes.Equal(status.GetIntentSha256(), digest[:]) {
		return errors.New("protected service status does not bind the dispatched intent")
	}
	return nil
}

func (m *managementLoop) serviceStatus(ctx context.Context, actionID string, digest [sha256.Size]byte) (*agentv1.ServiceExecutionStatus, error) {
	response, err := rpc(ctx, m.executor.GetServiceExecution, &agentv1.GetServiceExecutionRequest{ActionId: actionID})
	if err != nil {
		return nil, fmt.Errorf("get service execution: %w", err)
	}
	if err := checkServiceStatus(response.GetStatus(), actionID, digest); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}

func (m *managementLoop) pollServiceExecution(parent context.Context, actionID string, digest [sha256.Size]byte, status *agentv1.ServiceExecutionStatus) error {
	ctx, cancel := context.WithTimeout(parent, servicePollTimeout)
	defer cancel()
	for !serviceExecutionTerminal(status.GetState()) {
		var err error
		status, err = m.serviceStatus(ctx, actionID, digest)
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil {
				return nil // Attest the current protected history after the bound.
			}
			return err
		}
		if serviceExecutionTerminal(status.GetState()) {
			return nil
		}
		timer := time.NewTimer(servicePollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return parent.Err()
		case <-timer.C:
		}
	}
	return nil
}

func serviceExecutionTerminal(state agentv1.ServiceExecutionState) bool {
	switch state {
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED:
		return true
	default:
		return false
	}
}

func (m *managementLoop) reportServiceResult(ctx context.Context, work *devicev1.ServiceWork) (bool, error) {
	fresh, err := m.serviceWork(ctx)
	if err != nil {
		return false, err
	}
	if fresh == nil || fresh.GetActionId() != work.GetActionId() {
		return false, nil
	}
	if !bytes.Equal(fresh.GetIntentEnvelope(), work.GetIntentEnvelope()) {
		return false, errors.New("server changed the intent of an existing service action")
	}
	// Re-establish before attesting so the signed session and report request
	// use current protected identity, including renewal while native work ran.
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return false, fmt.Errorf("establish service result session: %w", err)
	}
	attested, err := rpc(ctx, m.executor.AttestServiceExecution, &agentv1.AttestServiceExecutionRequest{
		ActionId: work.GetActionId(), Nonce: fresh.GetResultNonce(),
	})
	if err != nil {
		return false, fmt.Errorf("attest service execution: %w", err)
	}
	if err := validateManagementMessage(attested); err != nil {
		return false, fmt.Errorf("invalid protected service attestation: %w", err)
	}
	reported, err := rpc(ctx, authority.servers.device.ReportServiceResult, &devicev1.ReportServiceResultRequest{
		SessionEpoch: authority.epoch, ActionId: work.GetActionId(),
		AttestationEnvelope: attested.GetAttestationEnvelope(), CertificatePem: attested.GetCertificatePem(),
	})
	if err != nil {
		return false, fmt.Errorf("report service result: %w", err)
	}
	if err := validateManagementMessage(reported); err != nil {
		return false, fmt.Errorf("invalid service result response: %w", err)
	}
	return reported.GetClosed(), nil
}
