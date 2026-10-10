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

func (m *managementLoop) serviceWork(ctx context.Context) (*devicev1.ResourceWork, error) {
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return nil, fmt.Errorf("establish service work session: %w", err)
	}
	response, err := rpc(ctx, authority.servers.device.GetResourceWork, &devicev1.GetResourceWorkRequest{SessionEpoch: authority.epoch})
	if err != nil {
		return nil, fmt.Errorf("get service work: %w", err)
	}
	if err := validateManagementMessage(response); err != nil {
		return nil, fmt.Errorf("invalid service work: %w", err)
	}
	return response.GetWork(), nil
}

func (m *managementLoop) relayServiceAction(ctx context.Context, work *devicev1.ResourceWork) (bool, error) {
	if work.GetCancelPreparation() {
		return m.reportResourceResult(ctx, work)
	}
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
	// Staging is independent native work. Prepare polls it once per management
	// cycle; never spend a dispatch polling window waiting for downloads.
	// A failed start authorization also retries in the next cycle, without
	// spending the remaining challenge lifetime waiting for PREPARED to execute.
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING &&
		(phaseErr == nil || status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED) {
		if err := m.pollResourceExecution(ctx, work.GetActionId(), digest, status); err != nil {
			return false, errors.Join(phaseErr, err)
		}
	}
	return m.reportResourceResult(ctx, work)
}

func (m *managementLoop) prepareAndStartService(ctx context.Context, work *devicev1.ResourceWork, digest [sha256.Size]byte) (*agentv1.ResourceExecutionStatus, error) {
	prepared, err := rpc(ctx, m.executor.PrepareResourceExecution, &agentv1.PrepareResourceExecutionRequest{IntentEnvelope: work.GetIntentEnvelope()})
	if err != nil {
		return nil, fmt.Errorf("prepare service execution: %w", err)
	}
	status := prepared.GetStatus()
	if err := checkServiceStatus(status, work.GetActionId(), digest); err != nil {
		return nil, err
	}
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
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
		response, err := rpc(ctx, authority.servers.device.AuthorizeResourceStart, &devicev1.AuthorizeResourceStartRequest{
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
	started, err := rpc(ctx, m.executor.StartResourceExecution, &agentv1.StartResourceExecutionRequest{
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

func (m *managementLoop) cancelResourcePreparation(ctx context.Context, work *devicev1.ResourceWork, digest [sha256.Size]byte) (*agentv1.CancelResourcePreparationResponse, error) {
	response, err := rpc(ctx, m.executor.CancelResourcePreparation, &agentv1.CancelResourcePreparationRequest{
		ActionId: work.GetActionId(), IntentSha256: digest[:],
	})
	if err != nil {
		return nil, fmt.Errorf("cancel resource preparation: %w", err)
	}
	if err := validateManagementMessage(response); err != nil {
		return nil, fmt.Errorf("invalid preparation cancellation: %w", err)
	}
	if response.GetStatus() != nil {
		if err := checkServiceStatus(response.GetStatus(), work.GetActionId(), digest); err != nil {
			return nil, err
		}
	}
	return response, nil
}

func checkServiceStatus(status *agentv1.ResourceExecutionStatus, actionID string, digest [sha256.Size]byte) error {
	if err := validateManagementMessage(status); err != nil {
		return fmt.Errorf("invalid protected service status: %w", err)
	}
	if status.GetActionId() != actionID || !bytes.Equal(status.GetIntentSha256(), digest[:]) {
		return errors.New("protected service status does not bind the dispatched intent")
	}
	return nil
}

func (m *managementLoop) serviceStatus(ctx context.Context, actionID string, digest [sha256.Size]byte) (*agentv1.ResourceExecutionStatus, error) {
	response, err := rpc(ctx, m.executor.GetResourceExecution, &agentv1.GetResourceExecutionRequest{ActionId: actionID})
	if err != nil {
		return nil, fmt.Errorf("get service execution: %w", err)
	}
	if err := checkServiceStatus(response.GetStatus(), actionID, digest); err != nil {
		return nil, err
	}
	return response.GetStatus(), nil
}

func (m *managementLoop) pollResourceExecution(parent context.Context, actionID string, digest [sha256.Size]byte, status *agentv1.ResourceExecutionStatus) error {
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
		if serviceExecutionTerminal(status.GetState()) || status.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
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

func serviceExecutionTerminal(state agentv1.ResourceExecutionState) bool {
	switch state {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED:
		return true
	default:
		return false
	}
}

func (m *managementLoop) reportResourceResult(ctx context.Context, work *devicev1.ResourceWork) (bool, error) {
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
	neverPrepared := false
	if fresh.GetCancelPreparation() {
		// Supersession/expiry may have committed during preparation. Cleanup
		// consumes no effect authority and must precede its acknowledgment.
		digest := sha256.Sum256(work.GetIntentEnvelope())
		cancelled, err := m.cancelResourcePreparation(ctx, fresh, digest)
		if err != nil {
			return false, err
		}
		neverPrepared = cancelled.GetNeverPrepared()
	}
	// Re-establish before attesting so the signed session and report request
	// use current protected identity, including renewal while native work ran.
	authority, err := establish(ctx, m.executor, &m.cache, m.gate)
	if err != nil {
		return false, fmt.Errorf("establish service result session: %w", err)
	}
	request := &devicev1.ReportResourceResultRequest{SessionEpoch: authority.epoch, ActionId: work.GetActionId()}
	if neverPrepared {
		digest := sha256.Sum256(work.GetIntentEnvelope())
		request.NeverPrepared = &devicev1.ResourcePreparationCancellation{IntentSha256: digest[:], ResultNonce: fresh.GetResultNonce()}
	} else {
		attested, err := rpc(ctx, m.executor.AttestResourceExecution, &agentv1.AttestResourceExecutionRequest{
			ActionId: work.GetActionId(), Nonce: fresh.GetResultNonce(),
		})
		if err != nil {
			return false, fmt.Errorf("attest service execution: %w", err)
		}
		if err := validateManagementMessage(attested); err != nil {
			return false, fmt.Errorf("invalid protected service attestation: %w", err)
		}
		request.AttestationEnvelope, request.CertificatePem = attested.GetAttestationEnvelope(), attested.GetCertificatePem()
	}
	reported, err := rpc(ctx, authority.servers.device.ReportResourceResult, request)
	if err != nil {
		return false, fmt.Errorf("report service result: %w", err)
	}
	if err := validateManagementMessage(reported); err != nil {
		return false, fmt.Errorf("invalid service result response: %w", err)
	}
	return reported.GetClosed(), nil
}
