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
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/protodata"
)

const managementInterval = 20 * time.Second

// The management loop owns its cancellation, join and connection cache. It does
// not share inventory scheduling, collection, spool state or transport status;
// even a two-minute native collection cannot delay trust admission or dispatch.
type managementLoop struct {
	executor agentv1connect.ExecutorServiceClient
	cache    connectionCache
	gate     authorityGate
}

func (m *managementLoop) start(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer m.cache.Close()
		for ctx.Err() == nil {
			if err := synchronizeExecutionTrust(ctx, m.executor, &m.cache, m.gate); err != nil {
				if ctx.Err() == nil {
					slog.Warn("execution trust synchronization incomplete", "error", err)
				}
			} else if err := m.dispatchServices(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("service dispatch incomplete", "error", err)
			}
			if ctx.Err() != nil {
				return
			}
			timer := time.NewTimer(managementInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func synchronizeExecutionTrust(ctx context.Context, executor agentv1connect.ExecutorServiceClient, cache *connectionCache, gate authorityGate) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	authority, err := establish(ctx, executor, cache, gate)
	if err != nil {
		return err
	}
	view, err := rpc(ctx, executor.GetExecutionTrust, &agentv1.GetExecutionTrustRequest{})
	if err != nil {
		return err
	}
	if err := validateManagementMessage(view); err != nil {
		return fmt.Errorf("invalid protected execution trust view: %w", err)
	}
	desired, err := rpc(ctx, authority.servers.device.GetExecutionTrust, &devicev1.GetExecutionTrustRequest{
		SessionEpoch: authority.epoch, RootVersion: view.GetRootVersion(), RootSha256: view.GetRootSha256(),
		DelegationVersion: view.GetDelegationVersion(), DelegationSha256: view.GetDelegationSha256(),
		MinimumRecoveryEpoch: view.GetMinimumRecoveryEpoch(),
	})
	if err != nil {
		return err
	}
	if err := validateManagementMessage(desired); err != nil {
		return fmt.Errorf("invalid server execution trust response: %w", err)
	}
	if desired.GetUpdate() == nil {
		return checkUnchangedTrust(view, desired)
	}
	// Server counters are comparison facts only. Signed documents must pass the
	// root's existing quorum, expiry, monotonicity and atomic-commit boundary.
	receipt, err := rpc(ctx, executor.UpdateExecutionTrust, desired.GetUpdate())
	if err != nil {
		return err
	}
	if err := checkTrustReceipt(receipt, desired); err != nil {
		return err
	}
	slog.Info("execution trust synchronized", "root_version", receipt.GetRootVersion(), "delegation_version", receipt.GetDelegationVersion(), "minimum_recovery_epoch", receipt.GetMinimumRecoveryEpoch())
	return nil
}

func checkUnchangedTrust(view *agentv1.GetExecutionTrustResponse, desired *devicev1.GetExecutionTrustResponse) error {
	// An unprovisioned server is not an instruction to clear local authority.
	if desired.GetRootVersion() == 0 && desired.GetDelegationVersion() == 0 && desired.GetMinimumRecoveryEpoch() == 0 {
		return nil
	}
	if desired.GetRootVersion() != view.GetRootVersion() || desired.GetDelegationVersion() != view.GetDelegationVersion() || desired.GetMinimumRecoveryEpoch() != view.GetMinimumRecoveryEpoch() {
		return errors.New("server omitted the signed update required by its execution trust counters")
	}
	return nil
}

func checkTrustReceipt(receipt *agentv1.UpdateExecutionTrustResponse, desired *devicev1.GetExecutionTrustResponse) error {
	if err := validateManagementMessage(receipt); err != nil {
		return fmt.Errorf("invalid protected execution trust receipt: %w", err)
	}
	if receipt.GetRootVersion() != desired.GetRootVersion() || receipt.GetDelegationVersion() != desired.GetDelegationVersion() || receipt.GetMinimumRecoveryEpoch() != desired.GetMinimumRecoveryEpoch() {
		return errors.New("protected execution trust receipt differs from server desired counters")
	}
	return nil
}

func validateManagementMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return errors.New("missing management message")
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	return protovalidate.Validate(message)
}
