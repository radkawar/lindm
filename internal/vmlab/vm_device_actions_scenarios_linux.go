//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/devlab"
)

func revealNativeRecovery(ctx context.Context, owner, approver *devlab.OwnerSession, deviceID, actionID string) ([]byte, error) {
	if err := owner.StepUp(ctx); err != nil {
		return nil, err
	}
	request := &adminv1.RevealRecoveryKeyRequest{RequestId: uuid.NewString(), DeviceId: deviceID, ActionId: actionID, Reason: "verify literal recovery credential on disposable cold boot"}
	created, err := owner.Admin.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 300, Payload: &adminv1.CreateApprovalRequest_RevealRecoveryKey{RevealRecoveryKey: request}}))
	if err != nil {
		return nil, err
	}
	approved, err := approver.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "independent approval for native recovery qualification"}))
	if err != nil {
		return nil, err
	}
	request.ApprovalId = approved.Msg.GetApproval().GetId()
	response, err := owner.Admin.RevealRecoveryKey(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	key := response.Msg.RecoveryKey
	response.Msg.RecoveryKey = nil
	if _, err := actionRecoveryText(key); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

// The network oracle lives wholly inside the disposable guest. A dedicated
// namespace is a real remote IP peer, not a host route or public Internet probe.
const actionNetworkSetup = `set -eu
ip netns add lindm-action-oracle
ip link add lindm-action-a type veth peer name lindm-action-b
ip link set lindm-action-b netns lindm-action-oracle
ip addr add 198.18.0.1/30 dev lindm-action-a
ip link set lindm-action-a up
ip netns exec lindm-action-oracle ip addr add 198.18.0.2/30 dev lindm-action-b
ip netns exec lindm-action-oracle ip link set lindm-action-b up
ip netns exec lindm-action-oracle ip link set lo up
ping -n -c 1 -W 2 198.18.0.2 >/dev/null`

func setupActionNetworkOracle(ctx context.Context, vm *EncryptedVM) error {
	_, err := vm.Run(ctx, "sudo -n sh -eu -c "+nativeQuote(actionNetworkSetup), nil)
	return err
}

func probeActionNetwork(ctx context.Context, vm *EncryptedVM, reachable bool) error {
	result, err := vm.guest.runResult(ctx, "ping -n -c 1 -W 2 198.18.0.2", nil, 4096, 5*time.Second)
	if err != nil {
		return err
	}
	if (reachable && result.ExitCode != 0) || (!reachable && result.ExitCode != 1) {
		return fmt.Errorf("quarantine IP-peer probe exit=%d reachable=%t", result.ExitCode, reachable)
	}
	return nil
}

func waitActionNetworkExpiry(ctx context.Context, vm *EncryptedVM, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		result, err := vm.guest.runResult(ctx, "ping -n -c 1 -W 1 198.18.0.2", nil, 4096, 3*time.Second)
		if err != nil {
			return err
		}
		if result.ExitCode == 0 {
			return nil
		}
		if result.ExitCode != 1 {
			return errors.New("expiry network oracle failed independently of quarantine")
		}
		select {
		case <-ctx.Done():
			return errors.New("native quarantine did not expire without executor")
		case <-ticker.C:
		}
	}
}
