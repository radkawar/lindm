// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

// assistanceReadinessTimeout bounds the wait for the server to see the lane's
// desktop after the inventory refresh it requested.
const assistanceReadinessTimeout = 2 * time.Minute

// awaitAssistanceReadiness publishes the desktop session the lane just started
// and waits until the server offers assistance. The console offers a request
// only while GetAssistanceReadiness is READY, which needs a desktop or login
// screen in the device's latest session inventory (87c22c76); the inventory
// from enrollment predates the lane's autologin. A signed RefreshInventory
// action publishes the current sessions; the returned readiness is evidence.
func awaitAssistanceReadiness(ctx context.Context, vm *guestVM, owner *devlab.OwnerSession, deviceID string) (*adminv1.AssistanceReadiness, error) {
	identity, err := readVMConnectionIdentity(ctx, vm)
	if err != nil {
		return nil, err
	}
	request := actionRequestFor(deviceID, identity.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})
	request.Reason = "disposable assistance desktop inventory refresh"
	if _, _, err := dispatchNativeAction(ctx, vm, owner, request, nil, false); err != nil {
		return nil, fmt.Errorf("publish assistance desktop inventory: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, assistanceReadinessTimeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		response, err := owner.Admin.GetAssistanceReadiness(ctx, connect.NewRequest(&adminv1.GetAssistanceReadinessRequest{DeviceId: deviceID}))
		if err == nil && response.Msg.GetReadiness().GetState() == adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_READY {
			return response.Msg.GetReadiness(), nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return nil, fmt.Errorf("assistance readiness: %w", err)
			}
			return nil, fmt.Errorf("assistance readiness stayed %s after the desktop inventory refresh", response.Msg.GetReadiness().GetState())
		case <-ticker.C:
		}
	}
}
