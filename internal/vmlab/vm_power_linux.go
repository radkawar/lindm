// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/devlab"
)

type VMPowerEvidence struct {
	BootBefore        string                      `json:"boot_before"`
	BootAfter         string                      `json:"boot_after"`
	Restart           *agentv1.DeviceActionStatus `json:"restart,omitempty"`
	Refresh           *agentv1.DeviceActionStatus `json:"refresh,omitempty"`
	Shutdown          *agentv1.DeviceActionStatus `json:"shutdown,omitempty"`
	PublishedSequence uint64                      `json:"published_sequence"`
	QEMUExited        bool                        `json:"qemu_exited"`
}

// exerciseNativePower issues only real signed Admin actions. SSH probes never
// reboot or power off the guest, and reconnect never reissues a mutation.
func exerciseNativePower(ctx context.Context, vm *guestVM, control *vmControlPlane, fixture *devlab.AuthorityFixture, result *VMDispatchResult, proof *VMPowerEvidence) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	if err := configureActionGuest(ctx, vm, &agentv1.DeviceActionProviderConfig{AllowPowerActions: true}, nil); err != nil {
		return err
	}
	before, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
	if err != nil {
		return err
	}
	proof.BootBefore = strings.TrimSpace(string(before))
	previous, err := uuid.Parse(proof.BootBefore)
	if err != nil || previous == uuid.Nil {
		return errors.New("invalid native boot ID")
	}
	create := func(spec *agentv1.DeviceActionSpec) (string, error) {
		if err := waitNativeActionPresence(ctx, control.session, result.DeviceID); err != nil {
			return "", err
		}
		request := actionRequestFor(result.DeviceID, result.Generation, spec)
		request.Reason = "disposable Ubuntu native power and inventory qualification"
		response, err := control.session.Admin.CreateDeviceAction(ctx, connect.NewRequest(request))
		if err != nil {
			return "", err
		}
		return response.Msg.GetAction().GetActionId(), nil
	}
	refresh, err := create(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})
	if err != nil {
		return err
	}
	proof.Refresh, err = waitPowerServerState(ctx, control.session, refresh, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	if err != nil {
		return err
	}
	proof.PublishedSequence = proof.Refresh.GetVerification().GetInventorySequence()
	if proof.PublishedSequence == 0 {
		return errors.New("refresh result omitted committed sequence")
	}
	restart, err := create(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}})
	if err != nil {
		return err
	}
	if err := waitGuestBootChange(ctx, previous, func(probe context.Context) (string, error) {
		if vm.client != nil {
			_ = vm.client.Close()
			vm.client = nil
		}
		if err := vm.connect(probe); err != nil {
			return "", err
		}
		boot, err := vm.run(probe, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
		proof.BootAfter = strings.TrimSpace(string(boot))
		return proof.BootAfter, err
	}); err != nil {
		return err
	}
	// Original SSH reverse forwards died at reboot. Reopen the same authenticated
	// transport endpoints without changing the installed device identity.
	forwards, err := openLifecycleForwards(ctx, vm, [2]string{fixture.AdminAddress, fixture.DeviceAddress})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeLifecycleForwards(forwards)) }()
	proof.Restart, err = waitPowerServerState(ctx, control.session, restart, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED)
	if err != nil {
		return err
	}
	if proof.Restart.GetVerification().GetBootId() != proof.BootAfter {
		return errors.New("restart result boot ID differs from independent native observation")
	}
	delay := uint32(20)
	shutdown, err := create(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{DelaySeconds: &delay}}})
	if err != nil {
		return err
	}
	proof.Shutdown, err = waitPowerServerState(ctx, control.session, shutdown, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN)
	if err != nil {
		return err
	}
	if proof.Shutdown.GetVerification().GetEvidence() != "outcome_unknown_until_contact" {
		return errors.New("shutdown did not preserve uncertainty")
	}
	select {
	case <-vm.done:
		if vm.waitErr != nil || vm.cmd.ProcessState == nil || !vm.cmd.ProcessState.Success() {
			return errors.New("native shutdown did not exit QEMU successfully")
		}
		proof.QEMUExited = true
		return nil
	case <-ctx.Done():
		return errors.New("signed shutdown did not power off guest before deadline")
	}
}

func waitPowerServerState(ctx context.Context, owner *devlab.OwnerSession, id string, want agentv1.DeviceActionState) (*agentv1.DeviceActionStatus, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		response, err := owner.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: id}))
		if err != nil {
			return nil, err
		}
		status := response.Msg.GetAction().GetStatus()
		if powerActionObserved(status, want) {
			return status, nil
		}
		if status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED || status.GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_EXPIRED {
			return status, errors.New("native action failed: " + status.GetFailure().String())
		}
		select {
		case <-ctx.Done():
			return status, ctx.Err()
		case <-ticker.C:
		}
	}
}

func powerActionObserved(status *agentv1.DeviceActionStatus, want agentv1.DeviceActionState) bool {
	// An issued start grant is projected UNKNOWN before the root's result
	// arrives. It is not yet evidence that logind accepted the request.
	return status.GetState() == want && (want != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN || status.GetVerification() != nil)
}
