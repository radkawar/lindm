//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type actionAccountLockEvidence struct {
	Scenario             string                  `json:"scenario"`
	Lock                 *actionDispatchEvidence `json:"lock"`
	Release              *actionDispatchEvidence `json:"release"`
	PasswordLocked       bool                    `json:"password_locked"`
	AccountExpired       bool                    `json:"account_expired"`
	OriginalRestored     bool                    `json:"original_restored"`
	AdminChangePreserved bool                    `json:"admin_change_preserved"`
}

// Shadow records are compared in memory only. Neither password hashes nor full
// shadow rows are exported to the nonsecret qualification record.
func nativeAccountLockScenarios(ctx context.Context, machine *actionMachine, control *vmControlPlane, result *VMDeviceActionsResult) error {
	const username = "lindm-lock-test"
	if _, err := machine.vm.Run(ctx, "sudo -n useradd --no-create-home --shell /bin/sh "+username, nil); err != nil {
		return err
	}
	provider := &agentv1.DeviceActionProviderConfig{AllowSessionLock: true, AllowAccountLock: true, ProtectedAccounts: []string{"root", "lindm-lab"}, AllowQuarantine: true, ManagementEndpoints: []string{"127.0.0.1", "10.0.2.2"}, DnsServers: []string{"10.0.2.3"}, QuarantineSeconds: 60}
	if err := configureActionGuest(ctx, machine.vm.guest, provider, nil); err != nil {
		return err
	}
	if _, err := waitGuestExecutorReady(ctx, machine.vm.guest, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return err
	}
	for _, scenario := range []string{"release_lock_restore", "release_lock_preserves_admin_change"} {
		before, err := machine.vm.Run(ctx, "sudo -n getent shadow "+username, nil)
		if err != nil {
			return err
		}
		entry := &actionAccountLockEvidence{Scenario: scenario}
		result.AccountLocks = append(result.AccountLocks, entry)
		request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{Usernames: []string{username}}}})
		entry.Lock, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
		if err != nil {
			clear(before)
			return err
		}
		locked, err := machine.vm.Run(ctx, "sudo -n getent shadow "+username, nil)
		if err != nil {
			clear(before)
			return err
		}
		fields := bytes.Split(bytes.TrimSpace(locked), []byte{':'})
		entry.PasswordLocked = len(fields) == 9 && bytes.HasPrefix(fields[1], []byte{'!'})
		entry.AccountExpired = len(fields) == 9 && bytes.Equal(fields[7], []byte{'1'})
		clear(locked)
		if !entry.PasswordLocked || !entry.AccountExpired {
			clear(before)
			return errors.New("native account lock did not disable password and expire login")
		}
		if scenario == "release_lock_preserves_admin_change" {
			if _, err := machine.vm.Run(ctx, "sudo -n chage -E 1970-01-03 "+username, nil); err != nil {
				clear(before)
				return err
			}
		}
		expected, err := machine.vm.Run(ctx, "sudo -n getent shadow "+username, nil)
		if err != nil {
			clear(before)
			return err
		}
		request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: entry.Lock.ActionID}}})
		entry.Release, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
		if err != nil {
			clear(before)
			clear(expected)
			return err
		}
		after, err := machine.vm.Run(ctx, "sudo -n getent shadow "+username, nil)
		if err != nil {
			clear(before)
			clear(expected)
			return err
		}
		entry.OriginalRestored = bytes.Equal(after, before)
		entry.AdminChangePreserved = scenario == "release_lock_preserves_admin_change" && bytes.Equal(after, expected)
		clear(before)
		clear(expected)
		clear(after)
		if scenario == "release_lock_restore" && !entry.OriginalRestored || scenario == "release_lock_preserves_admin_change" && !entry.AdminChangePreserved {
			return errors.New("native account release failed ownership-aware restoration")
		}
	}
	return nil
}
