//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

type actionAccountLockEvidence struct {
	Scenario                 string                  `json:"scenario"`
	Lock                     *actionDispatchEvidence `json:"lock"`
	Release                  *actionDispatchEvidence `json:"release"`
	PasswordInitiallyEnabled bool                    `json:"password_initially_enabled"`
	PasswordLocked           bool                    `json:"password_locked"`
	AccountExpired           bool                    `json:"account_expired"`
	OriginalRestored         bool                    `json:"original_restored"`
	AdminChangePreserved     bool                    `json:"admin_change_preserved"`
}

// unreportedLockPrefix is the executor's visible verification for a desktop
// whose locker never sets logind LockedHint.
const unreportedLockPrefix = "session_lock_state_unreported: "

func nativeLockScenarios(ctx context.Context, machine *actionMachine, control *vmControlPlane, result *VMDeviceActionsResult) (err error) {
	desktop := machine.desktop
	result.DesktopInitialLogind, err = prepareActionDesktop(ctx, machine.vm, desktop, machine.release)
	if err != nil {
		return err
	}
	result.DesktopBefore, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(false))
	if err != nil {
		return err
	}
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}})
	if desktop.lockedHint {
		result.Lock, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	} else {
		result.Lock, result.LockVerification, err = dispatchUnreportedLock(ctx, machine, control, request)
	}
	if err != nil {
		return err
	}
	result.DesktopAfter, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(true))
	if err != nil {
		return err
	}
	request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: result.Lock.ActionID}}})
	result.LockRelease, _, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	if err != nil {
		return err
	}
	// Release withdraws owned restrictions, never authenticates or remotely
	// unlocks a desktop. The native locker must remain as the lock left it.
	result.DesktopAfterRelease, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(true))
	if err != nil {
		return err
	}
	if !desktop.lockedHint {
		// Every later lock on this desktop would again end unverified. The
		// account scenarios run with no graphical session instead, which the
		// record states explicitly.
		if err := stopActionDesktop(ctx, machine.vm); err != nil {
			return err
		}
		result.AccountsNoDesktop = true
	}
	return nativeAccountLockScenarios(ctx, machine, control, result)
}

// dispatchUnreportedLock requires the executor's definite unreported-lock
// result: OUTCOME_UNKNOWN/OBSERVATION, not verified, never SESSIONS_LOCKED,
// with the session_lock_state_unreported evidence, agreed by the server.
func dispatchUnreportedLock(ctx context.Context, machine *actionMachine, control *vmControlPlane, request *adminv1.CreateDeviceActionRequest) (*actionDispatchEvidence, string, error) {
	_, status, err := dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	if err == nil || status == nil {
		return nil, "", fmt.Errorf("lock on a desktop without LockedHint did not end unverified: %w", err)
	}
	verification := status.GetVerification()
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN || status.GetFailure() != agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_OBSERVATION || verification.GetVerified() || verification.GetAfter().GetSessionsLocked() || !strings.HasPrefix(verification.GetEvidence(), unreportedLockPrefix) {
		return nil, "", fmt.Errorf("lock ended %s/%s with evidence %q, not the visible unreported lock state: %w", status.GetState(), status.GetFailure(), verification.GetEvidence(), err)
	}
	id := status.GetActionId()
	deadline := time.Now().Add(time.Minute)
	for {
		server, err := control.session.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: id}))
		if err != nil {
			return nil, "", err
		}
		if server.Msg.GetAction().GetStatus().GetState() == status.GetState() {
			evidence := &actionDispatchEvidence{ActionID: id, IntentSHA256: fmt.Sprintf("%x", status.GetIntentSha256()), RootState: status.GetState().String(), ServerState: server.Msg.GetAction().GetStatus().GetState().String(), Failure: status.GetFailure().String(), ObservedAt: time.Now().UTC()}
			if status.GetStartedAt() != nil {
				evidence.StartedAt = status.GetStartedAt().AsTime()
			}
			return evidence, verification.GetEvidence(), nil
		}
		if time.Now().After(deadline) {
			return nil, "", errors.New("server did not record the unverified lock result")
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// stopActionDesktop ends the lab desktop through its display manager and
// waits until logind lists no graphical user session.
func stopActionDesktop(ctx context.Context, vm *EncryptedVM) error {
	if _, err := vm.Run(ctx, "sudo -n systemctl stop display-manager.service", nil); err != nil {
		return err
	}
	return pollGuest(ctx, vm.guest, 2*time.Minute, "graphical sessions ended", `sudo -n sh -eu -c 'for id in $(loginctl list-sessions --no-legend --no-pager | cut -d" " -f1); do case "$(loginctl show-session "$id" -p Type --value)/$(loginctl show-session "$id" -p State --value)" in x11/active|x11/online|wayland/active|wayland/online) exit 1;; esac; done'`)
}

// Shadow records are compared in memory only. Neither password hashes nor full
// shadow rows are exported to the nonsecret qualification record.
func nativeAccountLockScenarios(ctx context.Context, machine *actionMachine, control *vmControlPlane, result *VMDeviceActionsResult) error {
	const username = "lindm-lock-test"
	if _, err := machine.vm.Run(ctx, "sudo -n useradd --no-create-home --shell /bin/sh "+username, nil); err != nil {
		return err
	}
	password := []byte(username + ":" + rand.Text() + "\n")
	_, err := machine.vm.Run(ctx, "sudo -n chpasswd", bytes.NewReader(password))
	clear(password)
	if err != nil {
		return err
	}
	data, err := machine.vm.Run(ctx, "sudo -n cat /etc/lindm/executor.json", nil)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	provider := config.GetActionProvider()
	if provider == nil {
		return errors.New("native account fixture requires existing action qualification")
	}
	provider.AllowAccountLock = true
	provider.ProtectedAccounts = []string{"root", "lindm-lab", actionDesktopUser}
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
		originalFields := bytes.Split(bytes.TrimSpace(before), []byte{':'})
		entry.PasswordInitiallyEnabled = len(originalFields) == 9 && len(originalFields[1]) > 0 && originalFields[1][0] != '!' && originalFields[1][0] != '*'
		if !entry.PasswordInitiallyEnabled {
			clear(before)
			return errors.New("native account fixture must start password-enabled")
		}
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
