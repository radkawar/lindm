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

type actionDesktopEvidence struct {
	SessionID         string `json:"session_id"`
	Type              string `json:"type"`
	Class             string `json:"class"`
	User              string `json:"user"`
	Service           string `json:"service"`
	Desktop           string `json:"desktop"`
	LockedHint        bool   `json:"locked_hint"`
	ScreenSaverActive bool   `json:"screen_saver_active"`
}

const actionDesktopUser = "lindm-desktop-test"

// prepareActionDesktop changes only the disposable overlay. A password-enabled
// user is required: a locked/passwordless installer SSH account is not a useful
// GNOME lock-screen fixture. GDM performs the real PAM/logind login.
func prepareActionDesktop(ctx context.Context, vm *EncryptedVM) (string, error) {
	initial, err := vm.Run(ctx, `sudo -n sh -eu -c 'loginctl list-sessions --no-legend --no-pager | while read -r id rest; do loginctl show-session "$id" -p Id -p Name -p Class -p Type -p Desktop -p Service -p LockedHint; done'`, nil)
	if err != nil {
		return "", err
	}
	script := `set -eu
useradd --create-home --shell /bin/bash ` + actionDesktopUser + `
chpasswd
install -d -o ` + actionDesktopUser + ` -g ` + actionDesktopUser + ` -m 0700 /home/` + actionDesktopUser + `/.config
printf 'yes\n' > /home/` + actionDesktopUser + `/.config/gnome-initial-setup-done
chown ` + actionDesktopUser + `:` + actionDesktopUser + ` /home/` + actionDesktopUser + `/.config/gnome-initial-setup-done
config=/etc/gdm/custom.conf
session=gnome
if test -d /etc/gdm3; then config=/etc/gdm3/custom.conf; session=ubuntu; fi
printf '[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=` + actionDesktopUser + `\nInitialSetupEnable=False\n' > "$config"
install -d -m 0755 /var/lib/AccountsService/users
printf '[User]\nSystemAccount=false\nSession=%s\nXSession=%s\n' "$session" "$session" > /var/lib/AccountsService/users/` + actionDesktopUser + `
if command -v restorecon >/dev/null; then restorecon -RF "$config" /var/lib/AccountsService /home/` + actionDesktopUser + `; fi
systemctl restart display-manager.service`
	password := []byte(actionDesktopUser + ":" + rand.Text() + "\n")
	defer clear(password)
	_, err = vm.Run(ctx, "sudo -n sh -eu -c "+nativeQuote(script), bytes.NewReader(password))
	return string(initial), err
}

func observeActionDesktop(ctx context.Context, vm *EncryptedVM, locked bool) (*actionDesktopEvidence, error) {
	data, err := vm.Run(ctx, `sudo -n sh -eu -c '
loginctl list-sessions --no-legend --no-pager | while read -r id rest; do
 type=$(loginctl show-session "$id" -p Type --value)
 case "$type" in x11|wayland) ;; *) continue;; esac
 class=$(loginctl show-session "$id" -p Class --value)
 [ "$class" = user ] || continue
 user=$(loginctl show-session "$id" -p Name --value)
 [ "$user" = `+actionDesktopUser+` ] || continue
 printf "%s\n%s\n" "$id" "$type"
 loginctl show-session "$id" -p Desktop --value
 loginctl show-session "$id" -p LockedHint --value
 printf "%s\n%s\n" "$class" "$user"
 loginctl show-session "$id" -p Service --value
 uid=$(id -u `+actionDesktopUser+`)
 pgrep -u "$uid" -x gnome-shell >/dev/null
 sudo -n -u `+actionDesktopUser+` env XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus gdbus call --session --dest org.gnome.ScreenSaver --object-path /org/gnome/ScreenSaver --method org.gnome.ScreenSaver.GetActive
 exit 0
done'`, nil)
	if err != nil {
		return nil, err
	}
	return parseActionDesktop(data, locked)
}

func parseActionDesktop(data []byte, locked bool) (*actionDesktopEvidence, error) {
	fields := strings.Split(strings.TrimSpace(string(data)), "\n")
	// logind's Desktop label can be empty, even with a real GNOME session.
	// The user-owned gnome-shell and ScreenSaver API establish the desktop.
	if len(fields) != 8 || (fields[1] != "x11" && fields[1] != "wayland") || fields[4] != "user" || fields[5] != actionDesktopUser || fields[6] != "gdm-autologin" {
		return nil, fmt.Errorf("actual GNOME user session was not observed: %q", fields)
	}
	if fields[3] != "yes" && fields[3] != "no" {
		return nil, errors.New("invalid logind lock observation")
	}
	if fields[7] != "(true,)" && fields[7] != "(false,)" {
		return nil, errors.New("invalid GNOME screen shield observation")
	}
	observed := &actionDesktopEvidence{SessionID: fields[0], Type: fields[1], Desktop: fields[2], Class: fields[4], User: fields[5], Service: fields[6], LockedHint: fields[3] == "yes", ScreenSaverActive: fields[7] == "(true,)"}
	if observed.LockedHint != locked || observed.ScreenSaverActive != locked {
		return nil, errors.New("native logind and GNOME lock state did not both reach expectation")
	}
	return observed, nil
}

func waitActionDesktop(ctx context.Context, vm *EncryptedVM, locked bool) (*actionDesktopEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last error
	for {
		result, err := observeActionDesktop(ctx, vm, locked)
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil && last != nil {
			return nil, fmt.Errorf("desktop state deadline (last completed observation: %v): %w", last, err)
		}
		last = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("desktop state deadline: %w", last)
		case <-ticker.C:
		}
	}
}
