//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/localrpc"
)

// assistanceUserPrelude runs a command inside the autologin user's session
// manager and bus. Only the disposable lab overlay is touched.
const assistanceUserPrelude = `u=` + actionDesktopUser + `
uid=$(id -u "$u")
as() { sudo -n -u "$u" env XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus WAYLAND_DISPLAY=wayland-0 "$@"; }
`

func assistanceRootScript(script string) string {
	return "sudo -n sh -eu -c " + nativeQuote(assistanceUserPrelude+script)
}

// routeAssistanceLocalhost makes the guest resolve "localhost" to QEMU's host
// alias 10.0.2.2, as the recovery boot artifact lanes do. The signed device
// origin (https://localhost:PORT) and the relay URL (turn:localhost:PORT) then
// name the same host listeners for the guest and the host browser, and the
// TURN UDP path traverses user-mode networking rather than an SSH forward.
func routeAssistanceLocalhost(ctx context.Context, vm *guestVM) (string, error) {
	const script = `test -e /etc/hosts.lindm-lab-orig || cp -p /etc/hosts /etc/hosts.lindm-lab-orig
awk '($1 == "127.0.0.1" || $1 == "::1") { line = $1; n = 0; for (i = 2; i <= NF; i++) if ($i != "localhost" && $i != "localhost.localdomain") { line = line " " $i; n++ } if (n) print line; next } { print }' /etc/hosts.lindm-lab-orig > /etc/hosts.lindm-lab
printf '10.0.2.2 localhost\n' >> /etc/hosts.lindm-lab
chmod 0644 /etc/hosts.lindm-lab
mv /etc/hosts.lindm-lab /etc/hosts
if command -v restorecon >/dev/null; then restorecon /etc/hosts; fi
getent ahostsv4 localhost | awk '{print $1}' | sort -u`
	out, err := vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(script), nil, 4096, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("route guest localhost to the QEMU host alias: %w", err)
	}
	resolved := strings.TrimSpace(string(out))
	if resolved != "10.0.2.2" {
		return resolved, fmt.Errorf("guest localhost resolves to %q, not the QEMU host alias", resolved)
	}
	return resolved, nil
}

// configureAssistanceGuest opts the installed executor into remote assistance
// and waits for its session-helper socket. Everything else in the packaged
// configuration is preserved.
func configureAssistanceGuest(ctx context.Context, vm *guestVM) error {
	data, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 1<<20, 10*time.Second)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	config.RemoteAssistance = &agentv1.RemoteAssistanceConfig{Enabled: true}
	data, err = protojson.Marshal(config)
	if err != nil {
		return err
	}
	command := "sudo -n sh -eu -c " + nativeQuote("umask 077; cat > /etc/lindm/executor.json; chown root:root /etc/lindm/executor.json; chmod 0600 /etc/lindm/executor.json; systemctl restart lindm-executor.service")
	configured, err := vm.runResult(ctx, command, bytes.NewReader(data), 16<<10, time.Minute)
	if err != nil {
		return fmt.Errorf("enable executor remote assistance: %w", err)
	}
	if configured.ExitCode != 0 {
		return fmt.Errorf("enable executor remote assistance: exit %d: %s", configured.ExitCode, configured.Stderr)
	}
	return pollGuest(ctx, vm, time.Minute, "executor session socket", "test -S "+nativeQuote(localrpc.DefaultSessionSocketPath))
}

// pollGuest runs a no-effect probe until it exits zero or the deadline passes.
func pollGuest(ctx context.Context, vm *guestVM, timeout time.Duration, what, command string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last string
	for {
		result, err := vm.runResult(ctx, command, nil, 8<<10, 15*time.Second)
		if err == nil && result.ExitCode == 0 {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = fmt.Sprintf("exit %d: %s", result.ExitCode, bytes.TrimSpace(result.Stderr))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s deadline (last: %s): %w", what, last, ctx.Err())
		case <-ticker.C:
		}
	}
}

// prepareAssistanceDesktop logs the lab user into GNOME through GDM autologin
// and removes first-login and idle surfaces that would cover the consent
// controls: the release-upgrade prompt (Ubuntu), the welcome tour and initial
// overview (Fedora), idle blanking and the automatic screen lock.
func prepareAssistanceDesktop(ctx context.Context, vm *EncryptedVM, distribution string) (*actionDesktopEvidence, error) {
	if distribution == "ubuntu" {
		if _, err := vm.Run(ctx, `sudo -n sh -eu -c 'if test -f /etc/update-manager/release-upgrades; then sed -i "s/^Prompt=.*/Prompt=never/" /etc/update-manager/release-upgrades; fi'`, nil); err != nil {
			return nil, fmt.Errorf("suppress release-upgrade prompt: %w", err)
		}
	}
	if _, err := prepareActionDesktop(ctx, vm); err != nil {
		return nil, err
	}
	// gnome-session reaches its running phase only after the shell finished
	// startup, which is when GNOME 50 opens its login overview.
	if err := pollGuest(ctx, vm.guest, 3*time.Minute, "GNOME session startup", assistanceRootScript(`as gdbus call --session --dest org.gnome.SessionManager --object-path /org/gnome/SessionManager --method org.gnome.SessionManager.IsSessionRunning | grep -q true`)); err != nil {
		return nil, err
	}
	settings := `as gsettings set org.gnome.desktop.session idle-delay 0
as gsettings set org.gnome.desktop.screensaver lock-enabled false
as gsettings set org.gnome.settings-daemon.plugins.power idle-dim false
as gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing
as gsettings set org.gnome.shell welcome-dialog-last-shown-version 999
pkill -u "$u" -x gnome-tour || true
session=$(loginctl list-sessions --no-legend --no-pager | awk -v u="$u" '$3 == u {print $1}' | while read -r id; do if test "$(loginctl show-session "$id" -p Class --value)" = user; then echo "$id"; fi; done)
test -n "$session"
loginctl unlock-session "$session"`
	if result, err := vm.guest.runResult(ctx, assistanceRootScript(settings), nil, 16<<10, time.Minute); err != nil || result.ExitCode != 0 {
		return nil, errors.Join(fmt.Errorf("configure lab GNOME session: exit %d: %s", result.ExitCode, bytes.TrimSpace(result.Stderr)), err)
	}
	// GNOME 50 opens the overview at login, after its startup animation, which
	// can begin seconds after the shell answers on the bus. Escape on the local
	// seat closes it; the desktop counts as ready only once the overview has
	// stayed closed for five consecutive one-second observations.
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var last string
	for closed := 0; closed < 5; {
		result, err := vm.guest.runResult(ctx2, assistanceRootScript(`as gdbus call --session --dest org.gnome.Shell --object-path /org/gnome/Shell --method org.freedesktop.DBus.Properties.Get org.gnome.Shell OverviewActive`), nil, 4096, 15*time.Second)
		switch {
		case err != nil:
			closed, last = 0, err.Error()
		case result.ExitCode != 0:
			closed, last = 0, fmt.Sprintf("exit %d: %s", result.ExitCode, bytes.TrimSpace(result.Stderr))
		case strings.Contains(string(result.Stdout), "<false>"):
			closed++
		default:
			closed, last = 0, "overview open"
			if err := vm.guest.sendKey(ctx2, "esc"); err != nil {
				return nil, err
			}
		}
		select {
		case <-ctx2.Done():
			return nil, fmt.Errorf("GNOME overview did not stay closed (last: %s)", last)
		case <-time.After(time.Second):
		}
	}
	return waitActionDesktop(ctx, vm, false)
}

// waitAssistanceSessionUnit observes the packaged user unit in the autologin
// user's manager. It reports whether the unit came up on its own through
// graphical-session.target; only if it did not is it started explicitly, and
// that fact is recorded, never hidden.
func waitAssistanceSessionUnit(ctx context.Context, vm *guestVM, evidence *assistanceGuestEvidence) error {
	state := func() (string, string, error) {
		out, err := vm.runResult(ctx, assistanceRootScript(`as systemctl --user is-active lindm-session.service graphical-session.target || true`), nil, 4096, 15*time.Second)
		if err != nil {
			return "", "", err
		}
		fields := strings.Fields(string(out.Stdout))
		if len(fields) != 2 {
			return "", "", fmt.Errorf("unexpected user unit state %q", out.Stdout)
		}
		return fields[0], fields[1], nil
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		unit, target, err := state()
		if err != nil {
			return err
		}
		evidence.SessionUnitState, evidence.GraphicalSessionTarget = unit, target
		if unit == "active" {
			evidence.SessionUnitAutoStarted = true
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if _, err := vm.run(ctx, assistanceRootScript(`as systemctl --user start lindm-session.service`), nil, 4096, time.Minute); err != nil {
		return fmt.Errorf("start lindm-session.service in the user manager: %w", err)
	}
	if err := pollGuest(ctx, vm, 30*time.Second, "lindm-session.service", assistanceRootScript(`as systemctl --user is-active --quiet lindm-session.service`)); err != nil {
		return err
	}
	evidence.SessionUnitState = "active"
	return nil
}

// openAssistanceTerminal starts a terminal in the lab user's session whose
// shell reads exactly one line into path. Only keyboard input that reaches the
// focused window can produce the file.
func openAssistanceTerminal(ctx context.Context, vm *guestVM, distribution, path string) (string, error) {
	terminal := map[string]string{"ubuntu": "gnome-terminal", "fedora": "ptyxis"}[distribution]
	args := map[string]string{"ubuntu": "--", "fedora": "--new-window --"}[distribution]
	if terminal == "" {
		return "", errors.New("assistance terminal requires Ubuntu or Fedora")
	}
	reader := `IFS= read -r line && printf %s "$line" > ` + nativeQuote(path)
	script := `rm -f ` + nativeQuote(path) + `
setsid sudo -n -u "$u" env XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus WAYLAND_DISPLAY=wayland-0 ` + terminal + ` ` + args + ` bash -c ` + nativeQuote(reader) + ` </dev/null >/dev/null 2>&1 &`
	if _, err := vm.run(ctx, assistanceRootScript(script), nil, 4096, 30*time.Second); err != nil {
		return "", fmt.Errorf("open %s in the lab session: %w", terminal, err)
	}
	return terminal, pollGuest(ctx, vm, 30*time.Second, "terminal reader", "pgrep -u "+actionDesktopUser+" -f "+nativeQuote("read -r line")+" >/dev/null")
}

// waitAssistanceNonce polls for the reader's file and returns its contents.
func waitAssistanceNonce(ctx context.Context, vm *guestVM, path string, timeout time.Duration) (string, error) {
	if err := pollGuest(ctx, vm, timeout, "typed nonce", "sudo -n test -s "+nativeQuote(path)); err != nil {
		return "", err
	}
	out, err := vm.run(ctx, "sudo -n cat "+nativeQuote(path), nil, 256, 10*time.Second)
	return string(out), err
}

// waitAssistanceCaptureStopped proves the device side ended capture: no
// encoder runs in the lab user's session any more.
func waitAssistanceCaptureStopped(ctx context.Context, vm *guestVM) error {
	return pollGuest(ctx, vm, 30*time.Second, "capture shutdown", "! pgrep -u "+actionDesktopUser+" -x gst-launch-1.0 >/dev/null")
}

func lockAssistanceSession(ctx context.Context, vm *guestVM, sessionID string, lock bool) error {
	if _, err := strconv.ParseUint(sessionID, 10, 32); err != nil {
		return errors.New("invalid logind session identifier")
	}
	verb := "unlock-session"
	if lock {
		verb = "lock-session"
	}
	_, err := vm.run(ctx, "sudo -n loginctl "+verb+" "+sessionID, nil, 4096, 15*time.Second)
	return err
}

// observeAssistancePackages records the guest's capture stack versions.
func observeAssistancePackages(ctx context.Context, vm *guestVM, distribution string) ([]string, error) {
	command := `dpkg-query -W -f='${Package}=${Version}\n' xdg-desktop-portal xdg-desktop-portal-gnome pipewire gstreamer1.0-pipewire gstreamer1.0-plugins-good gnome-shell lindm-agent`
	if distribution == "fedora" {
		command = `rpm -q xdg-desktop-portal xdg-desktop-portal-gnome pipewire pipewire-gstreamer gstreamer1-plugins-good gnome-shell lindm-agent`
	}
	out, err := vm.run(ctx, command, nil, 16<<10, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("observe capture stack packages: %w", err)
	}
	return strings.Fields(string(out)), nil
}

// assistanceJournalUnits are the bounded, nonsecret journal excerpts recorded
// as evidence: executor broker, network relay and the session helper.
var assistanceJournalUnits = []struct{ name, selector string }{
	{"executor", "-u lindm-executor.service"},
	{"agent", "-u lindm-agent.service"},
	{"session-helper", "_SYSTEMD_USER_UNIT=lindm-session.service"},
}

func collectAssistanceJournals(ctx context.Context, vm *guestVM, since int64, evidence *assistanceEvidence) ([]assistanceEvidenceFile, error) {
	var files []assistanceEvidenceFile
	for _, unit := range assistanceJournalUnits {
		command := fmt.Sprintf("sudo -n journalctl -b --no-pager -o short-iso-precise --since @%d %s | tail -c 262144", since, unit.selector)
		out, err := vm.run(ctx, command, nil, 300<<10, time.Minute)
		if err != nil {
			return files, fmt.Errorf("collect %s journal: %w", unit.name, err)
		}
		bound, err := evidence.write(unit.name+" journal", "journal-"+unit.name+".txt", out)
		if err != nil {
			return files, err
		}
		files = append(files, bound)
	}
	return files, nil
}
