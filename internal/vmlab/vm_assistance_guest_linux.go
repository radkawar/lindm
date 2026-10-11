//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/localrpc"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

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

// prepareAssistanceDesktop logs the lab user into the golden's desktop through
// its display manager's autologin and removes first-login and idle surfaces
// that would cover the consent controls: the release-upgrade prompt, the
// welcome tour or window and initial overview, idle blanking and the
// automatic screen lock.
func prepareAssistanceDesktop(ctx context.Context, vm *EncryptedVM, desktop *labDesktop, release *platform.Release) (*actionDesktopEvidence, error) {
	if prompt := release.Lab.Session.UpgradePrompt; prompt != "" {
		if _, err := vm.Run(ctx, "sudo -n sh -eu -c "+nativeQuote("if test -f "+nativeQuote(prompt)+"; then sed -i 's/^Prompt=.*/Prompt=never/' "+nativeQuote(prompt)+"; fi"), nil); err != nil {
			return nil, fmt.Errorf("suppress release-upgrade prompt: %w", err)
		}
	}
	if _, err := prepareActionDesktop(ctx, vm, desktop, release); err != nil {
		return nil, err
	}
	if err := pollGuest(ctx, vm.guest, 3*time.Minute, desktop.name+" session startup", desktop.rootScript(desktop.ready)); err != nil {
		return nil, err
	}
	settings := desktop.quiet + `
session=$(loginctl list-sessions --no-legend --no-pager | awk -v u="$u" '$3 == u {print $1}' | while read -r id; do if test "$(loginctl show-session "$id" -p Class --value)" = user; then echo "$id"; fi; done)
test -n "$session"
loginctl unlock-session "$session"`
	if result, err := vm.guest.runResult(ctx, desktop.rootScript(settings), nil, 16<<10, time.Minute); err != nil || result.ExitCode != 0 {
		return nil, errors.Join(fmt.Errorf("configure lab %s session: exit %d: %s", desktop.name, result.ExitCode, bytes.TrimSpace(result.Stderr)), err)
	}
	if desktop.name == "gnome" {
		if err := closeGNOMEOverview(ctx, vm, desktop); err != nil {
			return nil, err
		}
	}
	return waitActionDesktop(ctx, vm, desktop, desktop.expectedLock(false))
}

func closeGNOMEOverview(ctx context.Context, vm *EncryptedVM, desktop *labDesktop) error {
	// GNOME 50 opens the overview at login, after its startup animation, which
	// can begin seconds after the shell answers on the bus. Escape on the local
	// seat closes it; the desktop counts as ready only once the overview has
	// stayed closed for five consecutive one-second observations.
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var last string
	for closed := 0; closed < 5; {
		result, err := vm.guest.runResult(ctx2, desktop.rootScript(`as gdbus call --session --dest org.gnome.Shell --object-path /org/gnome/Shell --method org.freedesktop.DBus.Properties.Get org.gnome.Shell OverviewActive`), nil, 4096, 15*time.Second)
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
				return err
			}
		}
		select {
		case <-ctx2.Done():
			return fmt.Errorf("GNOME overview did not stay closed (last: %s)", last)
		case <-time.After(time.Second):
		}
	}
	return nil
}

// waitAssistanceSessionUnit observes the packaged user unit in the autologin
// user's manager. It reports whether the unit came up on its own through
// graphical-session.target; only if it did not is it started explicitly, and
// that fact is recorded, never hidden.
func waitAssistanceSessionUnit(ctx context.Context, vm *guestVM, desktop *labDesktop, evidence *assistanceGuestEvidence) error {
	state := func() (string, string, error) {
		out, err := vm.runResult(ctx, desktop.rootScript(`as systemctl --user is-active lindm-session.service graphical-session.target || true`), nil, 4096, 15*time.Second)
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
	if _, err := vm.run(ctx, desktop.rootScript(`as systemctl --user start lindm-session.service`), nil, 4096, time.Minute); err != nil {
		return fmt.Errorf("start lindm-session.service in the user manager: %w", err)
	}
	if err := pollGuest(ctx, vm, 30*time.Second, "lindm-session.service", desktop.rootScript(`as systemctl --user is-active --quiet lindm-session.service`)); err != nil {
		return err
	}
	evidence.SessionUnitState = "active"
	return nil
}

// openAssistanceTerminal starts a terminal in the lab user's session whose
// shell reads exactly one line into path. Only keyboard input that reaches the
// focused window can produce the file.
func openAssistanceTerminal(ctx context.Context, vm *guestVM, desktop *labDesktop, release *platform.Release, path string) (string, error) {
	argv := release.Lab.Session.Terminal
	if len(argv) == 0 {
		return "", fmt.Errorf("assistance terminal is not maintained for %s", release.Name)
	}
	terminal := argv[0]
	reader := `IFS= read -r line && printf %s "$line" > ` + nativeQuote(path)
	script := `rm -f ` + nativeQuote(path) + `
setsid sudo -n -u "$u" env XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus ` + desktop.userEnv + ` ` + strings.Join(argv, " ") + ` bash -c ` + nativeQuote(reader) + ` </dev/null >/dev/null 2>&1 &`
	if _, err := vm.run(ctx, desktop.rootScript(script), nil, 4096, 30*time.Second); err != nil {
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

// installAssistanceCapture installs the release's capture stack (the agent
// package's recommended screen-capture dependencies) from its signed archive.
func installAssistanceCapture(ctx context.Context, vm *guestVM, release *platform.Release) error {
	command, err := labInstallCommand(release, release.Lab.Session.Capture)
	if err != nil {
		return fmt.Errorf("assistance capture stack: %w", err)
	}
	result, err := vm.runResult(ctx, "sudo -n env DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), nil, 1<<20, 15*time.Minute)
	if err != nil {
		return fmt.Errorf("install assistance capture stack: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("install assistance capture stack: guest exit %d: %s", result.ExitCode, bytes.TrimSpace(result.Stderr))
	}
	return nil
}

// observeAssistancePackages records the guest's capture stack versions.
func observeAssistancePackages(ctx context.Context, vm *guestVM, release *platform.Release) ([]string, error) {
	packages := strings.Join(append(slices.Clone(release.Lab.Session.Capture), packaging.PackageName), " ")
	var command string
	switch release.Native().Packages.Backend.PackageDB() {
	case platform.PackageDBDpkg:
		command = `dpkg-query -W -f='${Package}=${Version}\n' ` + packages
	case platform.PackageDBRPM:
		command = "rpm -q " + packages
	default:
		return nil, fmt.Errorf("capture stack packages are not observable on %s", release.Name)
	}
	out, err := vm.run(ctx, command, nil, 16<<10, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("observe capture stack packages: %w", err)
	}
	return strings.Fields(string(out)), nil
}

// observeAssistanceCapabilities records, before any scenario, what the
// session helper's environment, portal frontend and notification server
// expose natively. Absent interfaces are recorded, not failed: the
// scenarios assert the product's visible handling of them.
func observeAssistanceCapabilities(ctx context.Context, vm *guestVM, desktop *labDesktop) (*assistanceCapabilityEvidence, error) {
	probe := func(script string) (string, error) {
		result, err := vm.runResult(ctx, desktop.rootScript(script), nil, 64<<10, 30*time.Second)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(result.Stdout)), nil
	}
	const get = `as timeout 20 gdbus call --session --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop --method org.freedesktop.DBus.Properties.Get`
	evidence := &assistanceCapabilityEvidence{}
	var err error
	if evidence.CurrentDesktop, err = probe(`as systemctl --user show-environment | sed -n 's/^XDG_CURRENT_DESKTOP=//p'`); err != nil {
		return nil, err
	}
	interfaces, err := probe(`for p in ScreenCast:version ScreenCast:AvailableSourceTypes ScreenCast:AvailableCursorModes RemoteDesktop:version RemoteDesktop:AvailableDeviceTypes; do
printf '%s=%s\n' "$p" "$(` + get + ` org.freedesktop.portal.${p%%:*} ${p#*:} 2>&1 | tr -d '\n')"
done`)
	if err != nil {
		return nil, err
	}
	evidence.PortalInterfaces = strings.Split(interfaces, "\n")
	if evidence.NotificationServer, err = probe(`as timeout 20 gdbus call --session --dest org.freedesktop.Notifications --object-path /org/freedesktop/Notifications --method org.freedesktop.Notifications.GetServerInformation 2>&1 || true`); err != nil {
		return nil, err
	}
	if evidence.NotificationCapabilities, err = probe(`as timeout 20 gdbus call --session --dest org.freedesktop.Notifications --object-path /org/freedesktop/Notifications --method org.freedesktop.Notifications.GetCapabilities 2>&1 || true`); err != nil {
		return nil, err
	}
	return evidence, nil
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
