//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// The OS update lane installs a real pending security update from the guest's
// own signed distribution repositories inside a lindm maintenance window that
// the owned systemd timer opens, and requires the logind reboot the policy
// schedules to actually happen. The policy zone deliberately differs from the
// guest's UTC clock so calendar rendering crosses a real IANA conversion.
const (
	osUpdateLabZone          = "Europe/Berlin"
	osUpdateLabNotice        = "lindm lab maintenance reboot"
	osUpdateLabRebootMinutes = 5
	osUpdateWindowLead       = 4 * time.Minute
	osUpdateWindowMinutes    = 45
	// A real security transaction on an aged cloud image can be large; the
	// runner unit's own TimeoutStartSec remains the native bound.
	osUpdateRunDeadline = 75 * time.Minute
)

var (
	osUpdateScheduled = regexp.MustCompile(`^\(st\) "([a-z-]*)" ([0-9]+)$`)
	// errOSUpdateUnitTiming marks a transient systemd timing read failure.
	errOSUpdateUnitTiming = errors.New("systemd unit timing unavailable")
)

func osUpdateDesired(zone *time.Location, selection resourcev1.UpdateSelection, start time.Time, deferral uint32) *resourcev1.ResourceDesiredState {
	local := start.In(zone)
	weekday := resourcev1.Weekday(int32(local.Weekday()+6)%7 + 1)
	return &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"},
		State: &resourcev1.ResourceDesiredState_OsUpdate{OsUpdate: &resourcev1.OSUpdateDesired{
			Selection:    selection,
			Maintenance:  &resourcev1.MaintenanceWindow{TimeZone: osUpdateLabZone, Weekdays: []resourcev1.Weekday{weekday}, LocalStartMinute: uint32(local.Hour()*60 + local.Minute()), DurationMinutes: osUpdateWindowMinutes},
			RebootPolicy: &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED, MaxDelayMinutes: osUpdateLabRebootMinutes, Notice: osUpdateLabNotice},
			DeferralDays: deferral,
		}},
	}
}

// osUpdateWindowStart is the next whole minute at least the lead time ahead.
func osUpdateWindowStart(now time.Time) time.Time {
	return now.Add(osUpdateWindowLead + time.Minute - 1).Truncate(time.Minute)
}

// Native prerequisites of each backend are installed from the distribution's
// own signed repositories as fixture setup, then metadata is refreshed so the
// independent pending-update oracle sees the current repository state.
func osUpdatePrerequisiteScript(rpm resourcePackaging) string {
	switch {
	case !rpm.rpm:
		return "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l; apt-get -q update; apt-get -y -q install --no-upgrade unattended-upgrades needrestart update-notifier-common; dpkg-query -W unattended-upgrades needrestart"
	case rpm.dnf4:
		return "dnf -y -q install dnf-automatic dnf-plugins-core; rpm -q dnf-automatic dnf-plugins-core"
	default:
		return "dnf5 -y -q install dnf5-plugin-automatic dnf5-plugins; rpm -q dnf5-plugin-automatic dnf5-plugins"
	}
}

// osUpdatePendingOracle counts pending updates with the distribution's own
// command, independent of the runner's parser and freshly refreshed.
func osUpdatePendingOracle(rpm resourcePackaging, security bool) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		name := "native-pending-all"
		if security {
			name = "native-pending-security"
		}
		var command string
		switch {
		case !rpm.rpm:
			filter := "cat"
			if security {
				filter = "grep -- '-security'"
			}
			command = "apt-get -qq update; apt-get -s -o Debug::NoLocking=1 dist-upgrade | grep '^Inst ' | " + filter + " > /tmp/lindm-lab-pending || true; printf 'pending %s\\n' \"$(wc -l < /tmp/lindm-lab-pending)\"; cat /tmp/lindm-lab-pending"
		default:
			dnf := "dnf5"
			if rpm.dnf4 {
				dnf = "dnf"
			}
			flag := ""
			if security {
				flag = " --security"
			}
			command = "set +e; " + dnf + " -q --refresh check-update" + flag + " > /tmp/lindm-lab-pending; rc=$?; set -e; test $rc -eq 0 -o $rc -eq 100; printf 'pending %s\\n' \"$(grep -cE '^[^[:space:]]+[.][^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+' /tmp/lindm-lab-pending || true)\"; cat /tmp/lindm-lab-pending"
		}
		return resourceOracle(ctx, vm, name, command)
	}
}

func osUpdatePendingCount(record VMResourceNativeRecord) (int, error) {
	line := nativeRecordLine(record, "pending ")
	count, err := strconv.Atoi(strings.TrimPrefix(line, "pending "))
	if line == "" || err != nil || count < 0 {
		return 0, fmt.Errorf("pending oracle %s lacks a count", record.Name)
	}
	return count, nil
}

// osUpdatePackageOracle binds the complete installed package database.
func osUpdatePackageOracle(rpm resourcePackaging) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		list := "dpkg-query -W -f '${Package}:${Architecture} ${Version} ${db:Status-Abbrev}\\n'"
		if rpm.rpm {
			list = "rpm -qa --qf '%{NAME}.%{ARCH} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n'"
		}
		command := list + " | LC_ALL=C sort > /tmp/lindm-lab-packages; printf 'packages %s\\n' \"$(sha256sum < /tmp/lindm-lab-packages | cut -d' ' -f1)\"; wc -l < /tmp/lindm-lab-packages; uname -r"
		if !rpm.rpm {
			command += "; dpkg-query -W -f 'version ${Package} ${Version}\\n' apt unattended-upgrades needrestart update-notifier-common || true"
		}
		return resourceOracle(ctx, vm, "native-package-database", command)
	}
}

// osUpdateConfigOracle reads every fixed owned path, the loaded timer and the
// effective APT periodic setting; refusal scenarios compare its exact bytes.
func osUpdateConfigOracle(rpm resourcePackaging) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		var command strings.Builder
		for _, kind := range resource.OSUpdateNativeFiles() {
			// Each backend owns only its own native configuration file.
			if (rpm.rpm && kind == resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC) || ((!rpm.rpm || rpm.dnf4) && kind == resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC) {
				continue
			}
			path := nativeQuote(resource.OSUpdateNativePath(kind))
			command.WriteString("if test -e " + path + "; then stat -c 'file %n %a %U %G %s' " + path + "; sha256sum " + path + "; else echo absent " + path + "; fi; ")
		}
		command.WriteString("systemctl show -p LoadState -p ActiveState -p FragmentPath -p TimersCalendar " + resource.OSUpdateTimerUnit + "; ")
		if rpm.rpm {
			command.WriteString("systemctl show -p UnitFileState -p ActiveState dnf-automatic.timer dnf5-automatic.timer 2>/dev/null || true")
		} else {
			command.WriteString("printf 'apt-periodic %s\\n' \"$(apt-config shell V APT::Periodic::Unattended-Upgrade)\"")
		}
		return resourceOracle(ctx, vm, "native-update-policy-configuration", command.String())
	}
}

// osUpdateInstalledOracle additionally requires the owned objects present and
// systemd's loaded calendar in the policy zone.
func osUpdateInstalledOracle(rpm resourcePackaging, zone *time.Location, start time.Time) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		record, err := osUpdateConfigOracle(rpm)(ctx, vm)
		if err != nil {
			return record, err
		}
		text := string(record.Bytes)
		local := start.In(zone)
		calendar := local.Format("15:04:05") + " " + osUpdateLabZone
		if strings.Contains(text, "absent ") || !strings.Contains(text, "ActiveState=active") || !strings.Contains(text, "FragmentPath="+resource.OSUpdateTimerPath) || !strings.Contains(text, calendar) {
			return record, fmt.Errorf("owned update policy objects or timer calendar %q not installed: %s", calendar, text)
		}
		if !rpm.rpm && !strings.Contains(text, "apt-periodic V='0'") {
			return record, errors.New("APT periodic unattended upgrades remain enabled outside the window")
		}
		return record, nil
	}
}

// osUpdateUnitTimes reads systemd's realtime timer trigger and service exit.
// Package scriptlets may re-execute systemd mid-transaction, so callers treat
// a failed read as transient; the error keeps the guest's stderr for evidence.
func osUpdateUnitTimes(ctx context.Context, vm *guestVM) (trigger, exit time.Time, active string, err error) {
	result, err := vm.runResult(ctx, "busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/lindm_2dos_2dupdate_2etimer org.freedesktop.systemd1.Timer LastTriggerUSec; busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/lindm_2dos_2dupdate_2eservice org.freedesktop.systemd1.Service ExecMainExitTimestamp; busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/lindm_2dos_2dupdate_2eservice org.freedesktop.systemd1.Unit ActiveState", nil, 4096, 15*time.Second)
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	data := result.Stdout
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if result.ExitCode != 0 || len(bytes.TrimSpace(result.Stderr)) != 0 || len(lines) != 3 {
		return time.Time{}, time.Time{}, "", fmt.Errorf("%w: exit %d stdout %q stderr %q", errOSUpdateUnitTiming, result.ExitCode, data, result.Stderr)
	}
	usec := func(line string) (time.Time, error) {
		value, err := strconv.ParseUint(strings.TrimPrefix(line, "t "), 10, 64)
		if err != nil || !strings.HasPrefix(line, "t ") {
			return time.Time{}, fmt.Errorf("unexpected systemd timestamp %q", line)
		}
		if value == 0 {
			return time.Time{}, nil
		}
		return time.UnixMicro(int64(value)), nil
	}
	if trigger, err = usec(lines[0]); err != nil {
		return
	}
	if exit, err = usec(lines[1]); err != nil {
		return
	}
	return trigger, exit, strings.Trim(strings.TrimPrefix(lines[2], "s "), `"`), nil
}

// waitOSUpdateWindowRun requires the owned timer itself to fire at or after the
// window start and the runner service to finish after that trigger.
func waitOSUpdateWindowRun(ctx context.Context, vm *guestVM, start time.Time, deadline time.Duration) (VMResourceNativeRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Until(start)+deadline)
	defer cancel()
	var last error
	for {
		trigger, exit, active, err := osUpdateUnitTimes(ctx, vm)
		if err != nil && !sshBootNotReady(err) && !errors.Is(err, errOSUpdateUnitTiming) {
			return VMResourceNativeRecord{}, err
		}
		last = err
		if err == nil && !trigger.Before(start) && !exit.Before(trigger) && (active == "inactive" || active == "failed") {
			if trigger.After(start.Add(2 * time.Minute)) {
				return VMResourceNativeRecord{}, fmt.Errorf("timer fired at %s, not at window start %s", trigger, start)
			}
			return resourceOracle(ctx, vm, "native-window-run", fmt.Sprintf("printf 'window-start %d\\ntimer-trigger %d\\nservice-exit %d\\nactive %s\\n'; systemctl show -p Result -p ExecMainStatus %s; journalctl -b -u %s --no-pager -o short-iso-precise | tail -n 120", start.Unix(), trigger.Unix(), exit.Unix(), active, resource.OSUpdateServiceUnit, resource.OSUpdateServiceUnit))
		}
		if err := lifecycleDelay(ctx, 5*time.Second); err != nil {
			return VMResourceNativeRecord{}, fmt.Errorf("maintenance window run did not complete: %w (last probe: %v)", err, last)
		}
	}
}

// freshHostInventory establishes the presence that device actions require: a
// host observation received within the last 3 minutes. Hosts are admitted at
// most every 5 minutes and collected every 10, so an older observation is
// renewed by restarting the relay (it collects on start) once the admission
// interval has passed; restarting earlier would only be rate limited.
func freshHostInventory(ctx context.Context, r *resourceDispatch) error {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Minute)
	defer cancel()
	restarted := time.Time{}
	for {
		device, err := r.control.GetDevice(ctx, r.device)
		if err != nil {
			return err
		}
		host := device.GetHost().GetReceivedAt()
		seen := device.GetDevice().GetLastSeenAt()
		if host != nil && seen != nil && time.Since(host.AsTime()) < 3*time.Minute && time.Since(seen.AsTime()) < 30*time.Second {
			return nil
		}
		if (host == nil || time.Since(host.AsTime()) > 5*time.Minute+15*time.Second) && time.Since(restarted) > 2*time.Minute {
			if err := lifecycleCommand(ctx, r.vm, "restart relay for fresh host inventory", "systemctl restart lindm-agent.service"); err != nil {
				return err
			}
			restarted = time.Now()
		}
		if err := lifecycleDelay(ctx, 5*time.Second); err != nil {
			return fmt.Errorf("fresh host inventory: %w", err)
		}
	}
}

// refreshPublishedInventory dispatches the real signed refresh-inventory action,
// whose challenge admits a full host observation inside the server's 5-minute
// host admission interval. The server-accepted action is scenario evidence.
func refreshPublishedInventory(ctx context.Context, r *resourceDispatch, s *VMResourceScenario) error {
	if err := freshHostInventory(ctx, r); err != nil {
		return err
	}
	identity, err := readVMConnectionIdentity(ctx, r.vm)
	if err != nil {
		return err
	}
	request := actionRequestFor(r.device, identity.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})
	request.Reason = "disposable patch status inventory refresh"
	dispatched, _, err := dispatchNativeAction(ctx, r.vm, r.control.session, request, nil, false)
	if dispatched != nil {
		s.DeviceActions = append(s.DeviceActions, dispatched)
	}
	return err
}

// serverPatchStatus publishes fresh host inventory and waits for the server's
// copy of the patch status to satisfy accept.
func serverPatchStatus(ctx context.Context, r *resourceDispatch, s *VMResourceScenario, name string, accept func(*agentv1.PatchStatusObservation) error) (*agentv1.PatchStatusObservation, VMResourceNativeRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var last error
	for {
		if err := refreshPublishedInventory(ctx, r, s); err != nil {
			return nil, VMResourceNativeRecord{}, fmt.Errorf("server patch status %s: %w (last: %v)", name, err, last)
		}
		device, err := r.control.GetDevice(ctx, r.device)
		if err != nil {
			return nil, VMResourceNativeRecord{}, err
		}
		status := device.GetHost().GetObservation().GetDetails().GetPatchStatus()
		last = errors.New("no patch status published")
		if status != nil {
			if last = accept(status); last == nil {
				data, err := protojson.Marshal(status)
				if err != nil {
					return nil, VMResourceNativeRecord{}, err
				}
				return status, resourceNativeRecord("server-published-patch-status-"+name, data), nil
			}
		}
		// A stale executor status starts the offline status unit; give it time.
		if err := lifecycleDelay(ctx, 20*time.Second); err != nil {
			return nil, VMResourceNativeRecord{}, fmt.Errorf("server patch status %s: %w (last: %v)", name, err, last)
		}
	}
}

// wallCapture is a real PAM login on a systemd-allocated pty. Its logind
// session must identify that terminal before native wall delivery is tested.
type wallCapture struct {
	client   *ssh.Client
	session  *ssh.Session
	mu       sync.Mutex
	output   bytes.Buffer
	done     chan struct{}
	vm       *guestVM
	unit     string
	closed   bool
	closeErr error
}

func (w *wallCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.output.Len()+len(p) > 256<<10 {
		return len(p), nil
	}
	return w.output.Write(p)
}

func (w *wallCapture) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.String()
}

func (w *wallCapture) Close() error {
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w.closeErr = lifecycleCommand(ctx, w.vm, "stop wall login fixture", "if test \"$(systemctl show --value -p LoadState "+w.unit+")\" != not-found; then systemctl stop "+w.unit+"; fi")
	for w.closeErr == nil {
		record, err := resourceOracle(ctx, w.vm, "remaining-wall-login-sessions", "loginctl --no-pager --no-legend list-sessions")
		if err != nil {
			w.closeErr = err
			break
		}
		if !wallSessionListed(string(record.Bytes), wallSessionID(w.text())) {
			break
		}
		w.closeErr = lifecycleDelay(ctx, 100*time.Millisecond)
	}
	for _, err := range []error{w.session.Close(), w.client.Close()} {
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			w.closeErr = errors.Join(w.closeErr, err)
		}
	}
	<-w.done
	return w.closeErr
}

func openWallCapture(ctx context.Context, vm *guestVM) (_ *wallCapture, resultErr error) {
	dial, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dial, "tcp4", vm.address)
	if err != nil {
		return nil, err
	}
	config := *vm.config
	sshConn, channels, requests, err := ssh.NewClientConn(conn, vm.address, &config)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	client := ssh.NewClient(sshConn, channels, requests)
	var capture *wallCapture
	defer func() {
		if resultErr != nil && capture == nil {
			resultErr = errors.Join(resultErr, client.Close())
		}
	}()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	if err := session.RequestPty("xterm", 50, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return nil, err
	}
	w := &wallCapture{client: client, session: session, done: make(chan struct{}), vm: vm, unit: "lindm-lab-wall-" + uuid.NewString() + ".service"}
	session.Stdout = w
	session.Stderr = w
	command := "export SYSTEMD_COLORS=0 SYSTEMD_PAGER=cat; printf '\\nterminal %s\\nsession-id %s\\n' \"$(tty)\" \"$XDG_SESSION_ID\"; loginctl --no-pager show-session \"$XDG_SESSION_ID\" -p TTY -p Type -p Remote -p Class; printf 'session-ready\\n'; exec sleep 7200"
	if err := session.Start("sudo -n systemd-run --quiet --wait --collect --pty --unit=" + w.unit + " --uid=" + labUser + " --property=PAMName=login /bin/sh -eu -c " + nativeQuote(command)); err != nil {
		capture = w
		close(w.done)
		return nil, errors.Join(err, w.Close())
	}
	go func() { _ = session.Wait(); close(w.done) }()
	capture = w
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		text := w.text()
		if wallSessionReady(text) {
			return w, nil
		}
		select {
		case <-w.done:
			return nil, errors.Join(fmt.Errorf("wall fixture exited before login: %q", text), w.Close())
		default:
		}
		if err := lifecycleDelay(ctx, 100*time.Millisecond); err != nil {
			return nil, errors.Join(err, w.Close())
		}
	}
	return nil, errors.Join(fmt.Errorf("wall fixture login timed out: %q", w.text()), w.Close())
}

// wallSessionReady binds the captured pty to a local, user-class logind session.
// An SSH pty alone is insufficient when sshd does not report its TTY to PAM.
func wallSessionReady(text string) bool {
	var terminal, tty, kind, remote, class string
	var ready bool
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "session-ready":
			ready = true
		case strings.HasPrefix(line, "terminal "):
			terminal = strings.TrimPrefix(line, "terminal ")
		case strings.HasPrefix(line, "TTY="):
			tty = strings.TrimPrefix(line, "TTY=")
		case strings.HasPrefix(line, "Type="):
			kind = strings.TrimPrefix(line, "Type=")
		case strings.HasPrefix(line, "Remote="):
			remote = strings.TrimPrefix(line, "Remote=")
		case strings.HasPrefix(line, "Class="):
			class = strings.TrimPrefix(line, "Class=")
		}
	}
	return ready && wallSessionID(text) != "" && strings.HasPrefix(terminal, "/dev/pts/") && tty != "" &&
		strings.TrimPrefix(terminal, "/dev/") == strings.TrimPrefix(tty, "/dev/") &&
		kind == "tty" && remote == "no" && class == "user"
}

func wallSessionID(text string) string {
	for line := range strings.SplitSeq(text, "\n") {
		if id, ok := strings.CutPrefix(strings.TrimSpace(line), "session-id "); ok {
			return id
		}
	}
	return ""
}

func wallSessionListed(text, id string) bool {
	if id == "" {
		return false
	}
	for line := range strings.SplitSeq(text, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == id {
			return true
		}
	}
	return false
}

// logindScheduleOracle reads logind's accepted schedule and wall message.
func logindScheduleOracle(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, string, time.Time, error) {
	record, err := resourceOracle(ctx, vm, "native-logind-scheduled-shutdown", "busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ScheduledShutdown; busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager WallMessage; cat /proc/sys/kernel/random/boot_id")
	if err != nil {
		return record, "", time.Time{}, err
	}
	match := osUpdateScheduled.FindStringSubmatch(strings.SplitN(string(record.Bytes), "\n", 2)[0])
	if match == nil {
		return record, "", time.Time{}, fmt.Errorf("unexpected logind schedule: %q", record.Bytes)
	}
	usec, err := strconv.ParseUint(match[2], 10, 64)
	if err != nil {
		return record, "", time.Time{}, err
	}
	when := time.Time{}
	if usec != 0 && usec != ^uint64(0) {
		when = time.UnixMicro(int64(usec))
	}
	return record, match[1], when, nil
}

// nativeRebootOracle is the distribution's own reboot-required signal.
func nativeRebootOracle(rpm resourcePackaging) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		command := "if test -e /run/reboot-required; then echo reboot-required yes; cat /run/reboot-required.pkgs 2>/dev/null || true; else echo reboot-required no; fi; uname -r; cat /proc/sys/kernel/random/boot_id"
		if rpm.rpm {
			dnf := "dnf5"
			if rpm.dnf4 {
				dnf = "dnf"
			}
			command = "set +e; " + dnf + " -q needs-restarting -r; rc=$?; set -e; test $rc -le 1; if test $rc -eq 1; then echo reboot-required yes; else echo reboot-required no; fi; uname -r; cat /proc/sys/kernel/random/boot_id"
		}
		return resourceOracle(ctx, vm, "native-reboot-required", command)
	}
}

// enableOSUpdateProvider adds the root-local resource and patch-now opt-ins.
func enableOSUpdateProvider(ctx context.Context, vm *guestVM) error {
	config, err := readGuestAgentConfig(ctx, vm)
	if err != nil {
		return err
	}
	config.OsUpdateProvider = &agentv1.NativeOSUpdateProviderConfig{Enabled: true}
	if config.ActionProvider == nil {
		config.ActionProvider = new(agentv1.DeviceActionProviderConfig)
	}
	config.ActionProvider.AllowPatchNow = true
	if err := writeGuestAgentConfig(ctx, vm, config); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, vm, "restart executor with update policy opt-in", "systemctl restart lindm-executor.service"); err != nil {
		return err
	}
	_, err = waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
	return err
}

// osUpdateConflictScripts enable a competing native scheduler and later restore
// its exact prior unit-file state (masked or not), so the release oracle can
// compare byte-for-byte with the pre-lane baseline.
func osUpdateConflictScripts(rpm resourcePackaging) (create, remove string) {
	if !rpm.rpm {
		return `printf 'APT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/99zz-lindm-lab-conflict`, "rm -f /etc/apt/apt.conf.d/99zz-lindm-lab-conflict"
	}
	unit := "dnf5-automatic.timer"
	if rpm.dnf4 {
		unit = "dnf-automatic.timer"
	}
	state := "/run/lindm-lab-conflict-unit-state"
	return "systemctl is-enabled " + unit + " > " + state + " 2>/dev/null || true; systemctl unmask " + unit + "; systemctl enable --now " + unit,
		"systemctl disable --now " + unit + "; if test \"$(cat " + state + ")\" = masked; then systemctl mask " + unit + "; fi; rm -f " + state
}

// osUpdateDiagnostics adds the runner units' journals and native cache state to
// a failed scenario; it is diagnostic context, never a pass oracle.
func osUpdateDiagnostics(rpm resourcePackaging) func(context.Context, *guestVM) VMResourceNativeRecord {
	return func(ctx context.Context, vm *guestVM) VMResourceNativeRecord {
		cache := "ls -la /var/lib/apt/lists | tail -n 40"
		if rpm.rpm {
			cache = "ls -la /var/cache/libdnf5 /var/cache/dnf 2>&1 | tail -n 60; ls -la /etc/yum.repos.d"
		}
		command := "journalctl -b --no-pager -o short-iso-precise -u lindm-os-update.service -u lindm-os-update-now.service -u lindm-os-update-status.service | tail -n 200; ls -la /var/lib/lindm/os-update /run/lindm/os-update; ls -laZi " + resource.OSUpdatePolicyPath + " " + resource.OSUpdateTimerPath + " " + resource.OSUpdateWantsPath + " " + resource.OSUpdateAPTPeriodPath + " " + resource.OSUpdateDNF5AutomaticPath + " 2>&1; systemctl show -p ActiveState -p TimersCalendar -p FragmentPath " + resource.OSUpdateTimerUnit + "; " + cache
		result, err := vm.runResult(ctx, "sudo -n /bin/sh -c "+nativeQuote(command)+" 2>&1", nil, 256<<10, time.Minute)
		if err != nil {
			return resourceNativeRecord("failure-diagnostic-os-update", []byte(err.Error()))
		}
		return resourceNativeRecord("failure-diagnostic-os-update", result.Stdout)
	}
}

func exerciseResourceOSUpdate(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	vm := r.vm
	if r.awaitReboot == nil {
		return errors.New("update policy lane requires a guest-initiated reboot boundary")
	}
	diagnose := osUpdateDiagnostics(rpm)
	r.diagnostics = func(ctx context.Context) []VMResourceNativeRecord {
		return []VMResourceNativeRecord{diagnose(ctx, r.vm)}
	}
	defer func() { r.diagnostics = nil }()
	zone, err := time.LoadLocation(osUpdateLabZone)
	if err != nil {
		return fmt.Errorf("load lab policy zone: %w", err)
	}
	if err := lifecycleCommand(ctx, vm, "install native automatic-update prerequisites", osUpdatePrerequisiteScript(rpm)); err != nil {
		return err
	}
	if err := enableOSUpdateProvider(ctx, vm); err != nil {
		return err
	}
	names := []string{}
	pending, err := osUpdatePendingOracle(rpm, true)(ctx, vm)
	if err != nil {
		return err
	}
	if count, err := osUpdatePendingCount(pending); err != nil || count == 0 {
		return errors.Join(errors.New("pinned image has no real pending security update to qualify against"), err)
	}
	baseline, err := osUpdateConfigOracle(rpm)(ctx, vm)
	if err != nil {
		return err
	}

	// A competing native scheduler is refused before any native effect.
	create, remove := osUpdateConflictScripts(rpm)
	if err := lifecycleCommand(ctx, vm, "enable competing native automatic-update scheduler", create); err != nil {
		return err
	}
	r.fresh()
	if err := resourceRefusalStep(ctx, r, evidence, "competing-native-scheduler-refused", osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, osUpdateWindowStart(time.Now()), 7), resourceCreatePolicy(), withVM(vm, osUpdateConfigOracle(rpm))); err != nil {
		return err
	}
	names = append(names, "competing-native-scheduler-refused")
	if err := lifecycleCommand(ctx, vm, "remove competing native automatic-update scheduler", remove); err != nil {
		return err
	}

	// Policy with a deferral: install, outside-window skip, window deferral.
	r.fresh()
	start := osUpdateWindowStart(time.Now())
	deferred := osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, start, 7)
	if err := resourceStep(ctx, r, evidence, "policy-installs-window-timer", deferred, resourceCreatePolicy(), false, withVM(vm, osUpdateInstalledOracle(rpm, zone, start))); err != nil {
		return err
	}
	names = append(names, "policy-installs-window-timer")
	if err := osUpdateOutsideWindow(ctx, r, rpm, evidence, start); err != nil {
		return err
	}
	names = append(names, "start-outside-window-skipped")
	if err := osUpdateDeferralHolds(ctx, r, rpm, evidence, start); err != nil {
		return err
	}
	names = append(names, "window-deferral-holds-updates")

	// No deferral: the real security update installs inside the window and
	// the policy's logind reboot happens.
	start = osUpdateWindowStart(time.Now())
	immediate := osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, start, 0)
	if err := resourceStep(ctx, r, evidence, "policy-reconciles-without-deferral", immediate, resourceCreatePolicy(), false, withVM(vm, osUpdateInstalledOracle(rpm, zone, start))); err != nil {
		return err
	}
	names = append(names, "policy-reconciles-without-deferral")
	if err := osUpdateWindowInstallsAndReboots(ctx, r, rpm, evidence, start); err != nil {
		return err
	}
	names = append(names, "window-installs-security-update", "scheduled-reboot-executes")
	if err := resourceStep(ctx, r, evidence, "repeat-after-reboot", immediate, resourceCreatePolicy(), true, withVM(vm, osUpdateInstalledOracle(rpm, zone, start))); err != nil {
		return err
	}
	names = append(names, "repeat-after-reboot")
	if err := osUpdatePatchNow(ctx, r, rpm, evidence); err != nil {
		return err
	}
	names = append(names, "patch-now-all-updates", "fleet-patch-compliance")
	if err := resourceReleaseStep(ctx, r, evidence, "release-removes-policy", immediate.GetRef(), withVM(vm, func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		record, err := osUpdateConfigOracle(rpm)(ctx, vm)
		if err == nil && !bytes.Equal(record.Bytes, baseline.Bytes) {
			err = fmt.Errorf("release did not restore the native baseline: before %q after %q", baseline.Bytes, record.Bytes)
		}
		return record, err
	})); err != nil {
		return err
	}
	names = append(names, "release-removes-policy")
	evidence.Unproven = []string{
		"graphical desktop notification (headless cloud guest; covered by the real session-bus test only)",
		"maintenance window end during a running transaction, DST transitions on a real clock (unit-tested only)",
		"block-inhibitor deferral of the scheduled reboot",
	}
	return qualifyResourceEvidence(evidence, names)
}

func osUpdateOutsideWindow(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence, start time.Time) error {
	s, fail := firewallScenario(ctx, r, evidence, "start-outside-window-skipped")
	before, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if time.Until(start) < time.Minute {
		return fail(errors.New("window opened before the outside-window probe"))
	}
	// Simulates a Persistent= catch-up or manual start before the window.
	if err := lifecycleCommand(ctx, r.vm, "start update runner before the window opens", "systemctl start "+resource.OSUpdateServiceUnit); err != nil {
		return fail(err)
	}
	after, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(before.Bytes, after.Bytes) {
		return fail(errors.New("runner changed packages outside the maintenance window"))
	}
	_, status, err := serverPatchStatus(ctx, r, s, "outside-window", func(p *agentv1.PatchStatusObservation) error {
		run := p.GetLastRun()
		if run.GetTrigger() != agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_MAINTENANCE_WINDOW || run.GetResult() != agentv1.PatchRunResult_PATCH_RUN_RESULT_SKIPPED_OUTSIDE_WINDOW || run.GetFinishedAt().AsTime().Before(s.StartedAt) {
			return fmt.Errorf("last run %v is not this outside-window skip", run)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	before.Name, after.Name = "before-"+before.Name, "after-"+after.Name
	passScenario(s, before, after, status)
	return nil
}

func osUpdateDeferralHolds(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence, start time.Time) error {
	s, fail := firewallScenario(ctx, r, evidence, "window-deferral-holds-updates")
	before, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	run, err := waitOSUpdateWindowRun(ctx, r.vm, start, 30*time.Minute)
	if err != nil {
		return fail(err)
	}
	after, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(before.Bytes, after.Bytes) {
		return fail(errors.New("deferred window run changed packages"))
	}
	_, status, err := serverPatchStatus(ctx, r, s, "deferred", func(p *agentv1.PatchStatusObservation) error {
		last := p.GetLastRun()
		if last.GetTrigger() != agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_MAINTENANCE_WINDOW || last.GetResult() != agentv1.PatchRunResult_PATCH_RUN_RESULT_DEFERRED || last.GetStartedAt().AsTime().Before(start) || last.GetDeferredPackages() == 0 || last.GetUpdatedPackages() != 0 {
			return fmt.Errorf("last run %v is not a deferral of this window", last)
		}
		if !p.GetAvailable() || p.GetDeferredUpdates() == 0 || !p.GetPolicyInstalled() {
			return fmt.Errorf("patch status %v lacks deferred pending updates", p)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	before.Name, after.Name = "before-"+before.Name, "after-"+after.Name
	passScenario(s, before, run, after, status)
	return nil
}

func osUpdateWindowInstallsAndReboots(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence, start time.Time) (resultErr error) {
	s, fail := firewallScenario(ctx, r, evidence, "window-installs-security-update")
	wall, err := openWallCapture(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	defer func() { resultErr = errors.Join(resultErr, wall.Close()) }()
	before, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	pendingBefore, err := osUpdatePendingOracle(rpm, true)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	countBefore, err := osUpdatePendingCount(pendingBefore)
	if err != nil || countBefore == 0 {
		return fail(errors.Join(errors.New("no pending security update before the window"), err))
	}
	run, err := waitOSUpdateWindowRun(ctx, r.vm, start, osUpdateRunDeadline)
	if err != nil {
		return fail(err)
	}
	finished := time.Now()
	after, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if bytes.Equal(before.Bytes, after.Bytes) {
		return fail(errors.New("window run installed no package"))
	}
	reboot, err := nativeRebootOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if nativeRecordLine(reboot, "reboot-required ") != "reboot-required yes" {
		return fail(errors.New("native oracle requires no reboot after the security update; the scheduled reboot cannot be qualified on this image"))
	}
	schedule, kind, when, err := logindScheduleOracle(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if kind != "reboot" || when.IsZero() || when.Before(start) || when.After(finished.Add(osUpdateLabRebootMinutes*time.Minute+time.Minute)) {
		return fail(fmt.Errorf("logind schedule %s at %s does not follow the policy", kind, when))
	}
	status, statusRecord, err := serverPatchStatus(ctx, r, s, "installed", func(p *agentv1.PatchStatusObservation) error {
		last := p.GetLastRun()
		if last.GetTrigger() != agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_MAINTENANCE_WINDOW || last.GetResult() != agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED || last.GetStartedAt().AsTime().Before(start) || last.GetUpdatedPackages() == 0 || !last.GetRebootRequired() || last.GetRebootScheduledFor() == nil {
			return fmt.Errorf("last run %v is not this window's installation", last)
		}
		if !p.GetRebootRequired() || p.GetLastSuccessfulUpdate() == nil || !p.GetLastSuccessfulUpdate().AsTime().Equal(last.GetFinishedAt().AsTime()) {
			return fmt.Errorf("patch status %v does not report the installed run", p)
		}
		if last.GetNotifiedSessions() != 0 {
			return errors.New("headless terminal-only fixture claimed graphical notification delivery")
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	if delta := status.GetLastRun().GetRebootScheduledFor().AsTime().Sub(when); delta > time.Second || delta < -time.Second {
		return fail(fmt.Errorf("reported reboot %s differs from logind %s", status.GetLastRun().GetRebootScheduledFor().AsTime(), when))
	}
	if delay := when.Sub(status.GetLastRun().GetFinishedAt().AsTime()); delay < (osUpdateLabRebootMinutes-1)*time.Minute || delay > (osUpdateLabRebootMinutes+1)*time.Minute {
		return fail(fmt.Errorf("reboot delay %s does not follow the %d minute policy", delay, osUpdateLabRebootMinutes))
	}
	notified := ""
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if text := wall.text(); strings.Contains(text, osUpdateLabNotice) {
			notified = text
			break
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return fail(err)
		}
	}
	if notified == "" {
		return fail(fmt.Errorf("logged-in terminal received no wall notice: %q", wall.text()))
	}
	if err := wall.Close(); err != nil {
		return fail(fmt.Errorf("clean up wall login fixture: %w", err))
	}
	before.Name, after.Name = "before-"+before.Name, "after-"+after.Name
	passScenario(s, pendingBefore, before, run, after, reboot, schedule, resourceNativeRecord("native-pty-wall-notice", []byte(notified)), statusRecord)

	executed, failExecuted := firewallScenario(ctx, r, evidence, "scheduled-reboot-executes")
	lines := strings.Split(strings.TrimSpace(string(schedule.Bytes)), "\n")
	previous := lines[len(lines)-1]
	if err := r.awaitReboot(ctx, previous, time.Until(when)+8*time.Minute); err != nil {
		return failExecuted(err)
	}
	rebooted := time.Now()
	if rebooted.Before(when.Add(-30 * time.Second)) {
		return failExecuted(fmt.Errorf("guest rebooted at %s before the scheduled %s", rebooted, when))
	}
	cleared, err := nativeRebootOracle(rpm)(ctx, r.vm)
	if err != nil {
		return failExecuted(err)
	}
	if nativeRecordLine(cleared, "reboot-required ") != "reboot-required no" {
		return failExecuted(errors.New("native oracle still requires a reboot in the new boot"))
	}
	if _, err := waitGuestExecutorReady(ctx, r.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return failExecuted(err)
	}
	_, fresh, err := serverPatchStatus(ctx, r, executed, "after-reboot", func(p *agentv1.PatchStatusObservation) error {
		if !p.GetAvailable() || p.GetRebootRequired() || p.GetBootId() == previous || p.GetObservedAt().AsTime().Before(rebooted.Add(-time.Minute)) {
			return fmt.Errorf("patch status %v is not a fresh post-reboot observation", p)
		}
		return nil
	})
	if err != nil {
		return failExecuted(err)
	}
	passScenario(executed, cleared, fresh)
	return nil
}

func osUpdatePatchNow(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	s, fail := firewallScenario(ctx, r, evidence, "patch-now-all-updates")
	before, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	pendingBefore, err := osUpdatePendingOracle(rpm, false)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	identity, err := readVMConnectionIdentity(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	// Device actions require fresh host inventory; publish it under a signed refresh.
	if err := refreshPublishedInventory(ctx, r, s); err != nil {
		return fail(err)
	}
	request := actionRequestFor(r.device, identity.GetEnrollmentGeneration(), &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, RebootPolicy: &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_NEVER}}}})
	request.Reason = "disposable patch-now native qualification"
	dispatched, root, err := dispatchNativeAction(ctx, r.vm, r.control.session, request, nil, false)
	if dispatched != nil {
		s.DeviceActions = append(s.DeviceActions, dispatched)
	}
	if err != nil {
		return fail(err)
	}
	if !root.GetVerification().GetPatchRunStarted() || root.GetVerification().GetPowerRequestAccepted() {
		return fail(fmt.Errorf("patch-now verification %v does not attest a started native run", root.GetVerification()))
	}
	status, statusRecord, err := serverPatchStatus(ctx, r, s, "patch-now", func(p *agentv1.PatchStatusObservation) error {
		last := p.GetLastRun()
		if last.GetTrigger() != agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_PATCH_NOW || last.GetActionId() != dispatched.ActionID || last.GetResult() != agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED || last.GetSelection() != resourcev1.UpdateSelection_UPDATE_SELECTION_ALL {
			return fmt.Errorf("last run %v is not this patch-now", last)
		}
		if last.GetRebootScheduledFor() != nil || (last.GetRebootRequired() && last.GetRebootReason() != "policy_never") {
			return fmt.Errorf("never-reboot patch-now scheduled or misreported a reboot: %v", last)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	after, err := osUpdatePackageOracle(rpm)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if changed := !bytes.Equal(before.Bytes, after.Bytes); changed != (status.GetLastRun().GetUpdatedPackages() > 0) {
		return fail(fmt.Errorf("reported %d updated packages but native database changed=%t", status.GetLastRun().GetUpdatedPackages(), changed))
	}
	schedule, kind, _, err := logindScheduleOracle(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if kind != "" {
		return fail(fmt.Errorf("never-reboot patch-now left a logind %s schedule", kind))
	}
	before.Name, after.Name = "before-"+before.Name, "after-"+after.Name
	passScenario(s, pendingBefore, before, after, schedule, statusRecord)

	fleet, failFleet := firewallScenario(ctx, r, evidence, "fleet-patch-compliance")
	// The fleet summary is compared with the device's latest published status.
	status, current, err := serverPatchStatus(ctx, r, fleet, "fleet", func(p *agentv1.PatchStatusObservation) error {
		if !p.GetAvailable() || p.GetLastRun().GetActionId() != dispatched.ActionID {
			return fmt.Errorf("patch status %v is not the post-patch-now observation", p)
		}
		return nil
	})
	if err != nil {
		return failFleet(err)
	}
	summary, err := r.control.session.Admin.GetFleetSummary(ctx, connect.NewRequest(&adminv1.GetFleetSummaryRequest{}))
	if err != nil {
		return failFleet(err)
	}
	patch := summary.Msg.GetPatchCompliance()
	total := patch.GetPatchedDevices() + patch.GetSecurityPendingDevices() + patch.GetRebootRequiredDevices() + patch.GetStaleDevices() + patch.GetUnknownDevices()
	expected := patch.GetPatchedDevices()
	switch {
	case status.GetPendingSecurityUpdates() > 0:
		expected = patch.GetSecurityPendingDevices()
	case status.GetRebootRequired():
		expected = patch.GetRebootRequiredDevices()
	}
	if total != summary.Msg.GetLifecycle().GetActiveDevices() || expected != 1 || patch.GetPendingSecurityUpdates() != uint64(status.GetPendingSecurityUpdates()) {
		return failFleet(fmt.Errorf("fleet patch compliance %v does not match the device status %v", patch, status))
	}
	data, err := protojson.Marshal(summary.Msg)
	if err != nil {
		return failFleet(err)
	}
	passScenario(fleet, current, resourceNativeRecord("server-fleet-summary", data))
	return nil
}
