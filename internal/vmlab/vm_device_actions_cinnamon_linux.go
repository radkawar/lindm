// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

// CinnamonLockEvidence qualifies only native Cinnamon session-lock confirmation,
// not account policy, quarantine, assistance or destructive device actions.
type CinnamonLockEvidence struct {
	MinimumVersion   string                 `json:"minimum_version"`
	InstalledVersion string                 `json:"installed_version"`
	CandidateVersion string                 `json:"candidate_version,omitempty"`
	GateReason       string                 `json:"gate_reason,omitempty"`
	NativeLocker     bool                   `json:"native_locker"`
	LogindRequest    *actionDesktopEvidence `json:"logind_request,omitempty"`
	AfterLogindPAM   *actionDesktopEvidence `json:"after_logind_pam,omitempty"`
	AfterPAM         *actionDesktopEvidence `json:"after_pam,omitempty"`
}

type cinnamonLockGate struct{ installed, candidate string }

func (g *cinnamonLockGate) Error() string {
	return fmt.Sprintf("Cinnamon lock confirmation requires %s or later; installed %s and signed vendor candidate %s are below the minimum", platform.CinnamonLockMinimumVersion, g.installed, g.candidate)
}

// IsCinnamonLockGate distinguishes a safely established old-package prerequisite
// from native execution, package, transport and cleanup failures. Joined nil
// cleanup wrappers are harmless; any additional error makes this a real failure.
func IsCinnamonLockGate(err error) bool {
	var gate *cinnamonLockGate
	return errors.As(err, &gate) && err.Error() == gate.Error()
}

// cinnamonVersionFloorCommand delegates syntax and ordering to real dpkg. An
// epoch orders Debian packages but cannot turn Cinnamon 6.6 into upstream 6.7.9.
// Strip only the epoch and Debian revision; keep ~rc prerelease ordering intact.
func cinnamonVersionFloorCommand(version string) (string, error) {
	if version == "" || len(version) > 128 || strings.ContainsAny(version, " \t\r\n\x00") {
		return "", errors.New("invalid Cinnamon package version")
	}
	script := `set -eu
dpkg --validate-version "$1"
v=${1#*:}
v=${v%-*}
dpkg --validate-version "$v"
if dpkg --compare-versions "$v" ge "$2"; then printf 'eligible\n'; else
  status=$?
  test "$status" = 1
  printf 'old\n'
fi`
	return "sh -c " + nativeQuote(script) + " sh " + nativeQuote(version) + " " + nativeQuote(platform.CinnamonLockMinimumVersion), nil
}

func cinnamonVersionEligible(ctx context.Context, vm *EncryptedVM, version string) (bool, error) {
	command, err := cinnamonVersionFloorCommand(version)
	if err != nil {
		return false, err
	}
	output, err := vm.guest.run(ctx, command, nil, 4096, time.Minute)
	if err != nil {
		return false, fmt.Errorf("compare Cinnamon version with dpkg: %w", err)
	}
	switch string(output) {
	case "eligible\n":
		return true, nil
	case "old\n":
		return false, nil
	default:
		return false, errors.New("invalid dpkg Cinnamon version comparison")
	}
}

const cinnamonAPT = "apt-get -q -y -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -o APT::Update::Error-Mode=any "

// APT and apt-cache can emit informational notices on stderr after successful
// completion. Use their actual exit status; update's Error-Mode=any still makes
// every failed index a failure. Never print guest-controlled diagnostics.
func cinnamonPackageOutput(result guestCommandResult, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("guest package operation exited with status %d (stderr bytes %d)", result.ExitCode, len(result.Stderr))
	}
	return result.Stdout, nil
}

// cinnamonPackageVersions uses only the clone's existing vendor sources. It
// never adds repositories, changes suites/pins, installs local builds or performs
// partial release upgrades. APT must refresh every index successfully first.
func cinnamonPackageVersions(ctx context.Context, machine *actionMachine, evidence *CinnamonLockEvidence) error {
	vm := machine.vm
	if machine.release.Native().Packages.Backend != platform.BackendAPT {
		return errors.New("native Cinnamon confirmation requires signed vendor APT packages")
	}
	if _, err := cinnamonPackageOutput(vm.guest.runResult(ctx, "sudo -n env DEBIAN_FRONTEND=noninteractive "+cinnamonAPT+"update", nil, 2<<20, 15*time.Minute)); err != nil {
		return fmt.Errorf("refresh signed Cinnamon vendor sources: %w", err)
	}
	query := `dpkg-query -W -f '${db:Status-Status}\n${Version}\n' cinnamon; apt-cache policy; printf '@@CINNAMON@@\n'; apt-cache policy cinnamon`
	output, err := cinnamonPackageOutput(vm.guest.runResult(ctx, "env LC_ALL=C sh -eu -c "+nativeQuote(query), nil, 2<<20, time.Minute))
	if err != nil {
		return fmt.Errorf("observe installed and candidate Cinnamon packages: %w", err)
	}
	installed, candidate, err := parseCinnamonAPTPolicy(string(output), machine.release.Advisory.VendorOrigins)
	if err != nil {
		return err
	}
	evidence.InstalledVersion, evidence.CandidateVersion = installed, candidate
	installedOK, err := cinnamonVersionEligible(ctx, vm, installed)
	if err != nil {
		return err
	}
	candidateOK, err := cinnamonVersionEligible(ctx, vm, candidate)
	if err != nil {
		return err
	}
	if !installedOK && !candidateOK {
		return &cinnamonLockGate{installed: installed, candidate: candidate}
	}
	if !candidateOK {
		return errors.New("newer installed-only Cinnamon lacks an eligible signed vendor candidate")
	}
	if installed != candidate {
		// Vendor Breaks/Replaces may retire the obsolete standalone screensaver.
		// Leave that dependency transaction to APT; never remove packages by hand.
		command := "sudo -n env DEBIAN_FRONTEND=noninteractive " + cinnamonAPT + "install " + nativeQuote("cinnamon="+candidate)
		if _, err := cinnamonPackageOutput(vm.guest.runResult(ctx, command, nil, 2<<20, 20*time.Minute)); err != nil {
			return fmt.Errorf("install exact signed Cinnamon vendor candidate and dependencies: %w", err)
		}
	}
	output, err = vm.guest.run(ctx, `dpkg-query -W -f '${db:Status-Status}\n${Version}\n' cinnamon`, nil, 4096, time.Minute)
	if err != nil {
		return err
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(fields) != 2 || fields[0] != "installed" {
		return errors.New("native Cinnamon package is not fully installed after native package preparation")
	}
	if fields[1] != candidate {
		return errors.New("native Cinnamon installation differs from the exact vendor candidate")
	}
	evidence.InstalledVersion = fields[1]
	eligible, err := cinnamonVersionEligible(ctx, vm, evidence.InstalledVersion)
	if err != nil {
		return err
	}
	if !eligible {
		return errors.New("installed Cinnamon remained below the native lock minimum")
	}
	output, err = vm.guest.run(ctx, "sudo -n dpkg --verify cinnamon", nil, 64<<10, time.Minute)
	if err != nil {
		return fmt.Errorf("verify vendor Cinnamon package files: %w", err)
	}
	if len(output) != 0 {
		return errors.New("vendor Cinnamon package files were modified")
	}
	return nil
}

// parseCinnamonAPTPolicy joins the candidate's actual package-file indexes with
// APT Release origins. An installed-only version, absent candidate, third-party
// source or malformed policy is a failure, never an old-package gate.
func parseCinnamonAPTPolicy(output string, vendorOrigins []string) (string, string, error) {
	status, rest, ok := strings.Cut(output, "\n")
	if !ok || status != "installed" {
		return "", "", errors.New("native Cinnamon package is not fully installed")
	}
	installed, rest, ok := strings.Cut(rest, "\n")
	if !ok {
		return "", "", errors.New("native Cinnamon installed version is missing")
	}
	global, policy, ok := strings.Cut(rest, "@@CINNAMON@@\n")
	if !ok {
		return "", "", errors.New("native Cinnamon APT candidate policy is missing")
	}
	files, err := parseAptPackageFiles(global)
	if err != nil {
		return "", "", err
	}
	candidate, policyInstalled := "", ""
	for _, line := range strings.Split(policy, "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "Installed: "); ok {
			if policyInstalled != "" {
				return "", "", errors.New("duplicate Cinnamon installed package policy")
			}
			policyInstalled = value
		}
		if value, ok := strings.CutPrefix(line, "Candidate: "); ok {
			if candidate != "" {
				return "", "", errors.New("duplicate Cinnamon candidate package policy")
			}
			candidate = value
		}
	}
	if installed == "" || policyInstalled != installed || candidate == "" || candidate == "(none)" {
		return "", "", errors.New("native Cinnamon installed and candidate policy is incomplete")
	}
	matching, found := false, false
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if strings.HasPrefix(line, " *** ") || indent == 5 {
			fields := strings.Fields(strings.TrimPrefix(trimmed, "*** "))
			if len(fields) != 2 {
				return "", "", errors.New("invalid Cinnamon APT version row")
			}
			matching = fields[0] == candidate
			continue
		}
		if !matching || indent <= 5 || trimmed == "" {
			continue
		}
		priority, index, ok := strings.Cut(trimmed, " ")
		if _, err := strconv.Atoi(priority); !ok || err != nil {
			return "", "", errors.New("invalid Cinnamon APT package-file row")
		}
		if index == "/var/lib/dpkg/status" {
			continue
		}
		release, ok := files[index]
		if !ok || release.origin == "" || !slices.Contains(vendorOrigins, release.origin) {
			return "", "", errors.New("native Cinnamon candidate is not from a declared vendor archive")
		}
		found = true
	}
	if !found {
		return "", "", errors.New("native Cinnamon candidate has no vendor package-file index")
	}
	return installed, candidate, nil
}

const cinnamonNativeLocker = "cinnamon org.cinnamon.ScreenSaver.GetActive"

// The new API lives in Cinnamon itself, not cinnamon-screensaver. Prove both
// names have one unique bus owner and that owner's PID is the actual user-owned
// vendor Cinnamon executable before accepting its genuine isLocked() state.
const cinnamonNativeIdentity = `owner() {
 as gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.GetNameOwner "$1"
}
owner=$(owner org.Cinnamon)
test "$owner" = "$(owner org.cinnamon.ScreenSaver)"
pid=$(as gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.GetConnectionUnixProcessID org.Cinnamon | sed -n 's/^(uint32 \([0-9][0-9]*\),)$/\1/p')
case "$pid" in ''|*[!0-9]*) exit 1;; esac
test "$(stat -c %u /proc/"$pid")" = "$uid"
test "$(cat /proc/"$pid"/comm)" = cinnamon
test "$(readlink -f /proc/"$pid"/exe)" = "$(readlink -f /usr/bin/cinnamon)"
test "$(dpkg-query -S /usr/bin/cinnamon)" = 'cinnamon: /usr/bin/cinnamon'
`

func cinnamonConfirmationDesktop(stock *labDesktop) *labDesktop {
	desktop := *stock
	desktop.lockedHint = true
	desktop.locker = cinnamonNativeLocker
	// This focused cell needs no welcome/idle helpers and must not inherit the
	// stock profile's process-pattern cleanup.
	desktop.quiet = ""
	desktop.lockOracle = cinnamonNativeIdentity + `case "$(as gdbus call --session --dest org.cinnamon.ScreenSaver --object-path /org/cinnamon/ScreenSaver --method org.cinnamon.ScreenSaver.GetActive)" in
"(true,)") echo locked;; "(false,)") echo unlocked;; *) echo invalid;; esac`
	return &desktop
}

func nativeCinnamonLockConfirmation(ctx context.Context, machine *actionMachine, control *vmControlPlane, result *VMDeviceActionsResult) (err error) {
	result.CinnamonLock = &CinnamonLockEvidence{MinimumVersion: platform.CinnamonLockMinimumVersion}
	evidence := result.CinnamonLock
	if err := cinnamonPackageVersions(ctx, machine, evidence); err != nil {
		return err
	}
	// Scope this expectation to the eligible disposable clone. In particular the
	// global Mint 6.6 profile must still require locker=true and LockedHint=false.
	desktop := cinnamonConfirmationDesktop(machine.desktop)
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	password := make([]byte, hex.EncodedLen(len(random)))
	hex.Encode(password, random[:])
	clear(random[:])
	defer clear(password)
	result.DesktopInitialLogind, err = prepareActionDesktopWithPassword(ctx, machine.vm, desktop, machine.release, password)
	if err != nil {
		return err
	}
	result.DesktopBefore, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(false))
	if err != nil {
		return fmt.Errorf("observe integrated Cinnamon locker before lock: %w", err)
	}
	if err := verifyRunningCinnamon(ctx, machine.vm, desktop); err != nil {
		return err
	}
	evidence.NativeLocker = true
	if _, err := machine.vm.Run(ctx, "sudo -n loginctl lock-session "+nativeQuote(result.DesktopBefore.SessionID), nil); err != nil {
		return fmt.Errorf("request native Cinnamon lock through logind: %w", err)
	}
	evidence.LogindRequest, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(true))
	if err != nil {
		return err
	}
	evidence.AfterLogindPAM, err = unlockCinnamonPAM(ctx, machine.vm, desktop, password)
	if err != nil {
		return err
	}
	request := actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}})
	var status *agentv1.DeviceActionStatus
	result.Lock, status, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	if err != nil {
		return err
	}
	if err := cinnamonSignedActionVerified(status, true); err != nil {
		return err
	}
	result.DesktopAfter, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(true))
	if err != nil {
		return err
	}
	request = actionRequestFor(machine.deviceID, machine.generation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: result.Lock.ActionID}}})
	result.LockRelease, status, err = dispatchNativeAction(ctx, machine.vm.guest, control.session, request, nil, false)
	if err != nil {
		return err
	}
	if err := cinnamonSignedActionVerified(status, false); err != nil {
		return err
	}
	result.DesktopAfterRelease, err = waitActionDesktop(ctx, machine.vm, desktop, desktop.expectedLock(true))
	if err != nil {
		return fmt.Errorf("signed release must leave native Cinnamon locked: %w", err)
	}
	evidence.AfterPAM, err = unlockCinnamonPAM(ctx, machine.vm, desktop, password)
	if err != nil {
		return err
	}
	for _, observation := range []*actionDesktopEvidence{evidence.LogindRequest, evidence.AfterLogindPAM, result.DesktopAfter, result.DesktopAfterRelease, evidence.AfterPAM} {
		if !sameCinnamonDesktopSession(result.DesktopBefore, observation) {
			return errors.New("native Cinnamon lock confirmation changed the native desktop session")
		}
	}
	result.Boundaries = append(result.Boundaries, "Signed vendor Cinnamon "+evidence.InstalledVersion+": integrated native locker and logind LockedHint false-to-true-to-PAM-false after both loginctl and signed lindm session lock; signed release does not unlock. No account-policy, assistance, wipe or quarantine qualification.")
	return nil
}

func sameCinnamonDesktopSession(before, after *actionDesktopEvidence) bool {
	return before != nil && after != nil && before.SessionID != "" &&
		before.SessionID == after.SessionID && before.Type == after.Type &&
		before.Class == after.Class && before.User == after.User &&
		before.Service == after.Service && before.Desktop == after.Desktop &&
		before.Locker == after.Locker
}

func cinnamonSignedActionVerified(status *agentv1.DeviceActionStatus, lock bool) error {
	if status.GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || status.GetFailure() != agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE || !status.GetVerification().GetVerified() || (lock && !status.GetVerification().GetAfter().GetSessionsLocked()) {
		return errors.New("signed Cinnamon action lacks a successful verified native result")
	}
	return nil
}

func verifyRunningCinnamon(ctx context.Context, vm *EncryptedVM, desktop *labDesktop) error {
	output, err := vm.Run(ctx, desktop.rootScript(cinnamonNativeIdentity+`as gdbus call --session --dest org.Cinnamon --object-path /org/Cinnamon --method org.freedesktop.DBus.Properties.Get org.Cinnamon CinnamonVersion`), nil)
	if err != nil {
		return fmt.Errorf("observe actual running Cinnamon version: %w", err)
	}
	version, ok := strings.CutPrefix(strings.TrimSpace(string(output)), "(<'")
	if !ok || !strings.HasSuffix(version, "'>,)") {
		return errors.New("invalid running Cinnamon version property")
	}
	version = strings.TrimSuffix(version, "'>,)")
	eligible, err := cinnamonVersionEligible(ctx, vm, version)
	if err != nil {
		return err
	}
	if !eligible {
		return errors.New("actual running Cinnamon is below the native lock minimum")
	}
	return nil
}

// Read only the real focused native password widget, never its contents. PAM's
// auth-prompt makes this widget visible and focuses it; no state or authentication
// is injected through Eval. All credential input below travels through QEMU's
// physical keyboard and Cinnamon's normal password-entry activation/PAM helper.
const cinnamonPAMReady = `(() => { let actor = global.stage.get_key_focus(); while (actor) { if (actor instanceof imports.gi.St.PasswordEntry) return actor.is_mapped() && actor.reactive; actor = actor.get_parent(); } return false; })()`

func unlockCinnamonPAM(ctx context.Context, vm *EncryptedVM, desktop *labDesktop, password []byte) (*actionDesktopEvidence, error) {
	if _, err := vm.Run(ctx, desktop.rootScript(`as gdbus call --session --dest org.cinnamon.ScreenSaver --object-path /org/cinnamon/ScreenSaver --method org.cinnamon.ScreenSaver.SimulateUserActivity >/dev/null`), nil); err != nil {
		return nil, fmt.Errorf("open native Cinnamon PAM unlock dialog: %w", err)
	}
	ready := desktop.rootScript(cinnamonNativeIdentity + `test "$(as gdbus call --session --dest org.Cinnamon --object-path /org/Cinnamon --method org.Cinnamon.Eval ` + nativeQuote(cinnamonPAMReady) + `)" = "(true, 'true')"`)
	if err := pollGuest(ctx, vm.guest, time.Minute, "native Cinnamon PAM password entry focused", ready); err != nil {
		return nil, err
	}
	if err := typeCinnamonPAMPassword(ctx, vm.guest, password); err != nil {
		return nil, err
	}
	if err := vm.guest.sendKey(ctx, "ret"); err != nil {
		return nil, fmt.Errorf("submit native Cinnamon PAM password: %w", err)
	}
	observed, err := waitActionDesktop(ctx, vm, desktop, desktop.expectedLock(false))
	if err != nil {
		return nil, fmt.Errorf("native Cinnamon PAM did not unlock both lock oracles: %w", err)
	}
	return observed, nil
}

func typeCinnamonPAMPassword(ctx context.Context, vm *guestVM, password []byte) error {
	const alphabet = "0123456789abcdef"
	if len(password) == 0 {
		return errors.New("missing native Cinnamon PAM password")
	}
	for _, char := range password {
		if !strings.ContainsRune(alphabet, rune(char)) {
			return errors.New("unsupported native Cinnamon PAM password character")
		}
	}
	key := map[string]any{"type": "qcode", "data": ""}
	events := []map[string]any{
		{"type": "key", "data": map[string]any{"down": true, "key": key}},
		{"type": "key", "data": map[string]any{"down": false, "key": key}},
	}
	request := map[string]any{"execute": "input-send-event", "id": "native-pam-key", "arguments": map[string]any{"events": events}}
	defer func() { key["data"] = "" }()
	for _, char := range password {
		index := strings.IndexByte(alphabet, char)
		key["data"] = alphabet[index : index+1]
		if err := vm.qmpCommand(ctx, request); err != nil {
			return fmt.Errorf("type native Cinnamon PAM password through local keyboard: %w", err)
		}
	}
	return nil
}
