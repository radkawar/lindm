// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

// Execute the production comparison command with actual dpkg, not a Go semver
// approximation: Debian epochs/revisions and ~ prereleases have distinct rules.
func TestCinnamonMinimumUsesRealDpkgUpstreamOrdering(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("native Debian version comparator is unavailable")
	}
	for _, test := range []struct {
		version string
		want    string
	}{
		{"6.6.0", "old\n"}, {"6.6.7+zena", "old\n"},
		{"6.7.8", "old\n"}, {"6.7.9~rc", "old\n"}, {"6.7.9~rc1", "old\n"},
		{"6.7.9~rc1-1mint1", "old\n"}, {"6.7.9", "eligible\n"},
		{"6.7.9+zena-1", "eligible\n"}, {"6.7.10", "eligible\n"},
		{"9:6.6.7-1mint1", "old\n"}, {"2:6.7.8-9", "old\n"},
		{"2:6.7.9~rc1-9", "old\n"}, {"2:6.7.9-1mint1", "eligible\n"},
		{"1:6.7.10-0ubuntu1", "eligible\n"},
	} {
		t.Run(test.version, func(t *testing.T) {
			command, err := cinnamonVersionFloorCommand(test.version)
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), "sh", "-c", command).CombinedOutput()
			if err != nil || string(output) != test.want {
				t.Fatalf("dpkg %s = %q, %v; want %q", test.version, output, err, test.want)
			}
		})
	}
	for _, version := range []string{"", "(none)", "not-a-version", "6.7.9\n", "6.7.9;exit 0", "x:6.7.9", "6.7.9/invalid", strings.Repeat("9", 129)} {
		command, err := cinnamonVersionFloorCommand(version)
		if err != nil {
			continue
		}
		if output, err := exec.CommandContext(t.Context(), "sh", "-c", command).CombinedOutput(); err == nil {
			t.Fatalf("malformed version %q became an eligibility result %q", version, output)
		}
	}
}

func TestCinnamonGateRejectsExecutionAndCleanupFailures(t *testing.T) {
	gate := &cinnamonLockGate{installed: "6.6.7+zena", candidate: "6.6.7+zena"}
	if !IsCinnamonLockGate(gate) || !IsCinnamonLockGate(errors.Join(gate, nil)) || len(gate.Error()) > 512 {
		t.Fatal("genuine old-package gate was not retained")
	}
	for _, err := range []error{
		nil, errors.New(gate.Error()), errors.New("dpkg tool is unavailable"),
		errors.New("APT candidate is missing"), errors.New("APT signature verification failed"),
		errors.Join(gate, errors.New("close owned VM failed")),
		errors.Join(errors.New("write result failed"), gate),
		fmt.Errorf("transport failed: %w", gate),
	} {
		if IsCinnamonLockGate(err) {
			t.Errorf("execution/IO failure became an old-package gate: %v", err)
		}
	}
}

const cinnamonVendorPolicy = `installed
6.6.7+zena
Package files:
 100 /var/lib/dpkg/status
     release a=now
 700 http://packages.linuxmint.com zena/main amd64 Packages
     release v=22.3,o=linuxmint,a=zena,n=zena,l=linuxmint,c=main,b=amd64
     origin packages.linuxmint.com
Pinned packages:
@@CINNAMON@@
cinnamon:
  Installed: 6.6.7+zena
  Candidate: 6.7.9+zena
  Version table:
     6.7.9+zena 700
        700 http://packages.linuxmint.com zena/main amd64 Packages
 *** 6.6.7+zena 100
        100 /var/lib/dpkg/status
`

func TestCinnamonCandidateRequiresRealDeclaredVendorIndex(t *testing.T) {
	installed, candidate, err := parseCinnamonAPTPolicy(cinnamonVendorPolicy, []string{"linuxmint"})
	if err != nil || installed != "6.6.7+zena" || candidate != "6.7.9+zena" {
		t.Fatalf("vendor package policy = %q/%q, %v", installed, candidate, err)
	}
	stock := strings.ReplaceAll(cinnamonVendorPolicy, "6.7.9+zena", "6.6.7+zena")
	if installed, candidate, err := parseCinnamonAPTPolicy(stock, []string{"linuxmint"}); err != nil || installed != candidate {
		t.Fatalf("stock vendor policy must remain observable for old-package gating: %q/%q, %v", installed, candidate, err)
	}
	for name, policy := range map[string]string{
		"absent package":      strings.Replace(cinnamonVendorPolicy, "installed\n", "config-files\n", 1),
		"no candidate":        strings.Replace(cinnamonVendorPolicy, "Candidate: 6.7.9+zena", "Candidate: (none)", 1),
		"missing candidate":   strings.Replace(cinnamonVendorPolicy, "  Candidate: 6.7.9+zena\n", "", 1),
		"duplicate candidate": strings.Replace(cinnamonVendorPolicy, "  Candidate: 6.7.9+zena\n", "  Candidate: 6.7.9+zena\n  Candidate: 6.7.10\n", 1),
		"different installed": strings.Replace(cinnamonVendorPolicy, "Installed: 6.6.7+zena", "Installed: 6.7.9+zena", 1),
		"third party":         strings.Replace(cinnamonVendorPolicy, "o=linuxmint", "o=unreviewed-ppa", 1),
		"undeclared index":    strings.Replace(cinnamonVendorPolicy, "        700 http://packages.linuxmint.com", "        700 http://unreviewed.invalid", 1),
		"installed only":      strings.Replace(cinnamonVendorPolicy, "        700 http://packages.linuxmint.com zena/main amd64 Packages", "        100 /var/lib/dpkg/status", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseCinnamonAPTPolicy(policy, []string{"linuxmint"}); err == nil || IsCinnamonLockGate(err) {
				t.Fatalf("invalid package prerequisite did not fail normally: %v", err)
			}
		})
	}
	if _, _, err := parseCinnamonAPTPolicy(cinnamonVendorPolicy, nil); err == nil {
		t.Fatal("candidate with no declared vendor origins was accepted")
	}
}

func TestCinnamonConfirmationProfileDoesNotChangeStock66(t *testing.T) {
	stock := mustLabDesktop(t, "cinnamon")
	originalOracle, originalLocker, originalQuiet := stock.lockOracle, stock.locker, stock.quiet
	fixed := cinnamonConfirmationDesktop(stock)
	if fixed == stock || !fixed.lockedHint || fixed.locker != cinnamonNativeLocker || fixed.expectedLock(true) != (lockState{hint: true, locker: true}) {
		t.Fatal("eligible clone does not require independent native and logind lock confirmation")
	}
	if fixed.quiet != "" {
		t.Fatal("focused native cell inherited stock welcome/process cleanup")
	}
	for _, locked := range []bool{false, true} {
		want := fixed.expectedLock(locked)
		fields := desktopFields(fixed, "x11", "cinnamon", want)
		observed, err := parseActionDesktop(fixed, []byte(strings.Join(fields, "\n")), want)
		if err != nil || observed.LockedHint != locked || observed.ScreenSaverActive != locked || observed.Locker != cinnamonNativeLocker {
			t.Fatalf("native clone locked=%t: %+v, %v", locked, observed, err)
		}
		for _, state := range []lockState{{hint: !want.hint, locker: want.locker}, {hint: want.hint, locker: !want.locker}} {
			if _, err := parseActionDesktop(fixed, []byte(strings.Join(desktopFields(fixed, "x11", "cinnamon", state), "\n")), want); err == nil {
				t.Fatalf("native/logind disagreement accepted for locked=%t", locked)
			}
		}
	}
	if stock.lockedHint || stock.expectedLock(true) != (lockState{locker: true}) || stock.lockOracle != originalOracle || stock.locker != originalLocker || stock.quiet != originalQuiet {
		t.Fatal("native cell changed the stock Cinnamon 6.6 global profile")
	}
}

func TestCinnamonPhaseIsLockOnlyAndRequiresCinnamonBeforeVMAdmission(t *testing.T) {
	release, ok := platform.Lookup("linuxmint-22.3")
	if !ok {
		t.Fatal("stock Mint registry row is missing")
	}
	for _, desktop := range []string{"", "gnome", "cosmic", "hyprland"} {
		options := VMDeviceActionsOptions{Scenario: "wipe", WipePhase: "cinnamon-lock-confirmation", Encrypted: EncryptedVMOptions{Desktop: desktop}}
		if _, err := actionLaneDesktop(options, release); err == nil {
			t.Errorf("Cinnamon confirmation accepted desktop %q", desktop)
		}
	}
	options := VMDeviceActionsOptions{Scenario: "wipe", WipePhase: "cinnamon-lock-confirmation", Encrypted: EncryptedVMOptions{Desktop: "cinnamon"}}
	if desktop, err := actionLaneDesktop(options, release); err != nil || desktop != mustLabDesktop(t, "cinnamon") {
		t.Fatalf("Cinnamon phase desktop = %v, %v", desktop, err)
	}
	options.Scenario = "all"
	if _, err := actionLaneDesktop(options, release); err == nil {
		t.Fatal("Cinnamon-only phase accepted an all-actions scenario")
	}
	capabilities := deviceActionCapabilities("wipe", "cinnamon-lock-confirmation")
	if len(capabilities) != 1 || capabilities[0] != platform.Lock {
		t.Fatalf("Cinnamon lock cell gained unrelated action requirements: %v", capabilities)
	}
	if err := ownedBootFixtureAvailable(release, "x86_64", "wipe", "cinnamon-lock-confirmation", ""); err != nil {
		t.Fatalf("Cinnamon lock-only cell acquired a recovery boot prerequisite: %v", err)
	}
}

func TestCinnamonSignedActionRequiresNativeVerifiedSuccess(t *testing.T) {
	status := &agentv1.DeviceActionStatus{
		State:        agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED,
		Failure:      agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE,
		Verification: &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{SessionsLocked: true}},
	}
	if err := cinnamonSignedActionVerified(status, true); err != nil {
		t.Fatal(err)
	}
	status.Verification.After.SessionsLocked = false
	if err := cinnamonSignedActionVerified(status, true); err == nil {
		t.Fatal("signed lock accepted success without verified locked sessions")
	}
	if err := cinnamonSignedActionVerified(status, false); err != nil {
		t.Fatalf("signed release must not claim desktop unlock through action status: %v", err)
	}
	status.Verification.Verified = false
	if err := cinnamonSignedActionVerified(status, false); err == nil {
		t.Fatal("unverified signed release was accepted")
	}
	status.Verification.Verified = true
	status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN
	status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_OBSERVATION
	if err := cinnamonSignedActionVerified(status, true); err == nil {
		t.Fatal("stock Cinnamon unconfirmed outcome became a positive native lock result")
	}
	if err := cinnamonSignedActionVerified(nil, true); err == nil {
		t.Fatal("missing signed action status became a native lock result")
	}
}

func TestCinnamonTransitionsRemainInOneNativeSession(t *testing.T) {
	before := &actionDesktopEvidence{SessionID: "4", Type: "x11", Class: "user", User: actionDesktopUser, Service: "lightdm-autologin", Desktop: "cinnamon", Locker: cinnamonNativeLocker}
	after := *before
	after.LockedHint, after.ScreenSaverActive = true, true
	if !sameCinnamonDesktopSession(before, &after) {
		t.Fatal("normal lock transition changed session identity")
	}
	for name, alter := range map[string]func(*actionDesktopEvidence){
		"relogin":         func(e *actionDesktopEvidence) { e.SessionID = "5" },
		"greeter":         func(e *actionDesktopEvidence) { e.Class = "greeter" },
		"user":            func(e *actionDesktopEvidence) { e.User = "other" },
		"protocol":        func(e *actionDesktopEvidence) { e.Type = "wayland" },
		"service":         func(e *actionDesktopEvidence) { e.Service = "sshd" },
		"desktop":         func(e *actionDesktopEvidence) { e.Desktop = "other" },
		"external locker": func(e *actionDesktopEvidence) { e.Locker = "cinnamon-screensaver org.cinnamon.ScreenSaver.GetActive" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := after
			alter(&changed)
			if sameCinnamonDesktopSession(before, &changed) {
				t.Fatal("foreign native observation was joined into a lock transition")
			}
		})
	}
	if sameCinnamonDesktopSession(nil, &after) || sameCinnamonDesktopSession(before, nil) || sameCinnamonDesktopSession(&actionDesktopEvidence{}, &actionDesktopEvidence{}) {
		t.Fatal("missing native session identity was accepted")
	}
}

func TestCinnamonPackageCommandsUseActualCompletionStatus(t *testing.T) {
	transport := errors.New("bounded guest transport closed")
	for _, test := range []struct {
		name      string
		result    guestCommandResult
		transport error
		wantError bool
	}{
		{"clean", guestCommandResult{Stdout: []byte("policy")}, nil, false},
		{"successful notice", guestCommandResult{Stdout: []byte("policy"), Stderr: []byte("N: repository notice\n")}, nil, false},
		{"failed signed index", guestCommandResult{Stdout: []byte("old cached policy"), Stderr: []byte("E: failed index\n"), ExitCode: 100}, nil, true},
		{"unknown completion", guestCommandResult{Stdout: []byte("partial policy")}, transport, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := cinnamonPackageOutput(test.result, test.transport)
			if (err != nil) != test.wantError {
				t.Fatalf("package completion error = %v, want error %v", err, test.wantError)
			}
			if test.wantError {
				if len(output) != 0 || IsCinnamonLockGate(err) {
					t.Fatal("failed package preparation became a usable policy or prerequisite gate")
				}
				if test.transport != nil && !errors.Is(err, test.transport) {
					t.Fatal("package command lost its actual transport failure")
				}
				return
			}
			if string(output) != "policy" {
				t.Fatalf("successful package output = %q", output)
			}
		})
	}
}
