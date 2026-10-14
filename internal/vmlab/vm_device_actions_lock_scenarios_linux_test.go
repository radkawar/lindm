// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"strings"
	"testing"

	"lindm/internal/platform"
)

func mustLabDesktop(t *testing.T, name string) *labDesktop {
	t.Helper()
	for _, desktop := range labDesktops {
		if desktop.name == name {
			return desktop
		}
	}
	t.Fatalf("no lab desktop profile %q", name)
	return nil
}

func desktopFields(desktop *labDesktop, kind, label string, state lockState) []string {
	hint, locker := "no", "unlocked"
	if state.hint {
		hint = "yes"
	}
	if state.locker {
		locker = "locked"
	}
	return []string{"4", kind, label, hint, "user", actionDesktopUser, desktop.services[0], locker}
}

func TestActionDesktopRequiresGenuineUserAndBothLockOracles(t *testing.T) {
	gnome := mustLabDesktop(t, "gnome")
	for _, label := range []string{"", "ubuntu", "gnome"} {
		for _, kind := range []string{"wayland", "x11"} {
			for _, locked := range []bool{false, true} {
				want := gnome.expectedLock(locked)
				observed, err := parseActionDesktop(gnome, []byte(strings.Join(desktopFields(gnome, kind, label, want), "\n")+"\n"), want)
				if err != nil || observed == nil || observed.LockedHint != locked || observed.ScreenSaverActive != locked || observed.Desktop != label {
					t.Fatalf("%s/%s locked=%t: observed=%+v error=%v", label, kind, locked, observed, err)
				}
			}
		}
	}
	for _, test := range []struct {
		name  string
		field int
		value string
	}{
		{"greeter", 4, "greeter"},
		{"ssh", 1, "tty"},
		{"wrong_user", 5, "gdm"},
		{"not_gdm_login", 6, "sshd"},
		{"missing_logind_ack", 3, "no"},
		{"missing_gnome_ack", 7, "unlocked"},
		{"invalid_logind", 3, "unknown"},
		{"invalid_gnome", 7, "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := gnome.expectedLock(true)
			fields := desktopFields(gnome, "wayland", "ubuntu", want)
			fields[test.field] = test.value
			if _, err := parseActionDesktop(gnome, []byte(strings.Join(fields, "\n")), want); err == nil {
				t.Fatal("invalid native observation was accepted")
			}
		})
	}
	if _, err := parseActionDesktop(gnome, nil, gnome.expectedLock(false)); err == nil {
		t.Fatal("no logged-in session was accepted")
	}
}

// Cinnamon 6.6 engages its own locker on logind Lock but never reports
// LockedHint; the lab requires exactly that, and refuses a GNOME-style claim.
func TestCinnamonLockExpectsLockerWithoutLockedHint(t *testing.T) {
	cinnamon := mustLabDesktop(t, "cinnamon")
	want := cinnamon.expectedLock(true)
	if want.hint || !want.locker {
		t.Fatalf("cinnamon lock expectation %+v", want)
	}
	if _, err := parseActionDesktop(cinnamon, []byte(strings.Join(desktopFields(cinnamon, "x11", "cinnamon", want), "\n")), want); err != nil {
		t.Fatal(err)
	}
	claimed := lockState{hint: true, locker: true}
	if _, err := parseActionDesktop(cinnamon, []byte(strings.Join(desktopFields(cinnamon, "x11", "cinnamon", claimed), "\n")), want); err == nil {
		t.Fatal("a LockedHint the desktop never sets was accepted")
	}
	if _, err := parseActionDesktop(cinnamon, []byte(strings.Join(desktopFields(cinnamon, "wayland", "cinnamon", want), "\n")), want); err == nil {
		t.Fatal("a Wayland session was accepted for the X11 Cinnamon profile")
	}
	release := &platform.Release{Name: "fixture", Lab: platform.Lab{Session: platform.LabSession{Desktops: map[string][]string{"gnome": nil, "kde": nil}}}}
	if _, err := labDesktopFor("cinnamon", release); err == nil {
		t.Fatal("cinnamon profile accepted on a release whose lab session lacks it")
	}
	if _, err := labDesktopFor("kde", release); err == nil {
		t.Fatal("a lab session without a desktop profile was accepted")
	}
	if desktop, err := labDesktopFor("gnome", release); err != nil || desktop.name != "gnome" {
		t.Fatalf("gnome profile = %v, %v", desktop, err)
	}
}

// A headless server golden has no session to lock: it runs the encryption,
// live-erase, report-loss and recovery phases and is refused before any VM for
// every scenario that includes a desktop lock.
func TestHeadlessActionGoldenRefusesLockScenarios(t *testing.T) {
	release := &platform.Release{Name: "fixture", Lab: platform.Lab{Session: platform.LabSession{Desktops: map[string][]string{"gnome": nil}}}}
	for _, test := range []struct {
		scenario, phase string
		ok              bool
	}{
		{"encryption", "", true}, {"compliance", "", true},
		{"wipe", "live-erase", true}, {"wipe", "live-report-loss", true}, {"wipe", "recovery-nvme", true}, {"wipe", "recovery-sata", true},
		{"all", "", false}, {"wipe", "", false}, {"wipe", "live-actions", false}, {"wipe", "lock-quarantine", false},
	} {
		desktop, err := actionLaneDesktop(VMDeviceActionsOptions{Scenario: test.scenario, WipePhase: test.phase}, release)
		if (err == nil) != test.ok || desktop != nil {
			t.Errorf("headless %s/%s: desktop %v, error %v; want admitted=%t", test.scenario, test.phase, desktop, err, test.ok)
		}
	}
	options := VMDeviceActionsOptions{Scenario: "all", Encrypted: EncryptedVMOptions{Desktop: "gnome"}}
	if desktop, err := actionLaneDesktop(options, release); err != nil || desktop.name != "gnome" {
		t.Fatalf("gnome golden = %v, %v", desktop, err)
	}
}

// COSMIC locks through logind without LockedHint and refuses both assistance
// modes before consent: VIEW for cosmic-notifications' hidden prompt actions,
// CONTROL for its missing RemoteDesktop portal.
func TestCOSMICProfileLocksThroughLogindAndRefusesAssistance(t *testing.T) {
	cosmic := mustLabDesktop(t, "cosmic")
	if want := cosmic.expectedLock(true); want.hint || !want.locker {
		t.Fatalf("cosmic lock expectation %+v", want)
	}
	var got []string
	for _, spec := range cosmic.assistance {
		got = append(got, spec.name+"="+spec.detail)
	}
	if strings.Join(got, ",") != "view-unavailable=notification_actions_hidden,control-unavailable=portal_remote_desktop_unavailable" || !cosmic.refusalOnly() {
		t.Fatalf("cosmic scenarios = %v", got)
	}
	want := cosmic.expectedLock(true)
	fields := desktopFields(cosmic, "wayland", "COSMIC", want)
	if _, err := parseActionDesktop(cosmic, []byte(strings.Join(fields, "\n")), want); err != nil {
		t.Fatal(err)
	}
}
