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
	release := &platform.Release{Name: "fixture", Lab: platform.Lab{Session: platform.LabSession{Desktops: map[string][]string{"gnome": nil, "lxqt": nil}}}}
	if _, err := labDesktopFor("cinnamon", release); err == nil {
		t.Fatal("cinnamon profile accepted on a release whose lab session lacks it")
	}
	if _, err := labDesktopFor("lxqt", release); err == nil {
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

// COSMIC locks through logind without LockedHint. The ISO's missing
// RemoteDesktop portal refuses both assistance modes before consent.
func TestCOSMICProfileLocksThroughLogindAndRefusesAssistance(t *testing.T) {
	cosmic := mustLabDesktop(t, "cosmic")
	if want := cosmic.expectedLock(true); want.hint || !want.locker {
		t.Fatalf("cosmic lock expectation %+v", want)
	}
	var got []string
	for _, spec := range cosmic.assistance {
		got = append(got, spec.name+"="+spec.detail)
	}
	if strings.Join(got, ",") != "view-unavailable=portal_remote_desktop_unavailable,control-unavailable=portal_remote_desktop_unavailable" || !cosmic.refusalOnly() {
		t.Fatalf("cosmic scenarios = %v", got)
	}
	want := cosmic.expectedLock(true)
	fields := desktopFields(cosmic, "wayland", "COSMIC", want)
	if _, err := parseActionDesktop(cosmic, []byte(strings.Join(fields, "\n")), want); err != nil {
		t.Fatal(err)
	}
}

func TestHyprlandStockProfileRefusesUnqualifiedRuntimeBeforeLockCheck(t *testing.T) {
	desktop := mustLabDesktop(t, "hyprland")
	var got []string
	for _, spec := range desktop.assistance {
		got = append(got, spec.name+"="+spec.detail)
	}
	if strings.Join(got, ",") != "view-unavailable=desktop_runtime_unqualified,control-unavailable=portal_remote_desktop_unavailable" || !desktop.refusalOnly() {
		t.Fatalf("stock Hyprland scenarios = %v", got)
	}
	// Runtime qualification does not change the stock lock-observation truth.
	if want := desktop.expectedLock(true); want.hint || want.locker {
		t.Fatalf("stock Hyprland lock expectation %+v", want)
	}
}

// Plasma's kscreenlocker sets LockedHint and locks on Session.Lock; the lane
// presses its own Meta+L, reads consent controls by label in the bottom-right
// popup area, and proves the KDE gate's pre-consent refusal.
func TestKDEProfileLocksWithLockedHintAndProvesItsGate(t *testing.T) {
	kde := mustLabDesktop(t, "kde")
	if want := kde.expectedLock(true); !want.hint || !want.locker {
		t.Fatalf("kde lock expectation %+v", want)
	}
	if strings.Join(kde.lockKeys, "+") != "meta_l+l" || !kde.ocrConsent || kde.area != bannerBottomRight || kde.gate != "kde_plasma" {
		t.Fatalf("kde lane controls %+v", kde)
	}
	var names []string
	for _, spec := range kde.assistance {
		names = append(names, spec.name)
		if spec.desktopGateOff && spec.detail != "kde_plasma_policy_off" {
			t.Fatalf("kde gate scenario %+v", spec)
		}
	}
	if strings.Join(names, ",") != "desktop-policy-off,control,view,decline,portal-cancel,lock" {
		t.Fatalf("kde scenarios = %v", names)
	}
	want := kde.expectedLock(true)
	if _, err := parseActionDesktop(kde, []byte(strings.Join(desktopFields(kde, "wayland", "KDE", want), "\n")), want); err != nil {
		t.Fatal(err)
	}
	if _, err := parseActionDesktop(kde, []byte(strings.Join(desktopFields(kde, "x11", "KDE", want), "\n")), want); err == nil {
		t.Fatal("an X11 session was accepted for the Wayland Plasma profile")
	}
}

// An X11 variant logs into the same golden's X11 entry, accepts only x11
// logind sessions and proves the X11 gate; without an entry there is none.
func TestX11VariantUsesTheReleaseX11Session(t *testing.T) {
	gnome := mustLabDesktop(t, "gnome")
	if _, err := gnome.x11Variant(platform.LabSession{Name: "gnome"}); err == nil {
		t.Fatal("a release without an X11 session entry produced an X11 variant")
	}
	x11, err := gnome.x11Variant(platform.LabSession{Name: "ubuntu", X11Name: "ubuntu-xorg", GDMConfig: "/etc/gdm3/custom.conf"})
	if err != nil {
		t.Fatal(err)
	}
	if x11.name != "gnome-x11" || x11.goldenName() != "gnome" || x11.gate != "x11" || strings.Join(x11.sessionTypes, ",") != "x11" {
		t.Fatalf("x11 variant %+v", x11)
	}
	if script := x11.autologin(platform.LabSession{Name: "ubuntu", X11Name: "ubuntu-xorg", GDMConfig: "/etc/gdm3/custom.conf"}); !strings.Contains(script, "'ubuntu-xorg'") || strings.Contains(script, "'ubuntu'") {
		t.Fatalf("x11 autologin does not select the X11 entry: %s", script)
	}
	if gnome.gate != "" || strings.Join(gnome.sessionTypes, ",") != "wayland,x11" {
		t.Fatal("deriving the X11 variant changed the Wayland profile")
	}
	want := x11.expectedLock(true)
	if _, err := parseActionDesktop(x11, []byte(strings.Join(desktopFields(x11, "wayland", "GNOME", want), "\n")), want); err == nil {
		t.Fatal("a Wayland session was accepted for the X11 variant")
	}
}
