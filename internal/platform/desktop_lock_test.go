// SPDX-License-Identifier: Apache-2.0

package platform

import "testing"

func TestLockOfDesktopFollowsNativeTable(t *testing.T) {
	for _, test := range []struct {
		desktop    string
		lock       DesktopLock
		name       string
		observable bool
	}{
		{"GNOME", DesktopLockHinted, "GNOME", true},
		{"ubuntu:GNOME", DesktopLockHinted, "GNOME", true},
		{"COSMIC", DesktopLockLogindOnly, "COSMIC", true},
		{"X-Cinnamon", DesktopLockUnreported, "X-Cinnamon", false},
		{"Hyprland", DesktopLockIgnoresLogind, "Hyprland", false},
		{"Hyprland:" + string(make([]byte, 300)), DesktopLockIgnoresLogind, "Hyprland", false},
		{"KDE", DesktopLockUnknown, "", false},
		{"gnome", DesktopLockUnknown, "", false},
		{"", DesktopLockUnknown, "", false},
	} {
		lock, name := LockOfDesktop(test.desktop)
		if lock != test.lock || name != test.name || lock.EveryLockObservable() != test.observable {
			t.Errorf("%.20q: lock=%v name=%q observable=%v", test.desktop, lock, name, lock.EveryLockObservable())
		}
	}
}

// A desktop whose locker ignores logind keeps the Lock capability (account
// lock and the session lock request still run); the fact only lets the
// server refuse session-only locks, and it must match the lock table.
func TestSessionLockUnsupportedKeepsLockCapability(t *testing.T) {
	found := false
	for _, release := range registry {
		if release.Desktop.SessionLockUnsupported == "" {
			continue
		}
		found = true
		if !release.Supported(Lock) {
			t.Errorf("%s: session-lock fact gated the whole Lock capability", release.Name)
		}
		if lock, _ := LockOfDesktop(release.Desktop.Name); lock != DesktopLockIgnoresLogind {
			t.Errorf("%s: desktop %q is not a logind-ignoring desktop in the lock table", release.Name, release.Desktop.Name)
		}
	}
	if !found {
		t.Fatal("no release records the proven Omarchy session-lock fact")
	}
}
