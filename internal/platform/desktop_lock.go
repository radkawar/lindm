package platform

import "strings"

// DesktopLock is how a desktop's screen locker relates to logind, the only
// lock interface lindm's root executor and session helper use.
type DesktopLock int

const (
	// DesktopLockUnknown: no native observation; lindm cannot tell whether a
	// logind lock request engages the locker or whether every lock is seen.
	DesktopLockUnknown DesktopLock = iota
	// DesktopLockHinted: the locker engages on logind Session.Lock and sets
	// LockedHint on every lock, so both are observable.
	DesktopLockHinted
	// DesktopLockLogindOnly: the locker engages on logind Session.Lock and
	// PrepareForSleep and every lock path goes through logind, but it never
	// sets LockedHint. A lock is observable as a logind signal, not as state.
	DesktopLockLogindOnly
	// DesktopLockUnreported: the locker engages on logind Session.Lock but
	// never sets LockedHint and also locks without logind.
	DesktopLockUnreported
	// DesktopLockIgnoresLogind: a logind lock request does not engage the
	// desktop's locker at all.
	DesktopLockIgnoresLogind
)

// LockOfDesktop classifies an XDG_CURRENT_DESKTOP value (colon-separated
// names, the identification xdg-desktop-portal uses to select backends) by
// the natively observed table below; the first listed name wins and is
// returned as the canonical table name ("" when none is listed).
//   - GNOME: gnome-shell's shield sets LockedHint on every lock (Ubuntu 24.04
//     GNOME 46, Fedora 44 GNOME 50).
//   - COSMIC: cosmic-greeter (Pop!_OS 24.04: 0.1.0 ae627ab, 1.10.0 98df07d)
//     locks only on logind Session.Lock and PrepareForSleep; Super+Escape and
//     idle run `loginctl lock-session`, the panel applet calls Session.Lock;
//     it never sets LockedHint. logind LockSessions engaged it natively
//     (pop2404-lock-quarantine-11).
//   - X-Cinnamon: cinnamon-screensaver 6.6 engages on logind Lock but never
//     sets LockedHint and also locks directly (Mint 22.3,
//     mint223-lock-quarantine-01).
//   - Hyprland: logind LockSessions left Omarchy 4.0.4's Quickshell lock
//     disengaged (omarchy404-lock-quarantine-01); Hyprland has no logind lock
//     listener unless its locker adds one.
func LockOfDesktop(currentDesktop string) (DesktopLock, string) {
	for _, name := range strings.Split(currentDesktop, ":") {
		switch name {
		case "GNOME":
			return DesktopLockHinted, name
		case "COSMIC":
			return DesktopLockLogindOnly, name
		case "X-Cinnamon":
			return DesktopLockUnreported, name
		case "Hyprland":
			return DesktopLockIgnoresLogind, name
		}
	}
	return DesktopLockUnknown, ""
}

// EveryLockObservable reports whether every lock of the desktop is visible to
// lindm, as LockedHint or as a logind lock signal.
func (l DesktopLock) EveryLockObservable() bool {
	return l == DesktopLockHinted || l == DesktopLockLogindOnly
}
