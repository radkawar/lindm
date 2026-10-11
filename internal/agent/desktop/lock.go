package desktop

import (
	"context"
	"strings"
)

// LockMonitor observes lock requests for one logind session. It complements
// the executor's logind LockedHint check: desktops whose locker never calls
// SetLockedHint still receive every lock through logind's Session.Lock signal
// or Manager.PrepareForSleep when they lock only on those.
type LockMonitor interface {
	// Subscribe registers for lock requests of logind session id before it
	// returns, so no request after a successful return is missed.
	Subscribe(ctx context.Context, sessionID string) (LockSubscription, error)
}

// LockSubscription is one registered lock watch.
type LockSubscription interface {
	// Locked delivers a nonsecret detail for each observed lock request. It
	// is closed when the watch is lost, which ends every session.
	Locked() <-chan string
	// Close stops the watch.
	Close() error
}

// Lock-observation details reported as SESSION_LOCKED end details.
const (
	lockDetailLogindLock = "logind_lock"
	lockDetailSleep      = "logind_prepare_for_sleep"
)

// lockReporting is the lock-observability capability table, keyed on
// XDG_CURRENT_DESKTOP: the freedesktop desktop identification that
// xdg-desktop-portal itself uses to select portal backends. Lock reporting is
// a property of the desktop's locker, which no root-observable logind
// property exposes before a lock happens. A desktop is listed only when every
// lock path is observable:
//   - GNOME: gnome-shell's screen shield sets logind LockedHint on every lock
//     (natively observed on Ubuntu 24.04 GNOME 46 and Fedora 44 GNOME 50).
//   - COSMIC (epoch 1.x): cosmic-greeter never sets LockedHint, but it locks
//     only on logind Session.Lock and Manager.PrepareForSleep, which
//     LockMonitor observes. Its lock paths all go through logind: the
//     Super+Escape and idle actions run the LockScreen system action,
//     `loginctl lock-session` by default (cosmic-settings-daemon
//     system_actions.ron, cosmic-idle lock_screen); the panel power applet
//     calls logind Session.Lock; suspend emits PrepareForSleep.
//
// Every other desktop, including Cinnamon 6.6 (cinnamon-screensaver also
// locks directly on its own idle and keybinding paths and never sets
// LockedHint) and Hyprland (Omarchy's Quickshell lock bypasses logind
// entirely), is unreported: a lock there would not end a session, so none is
// offered.
func lockReporting(currentDesktop string) error {
	for _, name := range strings.Split(currentDesktop, ":") {
		switch name {
		case "GNOME", "COSMIC":
			return nil
		}
	}
	return unavailable("session_lock_state_unreported", nil)
}
