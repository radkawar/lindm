// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"

	"lindm/internal/platform"
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

// lockReporting admits only desktops on which every lock is visible to lindm
// (platform.LockOfDesktop, keyed on XDG_CURRENT_DESKTOP): GNOME through
// LockedHint, COSMIC through the logind signals LockMonitor observes. On every
// other desktop a lock would not end sharing, so no session is offered.
func lockReporting(currentDesktop string) error {
	if lock, _ := platform.LockOfDesktop(currentDesktop); lock.EveryLockObservable() {
		return nil
	}
	return unavailable("session_lock_state_unreported", nil)
}
