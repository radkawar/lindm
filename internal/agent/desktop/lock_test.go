// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"errors"
	"slices"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestLockReportingAcceptsOnlyQualifiedDesktops(t *testing.T) {
	for desktop, reported := range map[string]bool{
		"GNOME":                 true,
		"ubuntu:GNOME":          true,
		"COSMIC":                true,
		"X-Cinnamon":            false,
		"Hyprland":              false,
		"KDE":                   false,
		"":                      false,
		"gnome":                 false,
		"GNOME-Flashback:Unity": false,
	} {
		err := lockReporting(desktop)
		if (err == nil) != reported {
			t.Fatalf("%q: lock reporting error %v, want reported=%v", desktop, err, reported)
		}
		var endErr *EndError
		if err != nil && (!errors.As(err, &endErr) || endErr.Cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE || endErr.Detail != "session_lock_state_unreported") {
			t.Fatalf("%q: refusal is not a visible UNAVAILABLE reason: %v", desktop, err)
		}
	}
}

// Cinnamon 6.6 and Hyprland lock without telling logind; a session there
// would keep sharing a locked screen, so it is refused before any prompt.
func TestUnreportedDesktopRefusedBeforeConsent(t *testing.T) {
	for _, desktop := range []string{"X-Cinnamon", "Hyprland"} {
		t.Run(desktop, func(t *testing.T) {
			h := newDesktopHarness(t, desktop)
			h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
			report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
			if report.GetEndDetail() != "session_lock_state_unreported" {
				t.Fatalf("detail = %q", report.GetEndDetail())
			}
			select {
			case notice := <-h.notifier.posted:
				t.Fatalf("posted %q on a desktop whose lock is unobservable", notice.notification.Summary)
			default:
			}
			if h.portal.openCount() != 0 {
				t.Fatal("portal dialog opened on a desktop whose lock is unobservable")
			}
		})
	}
	t.Run("missing_remote_desktop_reported_first", func(t *testing.T) {
		h := newDesktopHarness(t, "Hyprland")
		h.portal.refuse = map[agentv1.AssistanceMode]error{modeControl: unavailable("portal_remote_desktop_unavailable", nil)}
		h.sync(directiveFor(invitation(modeControl, time.Minute, 10*time.Minute)))
		if report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE); report.GetEndDetail() != "portal_remote_desktop_unavailable" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
	})
}

// COSMIC never sets LockedHint; cosmic-greeter locks on logind's Lock signal,
// which the helper observes for the bound session and ends capture on.
func TestLogindLockSignalEndsSessionLocked(t *testing.T) {
	for _, detail := range []string{lockDetailLogindLock, lockDetailSleep} {
		t.Run(detail, func(t *testing.T) {
			h := newDesktopHarness(t, "COSMIC")
			directive := directiveFor(invitation(modeView, time.Minute, 10*time.Minute))
			h.offered(directive)
			if !slices.Equal(h.locks.subscribed, []string{localSession().GetLogindSessionId()}) {
				t.Fatalf("lock watch subscribed %v, want the bound logind session once", h.locks.subscribed)
			}
			h.locks.watch().locked <- detail
			h.sync(directive)
			report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED)
			if report.GetEndDetail() != detail {
				t.Fatalf("detail = %q", report.GetEndDetail())
			}
			if _, closes := h.portal.grant.snapshot(); closes != 1 {
				t.Fatal("portal session not closed after the lock")
			}
		})
	}
}

func TestLostLockWatchEndsSessionsAndBlocksPrompts(t *testing.T) {
	t.Run("lost", func(t *testing.T) {
		h := newDesktopHarness(t, "COSMIC")
		directive := directiveFor(invitation(modeView, time.Minute, 10*time.Minute))
		h.offered(directive)
		close(h.locks.watch().locked)
		h.sync(directive)
		if report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED); report.GetEndDetail() != "lock_watch_lost" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		h := newDesktopHarness(t, "COSMIC")
		h.locks.err = errors.New("system bus unavailable")
		h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
		if report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE); report.GetEndDetail() != "lock_watch_unavailable" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
		select {
		case notice := <-h.notifier.posted:
			t.Fatalf("posted %q without a lock watch", notice.notification.Summary)
		default:
		}
	})
}
