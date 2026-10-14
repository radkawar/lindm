// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"strings"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const indicatorSummary = "Remote assistance in progress"

// startGuidance activates a CONTROL session with elevation and posts the
// operator's guidance, an in-session notice awaiting a local decision.
func startGuidance(t *testing.T) (*harness, *fakeNotice, *fakeNotice, *agentv1.AssistanceInvitation) {
	t.Helper()
	h := newHarness(t)
	h.portal.grant.control, h.portal.grant.clipboard = true, true
	inv := controlWithElevation()
	activateTierOne(h, inv)
	indicator := h.notifier.next(t, indicatorSummary)
	guidance := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: guidance})
	if result := waitCommand(h, guidance.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("guidance = %v", result)
	}
	return h, indicator, h.notifier.next(t, "Remote control paused for your password"), inv
}

// GNOME shows one banner at a time and never hides the critical indicator on
// its own, so an in-session notice replaces it and carries its disclosure and
// Stop; resolving the notice brings the indicator back at once, and Stop on
// the reposted indicator still ends the session.
func TestInSessionNoticeTakesTheIndicatorBannerUntilResolved(t *testing.T) {
	h, indicator, notice, _ := startGuidance(t)
	if !indicator.isClosed() {
		t.Fatal("indicator stayed posted ahead of the in-session notice")
	}
	actions := notice.notification.Actions
	if len(actions) > maxPromptActions || actions[len(actions)-1].Key != actionStop || !notice.notification.Critical || !notice.notification.Persistent {
		t.Fatalf("notice actions = %+v", notice.notification)
	}
	if !strings.Contains(notice.notification.Body, "is viewing and controlling your screen.") {
		t.Fatalf("notice lacks the indicator disclosure: %q", notice.notification.Body)
	}
	notice.result <- actionElevationResume
	reposted := h.notifier.next(t, indicatorSummary)
	reposted.result <- actionStop
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
}

// A dismissed notice gives the banner back at once; its repost takes it again.
func TestDismissedInSessionNoticeRepostsTheIndicatorImmediately(t *testing.T) {
	h, _, notice, _ := startGuidance(t)
	notice.result <- ""
	indicator := h.notifier.next(t, indicatorSummary)
	again := h.notifier.next(t, "Remote control paused for your password")
	waitFor(t, "indicator withdrawn for the reposted notice", indicator.isClosed)
	again.result <- actionElevationResume
	h.notifier.next(t, indicatorSummary)
}

// Stop on the in-session notice ends the session; nothing reposts the
// indicator for an ended session.
func TestStopOnInSessionNoticeEndsTheSession(t *testing.T) {
	h, _, notice, _ := startGuidance(t)
	notice.result <- actionStop
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
	assertNoIndicatorPosted(t, h)
}

// The session ending while the notice is pending withdraws the notice and
// posts no indicator for the ended session.
func TestSessionEndingMidNoticeWithdrawsIt(t *testing.T) {
	h, _, notice, inv := startGuidance(t)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true})
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	waitFor(t, "notice withdrawn", notice.isClosed)
	assertNoIndicatorPosted(t, h)
}

func assertNoIndicatorPosted(t *testing.T, h *harness) {
	t.Helper()
	timeout := time.After(100 * time.Millisecond)
	for {
		select {
		case posted := <-h.notifier.posted:
			if posted.notification.Summary == indicatorSummary {
				t.Fatal("indicator reposted for an ended session")
			}
		case <-timeout:
			return
		}
	}
}

func TestInSessionNoticeKeepsRoomForStop(t *testing.T) {
	s := &session{invitation: &agentv1.AssistanceInvitation{OperatorDisplay: "Olga"}}
	actions := []NotificationAction{{Key: "a"}, {Key: "b"}, {Key: "c"}}
	if _, err := s.inSessionNotification(&sessionResources{}, Notification{Actions: actions}); err == nil {
		t.Fatal("a notice with no room for Stop was accepted")
	}
}
