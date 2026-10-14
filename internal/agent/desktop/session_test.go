// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/rpcreason"
)

const (
	modeView    = agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW
	modeControl = agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
)

func directiveFor(invitation *agentv1.AssistanceInvitation) *agentv1.AssistanceDirective {
	return &agentv1.AssistanceDirective{Invitation: invitation}
}

func TestConsentAllowOffersAppliesAnswerOnceAndTerminates(t *testing.T) {
	h := newHarness(t)
	inv := invitation(modeView, time.Minute, 10*time.Minute)

	h.sync(directiveFor(inv))
	prompt := h.notifier.next(t, "Remote assistance request")
	if !prompt.notification.Critical || !prompt.notification.Persistent || !prompt.notification.Reshow {
		t.Fatalf("prompt must be critical, persistent and reshown: %+v", prompt.notification)
	}
	if body := prompt.notification.Body; !strings.Contains(body, "Olga Operator") || !strings.Contains(body, "printer <setup> & drivers") || !strings.Contains(body, "Control is not requested") {
		t.Fatalf("prompt body lacks operator, reason or control statement: %q", body)
	}
	report := h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	if report.GetOfferSdp() != "" {
		t.Fatal("PROMPTED must not carry an offer")
	}
	if h.portal.openCount() != 0 {
		t.Fatal("portal opened before product consent")
	}
	prompt.result <- actionAllow

	report = h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	if report.GetOfferSdp() != testOffer || report.GetControlGranted() {
		t.Fatalf("offered report = %v", report)
	}
	if made := h.peers.made; len(made) != 1 || made[0].Input || len(made[0].ICEServers) != 1 {
		t.Fatalf("VIEW peer config = %+v", made)
	}
	indicator := h.notifier.next(t, "Remote assistance in progress")
	// The body never repeats the title (owner demo polish).
	if indicator.notification.Body != "Olga Operator is viewing your screen." {
		t.Fatalf("indicator body = %q", indicator.notification.Body)
	}

	answered := &agentv1.AssistanceDirective{Invitation: inv, AnswerSdp: testAnswer}
	h.sync(answered)
	h.sync(answered)
	h.sync(answered)
	deadline := time.Now().Add(5 * time.Second)
	for {
		answers, _ := h.peers.peer.state()
		if len(answers) == 1 && answers[0] == testAnswer {
			break
		}
		if len(answers) > 1 || time.Now().After(deadline) {
			t.Fatalf("answers applied = %q, want exactly one", answers)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(h.peers.peer.connected)
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE)
	h.sync(answered)
	if answers, _ := h.peers.peer.state(); len(answers) != 1 {
		t.Fatalf("answer reapplied: %q", answers)
	}

	h.sync(&agentv1.AssistanceDirective{Invitation: inv, AnswerSdp: testAnswer, Terminate: true})
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	if _, closes := h.peers.peer.state(); closes != 1 {
		t.Fatalf("peer closes = %d", closes)
	}
	if _, closes := h.portal.grant.snapshot(); closes != 1 {
		t.Fatalf("portal closes = %d", closes)
	}
	select {
	case <-h.capturer.capture.closed:
	default:
		t.Fatal("capture not stopped")
	}
	if !indicator.isClosed() {
		t.Fatal("indicator not withdrawn")
	}
	ended := h.notifier.next(t, "Remote assistance ended")
	if ended.notification.Body != "Stopped by the operator." {
		t.Fatalf("end notice = %q", ended.notification.Body)
	}
	// The ENDED report keeps flowing while the executor still lists it.
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true})
	requests := h.client.requests
	last := requests[len(requests)-1]
	if len(last.GetReports()) != 1 || last.GetReports()[0].GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		t.Fatalf("last request reports = %v", last.GetReports())
	}
	// Absent from directives: forgotten; a reappearing directive is answered ENDED.
	h.sync()
	if _, ok := h.helper.sessions[testSessionID]; ok {
		t.Fatal("ended session not forgotten")
	}
	h.sync(directiveFor(inv))
	if report := h.report(); report.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		t.Fatalf("reappearing directive restarted the session: %v", report)
	}
}

func TestConsentDeclineAndDismissEndDeclined(t *testing.T) {
	for _, action := range []string{actionDecline, "", "default"} {
		t.Run("action="+action, func(t *testing.T) {
			h := newHarness(t)
			h.sync(directiveFor(invitation(modeControl, time.Minute, 10*time.Minute)))
			prompt := h.notifier.next(t, "Remote assistance request")
			h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
			prompt.result <- action
			h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)
			if h.portal.openCount() != 0 {
				t.Fatal("portal opened without consent")
			}
		})
	}
}

func TestConsentTimeoutClosesPrompt(t *testing.T) {
	h := newHarness(t)
	h.sync(directiveFor(invitation(modeView, 150*time.Millisecond, 10*time.Minute)))
	prompt := h.notifier.next(t, "Remote assistance request")
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT)
	if !prompt.isClosed() {
		t.Fatal("prompt left visible after the consent deadline")
	}
	h.notifier.next(t, "Remote assistance ended")
}

func TestConsentDeadlineCoversPortalDialog(t *testing.T) {
	h := newHarness(t)
	h.portal.block = true
	h.sync(directiveFor(invitation(modeView, 300*time.Millisecond, 10*time.Minute)))
	h.notifier.next(t, "Remote assistance request").result <- actionAllow
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT)
}

func TestPortalCancelEndsDeclined(t *testing.T) {
	h := newHarness(t)
	h.portal.err = ErrPortalCancelled
	h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	h.notifier.next(t, "Remote assistance request").result <- actionAllow
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)
	if report.GetEndDetail() != "portal_cancelled" {
		t.Fatalf("detail = %q", report.GetEndDetail())
	}
}

func TestPortalUnavailableAndMissingActionsEndUnavailable(t *testing.T) {
	t.Run("portal", func(t *testing.T) {
		h := newHarness(t)
		h.portal.err = unavailable("portal_unavailable", errors.New("no portal"))
		h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
		h.notifier.next(t, "Remote assistance request").result <- actionAllow
		report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
		if report.GetEndDetail() != "portal_unavailable" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
	})
	t.Run("actions", func(t *testing.T) {
		h := newHarness(t)
		h.notifier.capabilities = []string{"body"}
		h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
		report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
		if report.GetEndDetail() != "notification_actions_unavailable" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
		select {
		case notice := <-h.notifier.posted:
			t.Fatalf("posted %q without action support", notice.notification.Summary)
		default:
		}
	})
	// cosmic-notifications advertises actions but shows no buttons, and
	// activating its card invokes the first action (allow): pop2404-assistance-04.
	t.Run("hidden actions", func(t *testing.T) {
		h := newHarness(t)
		h.notifier.server = "cosmic-notifications"
		h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
		report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
		if report.GetEndDetail() != "notification_actions_hidden" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
		select {
		case notice := <-h.notifier.posted:
			t.Fatalf("posted %q on a server that hides its actions", notice.notification.Summary)
		default:
		}
	})
	t.Run("capture", func(t *testing.T) {
		h := newHarness(t)
		h.capturer.err = unavailable("gst_element_missing:vp8enc", nil)
		h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
		h.notifier.next(t, "Remote assistance request").result <- actionAllow
		report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
		if report.GetEndDetail() != "gst_element_missing:vp8enc" {
			t.Fatalf("detail = %q", report.GetEndDetail())
		}
		if _, closes := h.portal.grant.snapshot(); closes != 1 {
			t.Fatal("portal session not closed after capture failure")
		}
	})
}

// A desktop whose portal lacks the requested interface (Cinnamon's
// xdg-desktop-portal-xapp has no ScreenCast; xdg-desktop-portal-hyprland has no
// RemoteDesktop) ends the session UNAVAILABLE before any consent prompt, and a
// CONTROL request is never downgraded to VIEW.
func TestPortalCapabilityGateRefusesBeforeConsent(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   agentv1.AssistanceMode
		detail string
	}{
		{"no_screencast", modeView, "portal_screencast_unavailable"},
		{"no_remote_desktop", modeControl, "portal_remote_desktop_unavailable"},
		{"no_monitor_source", modeView, "portal_monitor_source_unavailable"},
		{"no_input_devices", modeControl, "portal_input_devices_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			h.portal.refuse = map[agentv1.AssistanceMode]error{test.mode: unavailable(test.detail, errors.New("org.freedesktop.DBus.Error.InvalidArgs"))}
			h.sync(directiveFor(invitation(test.mode, time.Minute, 10*time.Minute)))
			report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
			if report.GetEndDetail() != test.detail || report.GetControlGranted() {
				t.Fatalf("detail = %q control=%v", report.GetEndDetail(), report.GetControlGranted())
			}
			select {
			case notice := <-h.notifier.posted:
				t.Fatalf("posted %q for a mode the portal cannot serve", notice.notification.Summary)
			default:
			}
			if h.portal.openCount() != 0 {
				t.Fatal("portal dialog opened for a refused mode")
			}
		})
	}
	t.Run("view_unaffected_by_missing_remote_desktop", func(t *testing.T) {
		h := newHarness(t)
		h.portal.refuse = map[agentv1.AssistanceMode]error{modeControl: unavailable("portal_remote_desktop_unavailable", nil)}
		h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
		h.notifier.next(t, "Remote assistance request")
	})
}

func TestPortalPreflightUsesConsentedPolicyWithoutOpeningSession(t *testing.T) {
	h := newHarness(t)
	inv := tierOneInvitation(modeControl)
	inv.EffectiveCapabilities.Keyboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	inv.RequestedCapabilities.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	h.sync(directiveFor(inv))
	prompt := h.notifier.next(t, "Remote assistance request")
	h.portal.mu.Lock()
	checked := append([]PortalRequest(nil), h.portal.checked...)
	h.portal.mu.Unlock()
	if len(checked) != 1 {
		t.Fatalf("preflight count = %d", len(checked))
	}
	request := checked[0]
	if request.Mode != modeControl || request.Policy.GetKeyboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF ||
		request.Policy.GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED ||
		request.Policy.GetDisplay() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON ||
		request.Policy.GetMessages() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON {
		t.Fatalf("preflight lost consented policy: %+v", request)
	}
	if h.portal.openCount() != 0 {
		t.Fatal("preflight opened a native session before product consent")
	}
	if !strings.Contains(prompt.notification.Body, "Keyboard control is not requested") ||
		!strings.Contains(prompt.notification.Body, "but not read it") {
		t.Fatalf("product prompt differs from preflight: %q", prompt.notification.Body)
	}
	prompt.result <- actionDecline
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)
	if h.portal.openCount() != 0 {
		t.Fatal("declined product consent opened a native session")
	}
	if request.Lifetime == nil || request.Lifetime.Err() == nil {
		t.Fatal("declined session retained its transfer lifetime")
	}
}

func TestPortalClosedEndsSession(t *testing.T) {
	h := newHarness(t)
	h.offered(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	close(h.portal.grant.closed)
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED)
}

func TestCaptureExitAfterPortalCloseIsPortalClosed(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.captureGrace = 5 * time.Second
	h.offered(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	close(h.capturer.capture.packets)
	close(h.portal.grant.closed)
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED)
}

func TestPeerFailureEndsConnectionFailed(t *testing.T) {
	h := newHarness(t)
	h.offered(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	close(h.peers.peer.failed)
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED)
}

func TestNonRelayAnswerEndsConnectionFailed(t *testing.T) {
	h := newHarness(t)
	inv := invitation(modeView, time.Minute, 10*time.Minute)
	h.offered(directiveFor(inv))
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, AnswerSdp: "v=0\r\na=candidate:1 1 udp 2 10.0.0.9 5000 typ host\r\n"})
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED)
	if report.GetEndDetail() != "answer_non_relay_candidate" {
		t.Fatalf("detail = %q", report.GetEndDetail())
	}
	if answers, _ := h.peers.peer.state(); len(answers) != 0 {
		t.Fatal("non-relay answer applied")
	}
}

func TestIndicatorStopAndRepost(t *testing.T) {
	h := newHarness(t)
	h.offered(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	first := h.notifier.next(t, "Remote assistance in progress")
	first.result <- "" // dismissed
	second := h.notifier.next(t, "Remote assistance in progress")
	second.result <- actionStop
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
	if report.GetEndDetail() != "local_stop" {
		t.Fatalf("detail = %q", report.GetEndDetail())
	}
}

func TestExpiryEndsSession(t *testing.T) {
	h := newHarness(t)
	h.offered(directiveFor(invitation(modeView, time.Minute, 400*time.Millisecond)))
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED)
}

func TestExecutorLossEndsAfterThirtySeconds(t *testing.T) {
	h := newHarness(t)
	inv := invitation(modeView, time.Minute, 10*time.Minute)
	h.offered(directiveFor(inv))
	h.client.set(func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("executor down"))
	})
	h.clock.Advance(29 * time.Second)
	h.helper.syncOnce(h.ctx, h.ctx)
	if h.report().GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		t.Fatal("session ended before the 30 s executor-loss window")
	}
	h.clock.Advance(time.Second)
	h.helper.syncOnce(h.ctx, h.ctx)
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
	if report.GetEndDetail() != "executor_unreachable" {
		t.Fatalf("detail = %q", report.GetEndDetail())
	}
}

func TestExecutorRefusalEndsImmediately(t *testing.T) {
	h := newHarness(t)
	h.offered(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	h.client.set(func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
		err := connect.NewError(connect.CodePermissionDenied, errors.New("locked"))
		rpcreason.Set(err, "no_graphical_session")
		return nil, err
	})
	h.helper.syncOnce(h.ctx, h.ctx)
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED)
	if report.GetEndDetail() != "no_graphical_session" {
		t.Fatalf("detail = %q", report.GetEndDetail())
	}
}

func TestDirectiveAbsenceEndsAndForgetsSession(t *testing.T) {
	h := newHarness(t)
	h.offered(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	s := h.helper.sessions[testSessionID]
	h.sync()
	if _, ok := h.helper.sessions[testSessionID]; ok {
		t.Fatal("unauthorized session still held")
	}
	report, _ := s.report()
	if report.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
		t.Fatalf("report = %v", report)
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not finish")
	}
	if _, closes := h.portal.grant.snapshot(); closes != 1 {
		t.Fatal("portal session not closed")
	}
}

func TestPromptCancelledWhenDirectiveDisappears(t *testing.T) {
	h := newHarness(t)
	h.sync(directiveFor(invitation(modeView, time.Minute, 10*time.Minute)))
	prompt := h.notifier.next(t, "Remote assistance request")
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	s := h.helper.sessions[testSessionID]
	h.sync()
	<-s.done
	if !prompt.isClosed() {
		t.Fatal("prompt not withdrawn")
	}
}

func TestUnknownTerminatedSessionIsReportedEnded(t *testing.T) {
	h := newHarness(t)
	inv := invitation(modeControl, time.Minute, 10*time.Minute)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true, TerminateCause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED})
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true, TerminateCause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED})
	requests := h.client.requests
	reports := requests[len(requests)-1].GetReports()
	if len(reports) != 1 || reports[0].GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED ||
		reports[0].GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED {
		t.Fatalf("reports = %v", reports)
	}
	select {
	case notice := <-h.notifier.posted:
		t.Fatalf("terminated invitation prompted: %q", notice.notification.Summary)
	default:
	}
}

func TestLocalSessionMismatchRefusesDirectives(t *testing.T) {
	h := newHarness(t)
	h.client.set(func(*agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
		local := localSession()
		local.Uid = testUID + 1
		return &agentv1.SyncSessionResponse{
			Directives:   []*agentv1.AssistanceDirective{directiveFor(invitation(modeView, time.Minute, 10*time.Minute))},
			LocalSession: local,
		}, nil
	})
	h.helper.syncOnce(h.ctx, h.ctx)
	if len(h.helper.sessions) != 0 {
		t.Fatal("helper accepted a directive bound to another uid")
	}
}

func TestControlGrantedForwardsInputAndReleasesHeld(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control = true
	inv := invitation(modeControl, time.Minute, 10*time.Minute)
	report := h.offered(directiveFor(inv))
	if !report.GetControlGranted() {
		t.Fatal("control_granted not reported")
	}
	if made := h.peers.made; len(made) != 1 || !made[0].Input {
		t.Fatalf("CONTROL peer config = %+v", made)
	}
	indicator := h.notifier.next(t, "Remote assistance in progress")
	if !strings.Contains(indicator.notification.Body, "viewing and controlling") {
		t.Fatalf("indicator body = %q", indicator.notification.Body)
	}
	for _, message := range []string{
		`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"button","b":"left","down":true,"display":"monitor-1","generation":1}`,
		`{"t":"move","x":0.5,"y":0.25,"display":"monitor-1","generation":1}`,
		`{"t":"key","code":"Power","down":true,"display":"monitor-1","generation":1}`,
		`not json`,
	} {
		h.peers.peer.input <- []byte(message)
	}
	waitInjected(t, h.portal.grant, 3)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true})
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	events, _ := h.portal.grant.snapshot()
	if len(events) != 5 {
		t.Fatalf("injected = %+v, want 3 events and 2 releases", events)
	}
	releasedKey, releasedButton := false, false
	for _, event := range events[3:] {
		switch {
		case event.kind == inputKey && event.Keycode == 30 && !event.Down:
			releasedKey = true
		case event.kind == inputButton && event.Button == btnLeft && !event.Down:
			releasedButton = true
		}
	}
	if !releasedKey || !releasedButton {
		t.Fatalf("held input not released: %+v", events[3:])
	}
}

func TestControlRequestedButNotGrantedIsViewOnly(t *testing.T) {
	h := newHarness(t)
	report := h.offered(directiveFor(invitation(modeControl, time.Minute, 10*time.Minute)))
	if report.GetControlGranted() {
		t.Fatal("control_granted without portal devices")
	}
	if made := h.peers.made; len(made) != 1 || made[0].Input {
		t.Fatalf("peer config = %+v, want no data channel", made)
	}
}

func waitInjected(t *testing.T, grant *fakeGrant, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if events, _ := grant.snapshot(); len(events) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	events, _ := grant.snapshot()
	t.Fatalf("injected %d events, want %d", len(events), n)
}

func TestRelayOnly(t *testing.T) {
	for name, tc := range map[string]struct {
		sdp  string
		want string
	}{
		"relay": {sdp: testOffer},
		"host":  {sdp: testOffer + "a=candidate:2 1 udp 2 10.0.0.1 5000 typ host\r\n", want: "non_relay_candidate"},
		"none":  {sdp: "v=0\r\n", want: "no_relay_candidate"},
	} {
		t.Run(name, func(t *testing.T) {
			err := relayOnly(tc.sdp)
			if (err == nil) != (tc.want == "") || (err != nil && err.Error() != tc.want) {
				t.Fatalf("relayOnly = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSanitizeDetail(t *testing.T) {
	if got := sanitizeDetail("a\nb\u00e9"); got != "a_b_" {
		t.Fatalf("sanitizeDetail = %q", got)
	}
	if got := sanitizeDetail(strings.Repeat("x", 300)); len(got) != maxEndDetail {
		t.Fatalf("len = %d", len(got))
	}
}

func TestRunShutdownEndsSessionsAndReportsOnce(t *testing.T) {
	h := newHarness(t)
	h.helper.idleInterval, h.helper.activeInterval = 5*time.Millisecond, 5*time.Millisecond
	h.client.set(h.directives(directiveFor(invitation(modeView, time.Minute, 10*time.Minute))))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.helper.Run(ctx) }()
	prompt := h.notifier.next(t, "Remote assistance request")
	deadline := time.Now().Add(5 * time.Second)
	for !h.client.sawPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED) {
		if time.Now().After(deadline) {
			t.Fatal("PROMPTED never reported to the executor")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if !prompt.isClosed() {
		t.Fatal("prompt not withdrawn on shutdown")
	}
	last := h.client.last()
	if len(last.GetReports()) != 1 || last.GetReports()[0].GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED ||
		last.GetReports()[0].GetEndDetail() != "helper_stopped" {
		t.Fatalf("final reports = %v", last.GetReports())
	}
}

// Notice bodies are sentences that never repeat their titles.
func TestNoticeBodiesDoNotRepeatTitles(t *testing.T) {
	for cause := range agentv1.AssistanceEndCause_name {
		c := agentv1.AssistanceEndCause(cause)
		if c == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
			continue
		}
		body := sentence(causeText(c))
		if body == "" || strings.Contains(strings.ToLower(body), "remote assistance ended") || !strings.HasSuffix(body, ".") || strings.ToUpper(body[:1]) != body[:1] {
			t.Errorf("%s ended body = %q", c, body)
		}
	}
}
