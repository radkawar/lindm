// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func tierOneInvitation(mode agentv1.AssistanceMode) *agentv1.AssistanceInvitation {
	inv := invitation(mode, time.Minute, 10*time.Minute)
	policy := &agentv1.AssistancePolicy{Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, Keyboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, Display: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, Messages: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}
	inv.RequestedCapabilities, inv.EffectiveCapabilities = policy, proto.CloneOf(policy)
	return inv
}

func activateTierOne(h *harness, inv *agentv1.AssistanceInvitation) {
	h.t.Helper()
	h.offered(directiveFor(inv))
	close(h.peers.peer.connected)
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE)
}

func newTestCommand(h *harness, id int, kind agentv1.AssistanceCommandKind) *agentv1.AssistanceCommand {
	return &agentv1.AssistanceCommand{RequestId: fmt.Sprintf("bce565bc-e82c-4d13-a433-%012d", id), Kind: kind, Deadline: timestamppb.New(h.clock.Now().Add(20 * time.Second))}
}

func waitCommand(h *harness, id string) *agentv1.AssistanceCommandResult {
	h.t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		report := h.report()
		if result := report.GetCommandResult(); result.GetRequestId() == id {
			return result
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			h.t.Fatalf("no command result for %s: %v", id, report)
			return nil
		}
	}
}

func TestClipboardCommandsAreExplicitDirectionalAndIdempotent(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control, h.portal.grant.clipboard = true, true
	inv := tierOneInvitation(modeControl)
	inv.RequestedCapabilities.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	activateTierOne(h, inv)
	if h.report().GetGrantedCapabilities().GetPolicy().GetClipboard() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED {
		t.Fatal("directional request escalated")
	}
	write := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE)
	write.Text = "explicit operator clipboard text"
	directive := &agentv1.AssistanceDirective{Invitation: inv, Command: write}
	h.sync(directive)
	result := waitCommand(h, write.GetRequestId())
	if result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED || result.GetReason() != "clipboard_selection_set" || result.GetText() != "" {
		t.Fatalf("write = %v", result)
	}
	for range 3 {
		h.sync(directive)
	}
	h.portal.grant.mu.Lock()
	writes := h.portal.grant.writes
	h.portal.grant.mu.Unlock()
	if writes != 1 {
		t.Fatalf("clipboard side effect replayed %d times", writes)
	}
	read := newTestCommand(h, 2, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: read})
	if result := waitCommand(h, read.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED || result.GetText() != "" {
		t.Fatalf("LIMITED clipboard read = %v", result)
	}
	h.sync(directive)
	if result := waitCommand(h, write.GetRequestId()); result.GetReason() != "command_result_expired" {
		t.Fatalf("old command replay = %v", result)
	}
	h.portal.grant.mu.Lock()
	defer h.portal.grant.mu.Unlock()
	if h.portal.grant.writes != 1 {
		t.Fatal("old command repeated clipboard write")
	}
}

func TestClipboardReadContentExpiresExplicitlyAndStopClearsIt(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprintf("stop=%t", stop), func(t *testing.T) {
			h := newHarness(t)
			h.portal.grant.control, h.portal.grant.clipboard, h.portal.grant.text = true, true, "user's private text"
			inv := tierOneInvitation(modeControl)
			activateTierOne(h, inv)
			command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ)
			h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
			if result := waitCommand(h, command.GetRequestId()); result.GetText() != "user's private text" {
				t.Fatalf("read = %v", result)
			}
			if stop {
				h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true})
				h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
			} else {
				h.clock.Advance(21 * time.Second)
			}
			result := h.report().GetCommandResult()
			if result.GetText() != "" || result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
				t.Fatalf("cleared content represented as successful empty clipboard: %v", result)
			}
		})
	}
}

func TestDisplaySwitchOnlyGrantedMonitorReleasesInputAndFencesOldCoordinates(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control = true
	h.portal.grant.streams = []Stream{{NodeID: 42, ID: "monitor-1", Label: "Monitor 1", Width: 1920, Height: 1080}, {NodeID: 43, ID: "monitor-2", Label: "Monitor 2", Width: 1280, Height: 800}}
	second := newFakeCapturer().capture
	h.capturer.captures = []*fakeCapture{h.capturer.capture, second}
	inv := tierOneInvitation(modeControl)
	activateTierOne(h, inv)
	h.peers.peer.input <- []byte(`{"t":"key","code":"ControlLeft","down":true,"display":"monitor-1","generation":1}`)
	waitInjected(t, h.portal.grant, 1)
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY)
	command.DisplayId = "monitor-2"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	if result := waitCommand(h, command.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("switch = %v", result)
	}
	report := h.report()
	if report.GetSelectedDisplayId() != "monitor-2" || report.GetDisplayGeneration() != 2 {
		t.Fatalf("selection = %v", report)
	}
	select {
	case <-h.capturer.capture.closed:
	default:
		t.Fatal("old monitor still captured")
	}
	events, _ := h.portal.grant.snapshot()
	if len(events) != 2 || events[1].Down || events[1].Keycode != 29 {
		t.Fatalf("switch did not release held modifier: %+v", events)
	}
	h.peers.peer.input <- []byte(`{"t":"move","x":0.5,"y":0.5,"display":"monitor-1","generation":1}`)
	h.peers.peer.input <- []byte(`{"t":"move","x":0.25,"y":0.75,"display":"monitor-2","generation":2}`)
	waitInjected(t, h.portal.grant, 3)
	events, _ = h.portal.grant.snapshot()
	if len(events) != 3 || events[2].Display != "monitor-2" {
		t.Fatalf("stale display input crossed switch: %+v", events)
	}
	unknown := newTestCommand(h, 2, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY)
	unknown.DisplayId = "monitor-not-granted"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: unknown})
	if result := waitCommand(h, unknown.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED {
		t.Fatal("ungranted monitor accepted")
	}
	if h.report().GetSelectedDisplayId() != "monitor-2" {
		t.Fatal("ungranted monitor triggered fallback")
	}
}

// GNOME shows no other banner while the critical in-progress notice is on
// screen (fedora44-tier1-14), so a message updates that notice in place and
// keeps its Stop action; it never replaces Stop with a separate notification.
func TestOperatorMessageEscapesBodyAndKeepsStopIndicator(t *testing.T) {
	h := newHarness(t)
	h.notifier.capabilities = []string{"actions", "body-markup"}
	inv := tierOneInvitation(modeView)
	inv.RequestedCapabilities.Messages = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	activateTierOne(h, inv)
	indicator := h.notifier.next(t, "Remote assistance in progress")
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE)
	command.Text = "Hello <b>user</b> & welcome"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	if result := waitCommand(h, command.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("message = %v", result)
	}
	var updated Notification
	select {
	case updated = <-indicator.updates:
	case <-time.After(5 * time.Second):
		t.Fatal("message did not update the in-progress notice")
	}
	if !strings.Contains(updated.Body, "Message from your support operator") || !strings.Contains(updated.Body, "Olga Operator:") || strings.Contains(updated.Body, "<b>") || !strings.Contains(updated.Body, "&lt;b&gt;") ||
		!updated.Critical || !updated.Persistent || len(updated.Actions) != 1 || updated.Actions[0].Key != actionStop || indicator.isClosed() {
		t.Fatalf("unsafe in-progress update: %+v", updated)
	}
	h.clock.Advance(3 * time.Second)
	next := newTestCommand(h, 2, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE)
	next.Text = "Second outstanding message"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: next})
	if result := waitCommand(h, next.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED {
		t.Fatal("LIMITED posted two outstanding messages")
	}
	indicator.result <- actionStop
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
}

func TestUnknownCommandSessionAndExpiredAuthorityNeverOpenPortal(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprintf("unknown=%t", unknown), func(t *testing.T) {
			h := newHarness(t)
			inv := tierOneInvitation(modeControl)
			directive := &agentv1.AssistanceDirective{Invitation: inv, AuthorizedUntil: timestamppb.New(h.clock.Now().Add(-time.Second))}
			if unknown {
				directive.Command = newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ)
			}
			h.sync(directive)
			h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
			if h.portal.openCount() != 0 {
				t.Fatal("unauthorized session opened portal")
			}
		})
	}
}

func TestCapabilityConsentNamesClipboardDirectionsAndNoImplicitGrants(t *testing.T) {
	inv := invitation(modeControl, time.Minute, time.Minute)
	inv.RequestedCapabilities, inv.EffectiveCapabilities = nil, nil
	policy := consentedPolicy(inv)
	if policyEnabled(policy.GetClipboard()) || policyEnabled(policy.GetKeyboard()) || policyEnabled(policy.GetDisplay()) || policyEnabled(policy.GetMessages()) {
		t.Fatal("unspecified capability enabled")
	}
	inv = tierOneInvitation(modeControl)
	limited := proto.CloneOf(inv.RequestedCapabilities)
	limited.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if !strings.Contains(capabilityConsentText(limited), "but not read it") || !strings.Contains(capabilityConsentText(inv.RequestedCapabilities), "explicitly read your clipboard text") {
		t.Fatal("consent omitted direction")
	}
	grant := &fakeGrant{control: true}
	caps := grantedCapabilities(inv.RequestedCapabilities, grant)
	if policyEnabled(caps.GetPolicy().GetClipboard()) || caps.GetClipboardReason() != "portal_clipboard_not_granted" {
		t.Fatal("clipboard granted without native Start flag")
	}
	if caps.GetPolicy().GetDisplay() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED {
		t.Fatal("single monitor claimed switch support")
	}
}

type blockedClipboardGrant struct {
	*fakeGrant
	started chan struct{}
}

func (g *blockedClipboardGrant) ClipboardRead(ctx context.Context) (string, error) {
	close(g.started)
	<-ctx.Done()
	return "", ctx.Err()
}

func TestLocalStopCancelsOutstandingClipboardCommand(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control, h.portal.grant.clipboard = true, true
	blocked := &blockedClipboardGrant{fakeGrant: h.portal.grant, started: make(chan struct{})}
	h.portal.grantOverride = blocked
	inv := tierOneInvitation(modeControl)
	activateTierOne(h, inv)
	indicator := h.notifier.next(t, "Remote assistance in progress")
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("read command did not begin")
	}
	indicator.result <- actionStop
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
	if result := report.GetCommandResult(); result != nil && result.GetText() != "" {
		t.Fatal("stopped command leaked text")
	}
	if _, closes := h.portal.grant.snapshot(); closes != 1 {
		t.Fatal("stop did not revoke portal while command was blocked")
	}
}

func TestCommandBeforeConsentCannotNotifyOrTouchClipboard(t *testing.T) {
	h := newHarness(t)
	inv := tierOneInvitation(modeControl)
	h.sync(directiveFor(inv))
	prompt := h.notifier.next(t, "Remote assistance request")
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE)
	command.Text = "Must not be visible before consent"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	select {
	case posted := <-h.notifier.posted:
		t.Fatalf("preconsent posted %q", posted.notification.Summary)
	default:
	}
	if h.report().GetCommandResult() != nil || h.portal.openCount() != 0 {
		t.Fatal("preconsent command executed")
	}
	prompt.result <- actionDecline
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)
}

func TestCommandIdentityConflictAndHistoryStayBounded(t *testing.T) {
	h := newHarness(t)
	inv := tierOneInvitation(modeView)
	// Exercise admission without a worker; draining models completed commands
	// while the native-effect idempotency is covered by the clipboard test.
	s := &session{deps: h.helper.deps, invitation: inv, phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE,
		commands: make(chan *agentv1.AssistanceCommand, 1), commandHistory: make(map[string][32]byte)}
	for id := 1; id <= maxSessionCommands; id++ {
		command := newTestCommand(h, id, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE)
		command.Text = "message"
		s.applyCommand(command)
		if len(s.commands) != 1 {
			t.Fatalf("command %d not admitted", id)
		}
		<-s.commands
		s.commandBusy = false
		s.commandResult = commandResult(command, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, "message_posted", h.clock.Now())
	}
	overflow := newTestCommand(h, maxSessionCommands+1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE)
	overflow.Text = "too many"
	s.applyCommand(overflow)
	if len(s.commandHistory) != maxSessionCommands || len(s.commands) != 0 || s.commandResult.GetReason() != "session_command_limit" {
		t.Fatal("command history not bounded")
	}
	conflict := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE)
	conflict.Text = "changed content"
	s.applyCommand(conflict)
	if len(s.commands) != 0 || s.commandResult.GetReason() != "command_identity_conflict" {
		t.Fatal("identity conflict re-executed")
	}
}

// GNOME queued a new request unseen behind a resident "ended" banner (org
// demo finance-desktop, Fedora 44): each prompt withdraws the previous one.
func TestNewPromptWithdrawsPreviousEndedNotice(t *testing.T) {
	deps := &sessionDeps{}
	first := &fakeNotice{result: make(chan string, 1), closed: make(chan struct{})}
	second := &fakeNotice{result: make(chan string, 1), closed: make(chan struct{})}
	if err := deps.replaceEndedNotice(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := deps.replaceEndedNotice(t.Context(), second); err != nil || !first.isClosed() || second.isClosed() {
		t.Fatalf("a newer end notice did not replace the older: %v", err)
	}
	if err := deps.replaceEndedNotice(t.Context(), nil); err != nil || !second.isClosed() {
		t.Fatalf("a prompt left the end notice resident: %v", err)
	}
}
