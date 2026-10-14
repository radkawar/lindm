// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func testFileLimits() *agentv1.AssistanceFilePolicy {
	return &agentv1.AssistanceFilePolicy{MaxFileBytes: 65536, MaxSessionBytes: 131072, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}
}

func filesInvitation() *agentv1.AssistanceInvitation {
	inv := tierOneInvitation(modeControl)
	inv.RequestedCapabilities.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	inv.RequestedCapabilities.FileLimits = testFileLimits()
	inv.EffectiveCapabilities = proto.CloneOf(inv.RequestedCapabilities)
	return inv
}

func fileDirective(inv *agentv1.AssistanceInvitation, now time.Time) *agentv1.AssistanceDirective {
	return &agentv1.AssistanceDirective{Invitation: inv, FileTransfer: &agentv1.AssistanceFileDirective{Request: &agentv1.AssistanceFileRequest{
		RequestId: "69acdf85-c609-46c6-af82-6250f0a141a1", Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER,
		Deadline: timestamppb.New(now.Add(time.Minute)), Policy: testFileLimits(),
	}}}
}

func waitFileState(h *harness, state agentv1.AssistanceFileState) *agentv1.SessionAssistanceReport {
	h.t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		report := h.report()
		if report.GetFileTransfer().GetState() == state {
			return report
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			h.t.Fatalf("file state = %v, want %v", report.GetFileTransfer(), state)
			return nil
		}
	}
}

func TestModalDropsPrequeuedHeldAndGuessedFutureInputEpochs(t *testing.T) {
	grant := &fakeGrant{control: true}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-1")
	peer := &pionPeer{input: make(chan []byte, inputQueueSize), inputEpoch: 1, failed: make(chan struct{})}
	key := func(epoch uint32) []byte {
		return fmt.Appendf(nil, `{"t":"key","code":"Enter","down":true,"display":"monitor-1","generation":1,"epoch":%d}`, epoch)
	}
	peer.admitInput(key(1))
	held, err := parseInput(<-peer.Input())
	if err != nil || input.inject(t.Context(), held) != nil {
		t.Fatal("initial held key was not injected")
	}
	peer.admitInput([]byte(`{"t":"button","b":"left","down":true,"display":"monitor-1","generation":1,"epoch":1}`))
	peer.admitInput(key(3)) // Guessing the resume epoch before pause is not admission.
	if err := peer.SetInputState(2, true); err != nil {
		t.Fatal(err)
	}
	if epoch, err := input.pauseModal(t.Context()); err != nil || epoch != 2 {
		t.Fatalf("pause = %d, %v", epoch, err)
	}
	for _, epoch := range []uint32{1, 2, 3, ^uint32(0)} {
		peer.admitInput(key(epoch))
	}
	peer.admitInput([]byte(`{"t":"release"}`))
	if len(peer.input) != 0 {
		t.Fatal("modal queued remotely supplied input")
	}
	if err := input.special(t.Context(), agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_SWITCH_WINDOW); !errors.Is(err, errInvalidInput) {
		t.Fatal("special keys crossed modal boundary")
	}
	if err := input.inject(t.Context(), held); !errors.Is(err, errInvalidInput) {
		t.Fatal("held event replayed while paused")
	}
	if epoch, err := input.resumeModal(); err != nil || epoch != 3 {
		t.Fatalf("resume = %d, %v", epoch, err)
	}
	if err := peer.SetInputState(3, false); err != nil {
		t.Fatal(err)
	}
	peer.admitInput(key(1))
	if len(peer.input) != 0 {
		t.Fatal("old epoch replayed after native completion")
	}
	peer.admitInput(key(3))
	fresh, err := parseInput(<-peer.Input())
	if err != nil || input.inject(t.Context(), fresh) != nil {
		t.Fatal("fresh independent epoch not admitted")
	}
	if input.generation != 1 {
		t.Fatal("modal changed the independent display fence")
	}
	events, _ := grant.snapshot()
	if len(events) != 3 || events[0].Keycode != 28 || events[1].Down || !events[2].Down {
		t.Fatalf("held/modal events = %+v", events)
	}
	if err := peer.SetInputState(2, false); err == nil {
		t.Fatal("input epoch regressed")
	}
	input.epoch = ^uint32(0) - 1
	if _, err := input.pauseModal(t.Context()); err == nil {
		t.Fatal("epoch exhaustion wrapped")
	}
}

type joinedInputGrant struct {
	*fakeGrant
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *joinedInputGrant) Inject(ctx context.Context, event InputEvent) error {
	if event.Down {
		g.once.Do(func() { close(g.entered) })
		select {
		case <-g.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return g.fakeGrant.Inject(ctx, event)
}

func TestModalJoinsNativePressBeforeReleasingIt(t *testing.T) {
	grant := &joinedInputGrant{fakeGrant: &fakeGrant{control: true}, entered: make(chan struct{}), release: make(chan struct{})}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-1")
	injected := make(chan error, 1)
	go func() {
		injected <- input.inject(t.Context(), InputEvent{kind: inputKey, Keycode: 28, Down: true, Display: "monitor-1", Generation: 1, Epoch: 1})
	}()
	<-grant.entered
	paused := make(chan error, 1)
	go func() { _, err := input.pauseModal(t.Context()); paused <- err }()
	select {
	case <-paused:
		t.Fatal("native approval could open before in-flight press joined")
	default:
	}
	close(grant.release)
	if err := <-injected; err != nil {
		t.Fatal(err)
	}
	if err := <-paused; err != nil {
		t.Fatal(err)
	}
	events, _ := grant.snapshot()
	if len(events) != 2 || !events[0].Down || events[1].Down {
		t.Fatalf("press was not drained/released: %+v", events)
	}
}

func TestNativeChooserIsOnlyResumeAuthorityAndCommandsCannotSelect(t *testing.T) {
	for _, completion := range []string{"local dismissal", "local close", "remote cancellation", "cleanup failure"} {
		t.Run(completion, func(t *testing.T) {
			h := newHarness(t)
			h.portal.grant.control = true
			h.portal.grant.clipboard = true
			entered, locallyClosed := make(chan struct{}), make(chan struct{})
			h.portal.choose = func(ctx context.Context, _ string) (*os.File, error) {
				h.portal.grant.mu.Lock()
				paused := h.portal.grant.paused
				h.portal.grant.mu.Unlock()
				if !paused {
					return nil, errors.New("chooser opened before clipboard pause")
				}
				close(entered)
				select {
				case <-locallyClosed:
					switch completion {
					case "cleanup failure":
						return nil, errors.Join(ErrPortalCancelled, errors.New("remove match failed"))
					case "local close":
						// Escape on GNOME 46 (response 2): no selection, same
						// resume authority as Cancel.
						return nil, ErrPortalClosed
					}
					return nil, ErrPortalCancelled
				case <-ctx.Done():
					return nil, errors.Join(ErrPortalCancelled, ctx.Err())
				}
			}
			inv := filesInvitation()
			activateTierOne(h, inv)
			request := fileDirective(inv, h.clock.Now())
			h.sync(request)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("native chooser not opened")
			}
			state := waitFileState(h, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT)
			if !state.GetInputState().GetPaused() || state.GetInputState().GetEpoch() != 2 {
				t.Fatal("modal input state not published")
			}
			for _, kind := range []agentv1.AssistanceCommandKind{agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY} {
				command := newTestCommand(h, int(kind)+20, kind)
				switch kind {
				case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE:
					command.Text = "remote selection"
				case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS:
					command.SpecialKey = agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_SWITCH_WINDOW
				case agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY:
					command.DisplayId = "monitor-1"
				}
				if err := h.helper.deps.validator.Validate(command); err != nil {
					t.Fatal(err)
				}
				h.helper.sessions[testSessionID].applyCommand(command)
			}
			if events, _ := h.portal.grant.snapshot(); len(events) != 0 {
				t.Fatal("modal commands reached native input")
			}
			h.portal.grant.mu.Lock()
			writes := h.portal.grant.writes
			h.portal.grant.mu.Unlock()
			if writes != 0 {
				t.Fatal("modal clipboard command reached native clipboard")
			}
			if completion == "remote cancellation" {
				request.FileTransfer.Cancel = true
				h.sync(request)
			} else {
				close(locallyClosed)
			}
			if completion != "local dismissal" && completion != "local close" {
				report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
				if !report.GetInputState().GetPaused() || report.GetInputState().GetEpoch() != 2 {
					t.Fatal("remote cancellation or failed cleanup resumed input")
				}
			} else {
				report := waitFileState(h, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED)
				if report.GetInputState().GetPaused() || report.GetInputState().GetEpoch() != 3 {
					t.Fatal("local completion did not create fresh epoch")
				}
				want := map[string]string{"local dismissal": "file_dialog_dismissed", "local close": "file_dialog_closed"}[completion]
				if report.GetFileTransfer().GetReason() != want || report.GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
					t.Fatalf("local chooser %s reported %q (phase %v), want %q with the session kept", completion, report.GetFileTransfer().GetReason(), report.GetPhase(), want)
				}
				h.sync(request) // Same ID does not invoke the chooser a second time.
				if h.report().GetFileTransfer().GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED {
					t.Fatal("replayed request repeated native effect")
				}
			}
		})
	}
}

func TestNativeChooserWaitsForCancelledClipboardCommand(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control, h.portal.grant.clipboard = true, true
	blocked := &blockedClipboardGrant{fakeGrant: h.portal.grant, started: make(chan struct{})}
	h.portal.grantOverride = blocked
	observed := make(chan bool, 1)
	h.portal.choose = func(context.Context, string) (*os.File, error) {
		result := h.report().GetCommandResult()
		observed <- result.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED && result.GetText() == "" && result.GetReason() == "local_file_dialog"
		return nil, ErrPortalCancelled
	}
	inv := filesInvitation()
	activateTierOne(h, inv)
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("clipboard command did not enter native call")
	}
	h.sync(fileDirective(inv, h.clock.Now()))
	select {
	case joined := <-observed:
		if !joined {
			t.Fatal("chooser preceded clipboard cancellation and command join")
		}
	case <-time.After(time.Second):
		t.Fatal("chooser stalled behind uncancelled clipboard")
	}
	waitFileState(h, agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED)
}

func TestFileConsentAndViewGrantIntersectWithoutInput(t *testing.T) {
	inv := filesInvitation()
	inv.Mode = modeView
	inv.EffectiveCapabilities.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	inv.EffectiveCapabilities.FileLimits.MaxFileBytes = 32768
	policy := consentedPolicy(inv)
	caps := grantedCapabilities(policy, &fakeGrant{})
	if caps.GetPolicy().GetFiles() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || caps.GetPolicy().GetFileLimits().GetMaxFileBytes() != 32768 ||
		policyEnabled(caps.GetPolicy().GetKeyboard()) {
		t.Fatal("view files grant enabled input or exceeded consent intersection")
	}
	text := capabilityConsentText(policy)
	for _, required := range []string{"Downloads", "approve each file locally", "clipboard access are paused"} {
		if !strings.Contains(text, required) {
			t.Fatalf("file consent omits %q", required)
		}
	}
	s := &session{invitation: inv, deps: &sessionDeps{filesUnavailableReason: "platform_files_unqualified"}}
	if strings.Contains(s.promptNotification(false, recordingOffer{}, policy).Body, "\nFiles:") {
		t.Fatal("unsupported files requested local consent")
	}
	inv.EffectiveCapabilities.FileLimits.AllowedMimeTypes = []string{"application/pdf"}
	if policyEnabled(consentedPolicy(inv).GetFiles()) {
		t.Fatal("empty MIME intersection granted files")
	}
}

func TestUnseenCancelledFileDirectiveNeverOpensNativeChooser(t *testing.T) {
	h := newHarness(t)
	entered := make(chan struct{}, 1)
	h.portal.choose = func(context.Context, string) (*os.File, error) {
		entered <- struct{}{}
		return nil, ErrPortalCancelled
	}
	inv := filesInvitation()
	activateTierOne(h, inv)
	directive := fileDirective(inv, h.clock.Now())
	directive.FileTransfer.Cancel = true
	h.sync(directive)
	s := h.helper.sessions[testSessionID]
	s.mu.Lock()
	untouched := s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE && !s.fileBusy && s.fileOperation == nil && s.fileReserved == 0 && len(s.fileHistory) == 1
	s.mu.Unlock()
	if !untouched {
		t.Fatal("never-started cancellation changed native session authority")
	}
	directive.FileTransfer.Cancel = false
	h.sync(directive)
	s.mu.Lock()
	resurrected := s.fileBusy || s.fileOperation != nil || s.fileReserved != 0
	s.mu.Unlock()
	if resurrected {
		t.Fatal("cancelled operation was resurrected by a stale active snapshot")
	}
	select {
	case <-entered:
		t.Fatal("cancelled operation opened a native chooser")
	default:
	}
}
