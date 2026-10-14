// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	testEnrollmentID = "5e1f3a44-7d7b-4f0e-9c8e-1d2a3b4c5d6e"
	testGrantID      = "8a0c6a5e-1b1f-4c3e-8f5d-0a9b8c7d6e5f"
	testRestoreToken = "1c3d5e7f-0a2b-4c6d-8e0f-1a2b3c4d5e6f"
	nextRestoreToken = "2d4e6f80-1b3c-4d7e-9f10-2b3c4d5e6f70"
)

type fakeOverlay struct {
	mu       sync.Mutex
	checkErr error
	frames   []OverlayFrame
	clears   int
	released int
}

func (o *fakeOverlay) Check(context.Context) error { return o.checkErr }
func (o *fakeOverlay) Draw(_ context.Context, frame OverlayFrame) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.frames = append(o.frames, frame)
	return nil
}
func (o *fakeOverlay) Clear(context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.clears++
	return nil
}
func (o *fakeOverlay) Release(context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.released++
	return nil
}
func (o *fakeOverlay) snapshot() ([]OverlayFrame, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]OverlayFrame(nil), o.frames...), o.clears
}

type fakeAudio struct {
	mu       sync.Mutex
	sources  []AudioSource
	starts   [][]AudioSource
	captures []*fakeCapture
}

func (a *fakeAudio) Sources(context.Context) ([]AudioSource, error) { return a.sources, nil }
func (a *fakeAudio) Start(_ context.Context, selected []AudioSource) (Capture, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.starts = append(a.starts, append([]AudioSource(nil), selected...))
	packets := make(chan []byte, 4)
	packets <- []byte{0x80, 111, 0, 7, 0, 0, 0x10, 0, 0, 0, 0, 2, 0xAA}
	capture := &fakeCapture{packets: packets, closed: make(chan struct{})}
	a.captures = append(a.captures, capture)
	return capture, nil
}
func (a *fakeAudio) startCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.starts)
}

type fakeEnrollments struct {
	mu      sync.Mutex
	current *Enrollment
	saves   []Enrollment
	removes int
}

func (e *fakeEnrollments) Load() (Enrollment, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current == nil {
		return Enrollment{}, errEnrollmentMissing
	}
	return *e.current, nil
}
func (e *fakeEnrollments) Save(enrollment Enrollment) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current = &enrollment
	e.saves = append(e.saves, enrollment)
	return nil
}
func (e *fakeEnrollments) Remove() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current = nil
	e.removes++
	return nil
}
func (e *fakeEnrollments) state() (*Enrollment, []Enrollment, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current, append([]Enrollment(nil), e.saves...), e.removes
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func controlWithElevation() *agentv1.AssistanceInvitation {
	inv := tierOneInvitation(modeControl)
	inv.RequestedCapabilities.Elevation, inv.EffectiveCapabilities.Elevation = modeLimited, modeLimited
	return inv
}

func injectedCount(h *harness) int {
	events, _ := h.portal.grant.snapshot()
	return len(events)
}

func TestElevationGuidancePausesEveryRemoteInjectionUntilLocalResume(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control, h.portal.grant.clipboard = true, true
	inv := controlWithElevation()
	activateTierOne(h, inv)
	h.peers.peer.input <- []byte(`{"t":"key","code":"KeyA","down":true,"display":"monitor-1","generation":1,"epoch":1}`)
	waitFor(t, "held key injected", func() bool { return injectedCount(h) == 1 })

	guidance := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE)
	guidance.Text = "Enter your password to add the printer"
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: guidance})
	if result := waitCommand(h, guidance.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED || result.GetReason() != "elevation_paused" {
		t.Fatalf("guidance = %v", result)
	}
	notice := h.notifier.next(t, "Remote control paused for your password")
	if !strings.Contains(notice.notification.Body, "Enter your password to add the printer") || len(notice.notification.Actions) != 2 || notice.notification.Actions[0].Key != actionElevationResume || notice.notification.Actions[1].Key != actionStop {
		t.Fatalf("guidance notice = %+v", notice.notification)
	}
	state := h.report().GetInputState()
	if !state.GetPaused() || state.GetPause() != agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION || state.GetEpoch() != 2 {
		t.Fatalf("input state = %v", state)
	}
	events, _ := h.portal.grant.snapshot()
	if len(events) != 2 || events[1].Down || events[1].Keycode != events[0].Keycode {
		t.Fatalf("held key was not released before the pause: %+v", events)
	}
	h.portal.grant.mu.Lock()
	clipboardPaused := h.portal.grant.paused
	h.portal.grant.mu.Unlock()
	if !clipboardPaused {
		t.Fatal("clipboard stayed live during the pause")
	}
	// Every remote input type, under the old or the paused epoch, is refused.
	for _, epoch := range []string{"1", "2"} {
		for _, raw := range []string{
			`{"t":"move","x":0.5,"y":0.5,"display":"monitor-1","generation":1,"epoch":` + epoch + `}`,
			`{"t":"button","b":"left","down":true,"display":"monitor-1","generation":1,"epoch":` + epoch + `}`,
			`{"t":"wheel","dx":0,"dy":1,"display":"monitor-1","generation":1,"epoch":` + epoch + `}`,
			`{"t":"key","code":"KeyB","down":true,"display":"monitor-1","generation":1,"epoch":` + epoch + `}`,
			`{"t":"keysym","keysym":121,"down":true,"display":"monitor-1","generation":1,"epoch":` + epoch + `}`,
		} {
			h.peers.peer.inputGate.admitInput([]byte(raw))
		}
	}
	for i, kind := range []agentv1.AssistanceCommandKind{agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ} {
		command := newTestCommand(h, 10+i, kind)
		if kind == agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS {
			command.SpecialKey = agentv1.AssistanceSpecialKey_ASSISTANCE_SPECIAL_KEY_OPEN_TERMINAL
		}
		if kind == agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE {
			command.Text = "remote text"
		}
		h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
		if result := waitCommand(h, command.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED || result.GetReason() != "local_elevation_pause" {
			t.Fatalf("%s during pause = %v", kind, result)
		}
	}
	if count := injectedCount(h); count != 2 {
		t.Fatalf("injected %d events during the pause", count)
	}
	// Dismissing the guidance is not a resume.
	notice.result <- ""
	notice = h.notifier.next(t, "Remote control paused for your password")
	if !h.report().GetInputState().GetPaused() {
		t.Fatal("dismissal resumed remote input")
	}
	notice.result <- actionElevationResume
	waitFor(t, "local resume", func() bool { return !h.report().GetInputState().GetPaused() })
	if state := h.report().GetInputState(); state.GetEpoch() != 3 || state.GetPause() != agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_UNSPECIFIED {
		t.Fatalf("resumed state = %v", state)
	}
	h.peers.peer.input <- []byte(`{"t":"move","x":0.5,"y":0.5,"display":"monitor-1","generation":1,"epoch":2}`)
	h.peers.peer.input <- []byte(`{"t":"move","x":0.25,"y":0.5,"display":"monitor-1","generation":1,"epoch":3}`)
	waitFor(t, "fresh-epoch input", func() bool { return injectedCount(h) == 3 })
	events, _ = h.portal.grant.snapshot()
	if events[2].X != 0.25 {
		t.Fatalf("pre-pause epoch input injected after resume: %+v", events[2])
	}
}

func TestLocalPauseForPasswordComesFromTheIndicator(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control = true
	inv := controlWithElevation()
	activateTierOne(h, inv)
	indicator := h.notifier.next(t, "Remote assistance in progress")
	keys := make([]string, 0, len(indicator.notification.Actions))
	for _, action := range indicator.notification.Actions {
		keys = append(keys, action.Key)
	}
	if strings.Join(keys, ",") != actionStop+","+actionElevationPause {
		t.Fatalf("indicator actions = %v", keys)
	}
	indicator.result <- actionElevationPause
	h.notifier.next(t, "Remote control paused for your password")
	waitFor(t, "local pause", func() bool {
		return h.report().GetInputState().GetPause() == agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION
	})
}

func TestElevationOffHidesGuidance(t *testing.T) {
	h := newHarness(t)
	h.portal.grant.control = true
	inv := tierOneInvitation(modeControl)
	activateTierOne(h, inv)
	indicator := h.notifier.next(t, "Remote assistance in progress")
	for _, action := range indicator.notification.Actions {
		if action.Key == actionElevationPause {
			t.Fatal("elevation guidance offered under OFF policy")
		}
	}
	command := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ELEVATION_GUIDANCE)
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: command})
	if result := waitCommand(h, command.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED || result.GetReason() != "command_not_granted" {
		t.Fatalf("guidance under OFF = %v", result)
	}
}

func annotationInvitation(mode agentv1.AssistancePolicyMode) *agentv1.AssistanceInvitation {
	inv := invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, time.Minute, 10*time.Minute)
	inv.RequestedCapabilities = &agentv1.AssistancePolicy{Annotation: mode}
	inv.EffectiveCapabilities = &agentv1.AssistancePolicy{Annotation: mode}
	return inv
}

func TestParseAnnotationRefusesInputVocabularyAndUnboundedFrames(t *testing.T) {
	for _, raw := range []string{
		`{"t":"p","d":"monitor-1","g":1,"x":0.5,"y":0.5}`,
		`{"t":"s","d":"monitor-1","g":1,"id":4,"p":[[0.1,0.1],[0.2,0.2]]}`,
		`{"t":"c"}`,
	} {
		if _, err := parseAnnotation([]byte(raw), modeOn); err != nil {
			t.Fatalf("valid frame %s refused: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"t":"button","b":"left","down":true}`,
		`{"t":"key","code":"KeyA","down":true}`,
		`{"t":"p","d":"monitor-1","g":1,"x":1.5,"y":0.5}`,
		`{"t":"p","d":"","g":1,"x":0.5,"y":0.5}`,
		`{"t":"p","d":"monitor-1","g":0,"x":0.5,"y":0.5}`,
		`{"t":"s","d":"monitor-1","g":1,"id":0,"p":[[0.1,0.1],[0.2,0.2]]}`,
		`{"t":"s","d":"monitor-1","g":1,"id":1,"p":[[0.1,0.1]]}`,
		`{"t":"c","d":"monitor-1"}`,
		`not json`,
	} {
		if _, err := parseAnnotation([]byte(raw), modeOn); err == nil {
			t.Fatalf("frame %s admitted", raw)
		}
	}
	long := `{"t":"s","d":"monitor-1","g":1,"id":1,"p":[` + strings.Repeat(`[0.1,0.1],`, maxStrokePoints) + `[0.2,0.2]]}`
	if _, err := parseAnnotation([]byte(long), modeOn); err == nil {
		t.Fatal("unbounded stroke admitted")
	}
	if _, err := parseAnnotation([]byte(`{"t":"s","d":"monitor-1","g":1,"id":4,"p":[[0.1,0.1],[0.2,0.2]]}`), modeLimited); err == nil {
		t.Fatal("LIMITED (pointer only) admitted a drawn mark")
	}
}

func TestAnnotationDrawsOnlyTheSharedDisplayAndHonoursLocalHide(t *testing.T) {
	h := newHarness(t)
	overlay := &fakeOverlay{}
	h.helper.deps.overlay = overlay
	inv := annotationInvitation(modeOn)
	activateTierOne(h, inv)
	if config := h.peers.made[0]; config.Input || !config.Annotation {
		t.Fatalf("annotation implied input or lacked its channel: %+v", config)
	}
	if granted := h.report().GetGrantedCapabilities().GetPolicy().GetAnnotation(); granted != modeOn {
		t.Fatalf("granted annotation = %v", granted)
	}
	// Before the operator's audited enable, frames are dropped.
	h.peers.peer.annotations <- []byte(`{"t":"p","d":"monitor-1","g":1,"x":0.5,"y":0.5}`)
	// The loop reads frames in order, so once it has taken this always-dropped
	// frame for an unshared display the one before it has been handled.
	h.peers.peer.annotations <- []byte(`{"t":"p","d":"monitor-9","g":1,"x":0.5,"y":0.5}`)
	waitFor(t, "pre-enable frames consumed", func() bool { return len(h.peers.peer.annotations) == 0 })
	enable := newTestCommand(h, 1, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION)
	enable.AnnotationEnabled = true
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: enable})
	if result := waitCommand(h, enable.GetRequestId()); result.GetReason() != "annotation_enabled" {
		t.Fatalf("enable = %v", result)
	}
	notice := h.notifier.next(t, "Support pointer on your screen")
	if len(notice.notification.Actions) != 3 || notice.notification.Actions[0].Key != actionAnnotationClear || notice.notification.Actions[1].Key != actionAnnotationHide || notice.notification.Actions[2].Key != actionStop {
		t.Fatalf("local controls = %+v", notice.notification.Actions)
	}
	if frames, _ := overlay.snapshot(); len(frames) != 0 {
		t.Fatal("a frame sent before enable was drawn")
	}
	h.peers.peer.annotations <- []byte(`{"t":"p","d":"monitor-2","g":1,"x":0.5,"y":0.5}`)
	h.peers.peer.annotations <- []byte(`{"t":"p","d":"monitor-1","g":7,"x":0.5,"y":0.5}`)
	h.peers.peer.annotations <- []byte(`{"t":"p","d":"monitor-1","g":1,"x":0.25,"y":0.75}`)
	h.peers.peer.annotations <- []byte(`{"t":"s","d":"monitor-1","g":1,"id":3,"p":[[0.1,0.1],[0.2,0.3]]}`)
	waitFor(t, "overlay frame", func() bool {
		frames, _ := overlay.snapshot()
		return len(frames) > 0 && frames[len(frames)-1].Pointer != nil && len(frames[len(frames)-1].Strokes) == 1
	})
	frames, _ := overlay.snapshot()
	last := frames[len(frames)-1]
	if *last.Pointer != (OverlayPoint{X: 0.25, Y: 0.75}) || last.Width != 1920 || last.Height != 1080 {
		t.Fatalf("frame = %+v", last)
	}
	for _, frame := range frames {
		if frame.Pointer != nil && *frame.Pointer == (OverlayPoint{X: 0.5, Y: 0.5}) {
			t.Fatal("a frame for an unshared display or stale generation was drawn")
		}
	}
	notice.result <- actionAnnotationClear
	notice = h.notifier.next(t, "Support pointer on your screen")
	waitFor(t, "local clear", func() bool { return h.report().GetAnnotation().GetClears() == 1 })
	notice.result <- actionAnnotationHide
	waitFor(t, "local hide", func() bool { return h.report().GetAnnotation().GetHidden() })
	if report := h.report().GetAnnotation(); report.GetEnabled() {
		t.Fatalf("hidden overlay still enabled: %v", report)
	}
	again := newTestCommand(h, 2, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_ANNOTATION)
	again.AnnotationEnabled = true
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Command: again})
	if result := waitCommand(h, again.GetRequestId()); result.GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_FAILED || result.GetReason() != "annotation_hidden_locally" {
		t.Fatalf("operator re-enabled a locally hidden overlay: %v", result)
	}
	before, _ := overlay.snapshot()
	h.peers.peer.annotations <- []byte(`{"t":"p","d":"monitor-1","g":1,"x":0.4,"y":0.4}`)
	time.Sleep(3 * annotationTick)
	after, _ := overlay.snapshot()
	if len(after) != len(before) {
		t.Fatal("a hidden overlay drew another frame")
	}
}

func TestAnnotationRequiresAQualifiedOverlay(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.overlay = &fakeOverlay{checkErr: unavailable("overlay_extension_unavailable", nil)}
	activateTierOne(h, annotationInvitation(modeLimited))
	granted := h.report().GetGrantedCapabilities()
	if granted.GetPolicy().GetAnnotation() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || granted.GetAnnotationReason() != "overlay_extension_unavailable" {
		t.Fatalf("granted = %v", granted)
	}
	if h.peers.made[0].Annotation {
		t.Fatal("annotation channel opened without an overlay")
	}
}

func audioInvitation(mode agentv1.AssistancePolicyMode) *agentv1.AssistanceInvitation {
	inv := invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, time.Minute, 10*time.Minute)
	inv.RequestedCapabilities = &agentv1.AssistancePolicy{Audio: mode}
	inv.EffectiveCapabilities = &agentv1.AssistancePolicy{Audio: mode}
	return inv
}

func audioSources() []AudioSource {
	return []AudioSource{
		{Serial: 41, Description: "Built-in Speakers"},
		{Serial: 42, Description: "Headphones"},
		{Serial: 43, Description: "Laptop Microphone", Microphone: true},
	}
}

// allowWithAudio accepts the prompt, answers the local sound choices and
// returns once the session is offered.
func allowWithAudio(h *harness, inv *agentv1.AssistanceInvitation, output string, microphone string) {
	h.t.Helper()
	h.sync(directiveFor(inv))
	h.notifier.nextWith(h.t, "Remote assistance request", func(summary string) bool { return strings.HasPrefix(summary, "Remote assistance request") }).result <- actionAllow
	choice := h.notifier.next(h.t, "Share sound with the operator?")
	choice.result <- output
	if microphone != "" {
		h.notifier.next(h.t, "Share your microphone?").result <- microphone
	}
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
}

func TestAudioIsSeparatelySelectedMutedAndStoppedLocally(t *testing.T) {
	h := newHarness(t)
	audio := &fakeAudio{sources: audioSources()}
	h.helper.deps.audio = audio
	inv := audioInvitation(modeOn)
	allowWithAudio(h, inv, actionAudioOutput+"1", actionMicrophone)
	if h.report().GetGrantedCapabilities().GetPolicy().GetAudio() != modeOn || !h.peers.made[0].Audio {
		t.Fatalf("granted = %v", h.report().GetGrantedCapabilities())
	}
	report := h.report().GetAudio()
	if report.GetState() != agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING || report.GetOutputSource() != "Headphones" || report.GetMicrophoneSource() != "Laptop Microphone" {
		t.Fatalf("audio report = %v", report)
	}
	if audio.startCount() != 1 || len(audio.starts[0]) != 2 || audio.starts[0][0].Serial != 42 || audio.starts[0][1].Serial != 43 {
		t.Fatalf("captured %v", audio.starts)
	}
	controls := h.notifier.next(t, "Sharing sound with the operator")
	controls.result <- actionAudioMute
	waitFor(t, "local mute", func() bool {
		return h.report().GetAudio().GetState() == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_MUTED
	})
	select {
	case <-audio.captures[0].closed:
	default:
		t.Fatal("muting kept capturing")
	}
	muted := h.notifier.next(t, "Sound sharing muted")
	muted.result <- actionAudioUnmute
	waitFor(t, "unmute", func() bool { return audio.startCount() == 2 })
	h.notifier.next(t, "Sharing sound with the operator").result <- actionAudioStop
	waitFor(t, "local stop", func() bool {
		return h.report().GetAudio().GetState() == agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED
	})
	if report := h.report().GetAudio(); report.GetOutputSource() != "" || report.GetMicrophoneSource() != "" {
		t.Fatalf("stopped report kept sources: %v", report)
	}
	if audio.startCount() != 2 {
		t.Fatal("stopped sound restarted")
	}
}

func TestAudioLimitedNeverOffersTheMicrophoneAndDeclineSharesNothing(t *testing.T) {
	h := newHarness(t)
	audio := &fakeAudio{sources: audioSources()}
	h.helper.deps.audio = audio
	allowWithAudio(h, audioInvitation(modeLimited), actionAudioOutput+"0", "")
	if report := h.report().GetAudio(); report.GetMicrophoneSource() != "" || report.GetOutputSource() != "Built-in Speakers" {
		t.Fatalf("LIMITED report = %v", report)
	}
	if got := h.report().GetGrantedCapabilities().GetPolicy().GetAudio(); got != modeLimited {
		t.Fatalf("LIMITED grant = %v", got)
	}

	declined := newHarness(t)
	declinedAudio := &fakeAudio{sources: audioSources()}
	declined.helper.deps.audio = declinedAudio
	allowWithAudio(declined, audioInvitation(modeOn), actionAudioNone, actionMicrophoneNone)
	granted := declined.report().GetGrantedCapabilities()
	if granted.GetPolicy().GetAudio() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || granted.GetAudioReason() != "user_declined" || declined.peers.made[0].Audio || declinedAudio.startCount() != 0 {
		t.Fatalf("declined sound was shared: %v", granted)
	}
	if declined.report().GetAudio().GetState() != agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED {
		t.Fatalf("declined report = %v", declined.report().GetAudio())
	}
}

func enrollmentInvitation() *agentv1.AssistanceInvitation {
	inv := invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, time.Minute, 10*time.Minute)
	limits := &agentv1.AssistanceUnattendedPolicy{MaxApprovalSeconds: 3600, MaxEnrollmentDays: 30, MaxSessionSeconds: 1800}
	inv.RequestedCapabilities = &agentv1.AssistancePolicy{Unattended: modeLimited, UnattendedLimits: limits}
	inv.EffectiveCapabilities = proto.CloneOf(inv.RequestedCapabilities)
	inv.UnattendedEnrollment = &agentv1.AssistanceUnattendedEnrollmentOffer{EnrollmentId: testEnrollmentID, ExpiresAt: timestamppb.New(time.Now().Add(30 * 24 * time.Hour))}
	return inv
}

func optIn(t *testing.T, action, restore string) (*harness, *fakeEnrollments) {
	t.Helper()
	h := newHarness(t)
	enrollments := &fakeEnrollments{}
	h.helper.deps.enrollments = enrollments
	h.portal.grant.restore = restore
	h.sync(directiveFor(enrollmentInvitation()))
	prompt := h.notifier.nextWith(t, "Remote assistance request", func(summary string) bool { return strings.HasPrefix(summary, "Remote assistance request") })
	if len(prompt.notification.Actions) != 3 || prompt.notification.Actions[1].Key != actionAllowUnattended || !strings.Contains(prompt.notification.Body, "Unattended access (optional)") {
		t.Fatalf("opt-in prompt = %+v", prompt.notification)
	}
	prompt.result <- action
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	return h, enrollments
}

func TestUnattendedOptInNeedsTheLocalChoiceAndThePersistentGrant(t *testing.T) {
	h, enrollments := optIn(t, actionAllowUnattended, testRestoreToken)
	if opens := h.portal.opens; len(opens) != 1 || !opens[0].Persist || opens[0].RestoreToken != "" {
		t.Fatalf("portal requests = %+v", opens)
	}
	report := h.report()
	if report.GetUnattended().GetState() != agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_ENROLLED || report.GetUnattended().GetEnrollmentId() != testEnrollmentID || report.GetGrantedCapabilities().GetPolicy().GetUnattended() != modeLimited {
		t.Fatalf("enrolled report = %v", report.GetUnattended())
	}
	if current, _, _ := enrollments.state(); current == nil || current.ID != testEnrollmentID || current.RestoreToken != testRestoreToken || current.Mode != agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW {
		t.Fatalf("stored opt-in = %+v", current)
	}

	plain, plainEnrollments := optIn(t, actionAllow, testRestoreToken)
	if plain.portal.opens[0].Persist {
		t.Fatal("plain Allow requested a persistent grant")
	}
	if report := plain.report(); report.GetUnattended().GetState() != agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_DECLINED || report.GetUnattended().GetReason() != "user_declined" || report.GetGrantedCapabilities().GetPolicy().GetUnattended() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		t.Fatalf("declined report = %v", report)
	}
	if _, saves, _ := plainEnrollments.state(); len(saves) != 0 {
		t.Fatal("an opt-in was stored without the local choice")
	}

	unremembered, unrememberedEnrollments := optIn(t, actionAllowUnattended, "")
	if report := unremembered.report().GetUnattended(); report.GetState() != agentv1.AssistanceUnattendedEnrollmentState_ASSISTANCE_UNATTENDED_ENROLLMENT_STATE_DECLINED || report.GetReason() != "portal_persist_not_granted" {
		t.Fatalf("unremembered report = %v", report)
	}
	if _, saves, _ := unrememberedEnrollments.state(); len(saves) != 0 {
		t.Fatal("an opt-in was stored without the desktop's persistent grant")
	}
}

func unattendedInvitation() *agentv1.AssistanceInvitation {
	inv := invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, time.Minute, 10*time.Minute)
	inv.RequestedCapabilities, inv.EffectiveCapabilities = &agentv1.AssistancePolicy{}, &agentv1.AssistancePolicy{}
	inv.TargetUsername = "alice"
	inv.Unattended = &agentv1.AssistanceUnattendedAuthority{GrantId: testGrantID, EnrollmentId: testEnrollmentID, ApproverDisplay: "Avery Approver", ApprovedUntil: inv.GetEndsAt()}
	return inv
}

func unattendedHarness(t *testing.T, enrollment *Enrollment) (*harness, *fakeEnrollments) {
	t.Helper()
	h := newHarness(t)
	h.notifier.capabilities = append(h.notifier.capabilities, "persistence")
	enrollments := &fakeEnrollments{current: enrollment}
	h.helper.deps.enrollments = enrollments
	h.helper.deps.unattendedRestore = 50 * time.Millisecond
	return h, enrollments
}

func enrolled() *Enrollment {
	return &Enrollment{ID: testEnrollmentID, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, ExpiresAt: time.Now().Add(time.Hour), RestoreToken: testRestoreToken}
}

func TestUnattendedConnectionShowsTheBannerFirstAndRestoresWithoutAPrompt(t *testing.T) {
	h, enrollments := unattendedHarness(t, enrolled())
	h.portal.grant.restore = nextRestoreToken
	h.portal.opened = make(chan struct{}, 1)
	h.sync(directiveFor(unattendedInvitation()))
	banner := h.notifier.next(t, "Unattended remote assistance — Olga Operator")
	if !strings.Contains(banner.notification.Body, "approved by Avery Approver") || !banner.notification.Critical || !banner.notification.Persistent {
		t.Fatalf("banner = %+v", banner.notification)
	}
	if keys := banner.notification.Actions; len(keys) != 2 || keys[0].Key != actionStop || keys[1].Key != actionUnattendedOff {
		t.Fatalf("banner actions = %+v", keys)
	}
	<-h.portal.opened
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	if opens := h.portal.opens; len(opens) != 1 || opens[0].RestoreToken != testRestoreToken || opens[0].Persist {
		t.Fatalf("portal request = %+v", opens)
	}
	if current, _, _ := enrollments.state(); current.RestoreToken != nextRestoreToken {
		t.Fatal("the desktop's replacement token was not kept")
	}
	// The banner becomes the indicator in place: updated to the connected
	// text and never closed, as a second notification posted while it shows
	// was stranded by GNOME without animations (layers-fedora44-tier3-34).
	select {
	case connected := <-banner.updates:
		if !strings.Contains(connected.Body, "can see this session") || connected.Summary != banner.notification.Summary {
			t.Fatalf("connected banner = %+v", connected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("banner was not updated to the connected indicator")
	}
	if banner.isClosed() {
		t.Fatal("no banner remained visible")
	}
	banner.result <- actionUnattendedOff
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED)
	if report.GetEndDetail() != "unattended_turned_off" {
		t.Fatalf("detail = %s", report.GetEndDetail())
	}
	if current, _, removes := enrollments.state(); current != nil || removes != 1 {
		t.Fatal("turning unattended access off kept the opt-in")
	}
}

func TestUnattendedConnectionRefusesWithoutEveryLocalGate(t *testing.T) {
	for name, tc := range map[string]struct {
		enrollment *Enrollment
		setup      func(*harness, *agentv1.AssistanceInvitation)
		detail     string
		removed    bool
	}{
		"no opt-in":      {nil, nil, "unattended_enrollment_missing", false},
		"other opt-in":   {&Enrollment{ID: "00000000-0000-4000-8000-000000000001", Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, ExpiresAt: time.Now().Add(time.Hour), RestoreToken: testRestoreToken}, nil, "unattended_enrollment_missing", false},
		"expired opt-in": {&Enrollment{ID: testEnrollmentID, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, ExpiresAt: time.Now().Add(-time.Minute), RestoreToken: testRestoreToken}, nil, "unattended_enrollment_missing", true},
		"other mode":     {&Enrollment{ID: testEnrollmentID, Mode: modeControl, ExpiresAt: time.Now().Add(time.Hour), RestoreToken: testRestoreToken}, nil, "unattended_enrollment_missing", true},
		"no banner": {enrolled(), func(h *harness, _ *agentv1.AssistanceInvitation) {
			h.notifier.capabilities = []string{"actions", "body"}
		}, "unattended_banner_unavailable", false},
		"dialog not grant": {enrolled(), func(h *harness, _ *agentv1.AssistanceInvitation) { h.portal.block = true }, "unattended_portal_grant_missing", true},
		"optional recording": {enrolled(), func(_ *harness, inv *agentv1.AssistanceInvitation) {
			limits := &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 64 << 20}
			inv.RequestedCapabilities = &agentv1.AssistancePolicy{Recording: modeLimited, RecordingLimits: limits}
			inv.EffectiveCapabilities = proto.CloneOf(inv.RequestedCapabilities)
			inv.Recording = &agentv1.AssistanceRecordingAuthority{RetentionDays: 30}
		}, "unattended_optional_recording", false},
	} {
		t.Run(name, func(t *testing.T) {
			h, enrollments := unattendedHarness(t, tc.enrollment)
			inv := unattendedInvitation()
			if tc.setup != nil {
				tc.setup(h, inv)
			}
			h.sync(directiveFor(inv))
			report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE)
			if report.GetEndDetail() != tc.detail {
				t.Fatalf("detail = %s, want %s", report.GetEndDetail(), tc.detail)
			}
			if _, _, removes := enrollments.state(); (removes > 0) != tc.removed {
				t.Fatalf("opt-in removed = %v", removes > 0)
			}
			if tc.detail != "unattended_portal_grant_missing" && h.portal.openCount() != 0 {
				t.Fatal("a refused connection reached the portal")
			}
		})
	}
}

func TestEnrollmentStoreIsPrivateAndNeverFollowsLinks(t *testing.T) {
	store := &FileEnrollmentStore{dir: t.TempDir() + "/lindm"}
	if _, err := store.Load(); !errors.Is(err, errEnrollmentMissing) {
		t.Fatalf("missing store = %v", err)
	}
	want := Enrollment{ID: testEnrollmentID, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, ExpiresAt: time.Now().Add(time.Hour).Round(time.Second).UTC(), RestoreToken: testRestoreToken}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got != want {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	// A symlinked state file is never followed.
	if err := os.Rename(store.dir+"/"+enrollmentFile, store.dir+"/elsewhere.json"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere.json", store.dir+"/"+enrollmentFile); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, errEnrollmentMissing) {
		t.Fatal("a linked opt-in was followed")
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	// A directory others can read is not private state.
	if err := os.Chmod(store.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, errEnrollmentMissing) {
		t.Fatal("an opt-in in a shared directory loaded")
	}
	if err := os.Chmod(store.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, errEnrollmentMissing) {
		t.Fatal("removed opt-in still loads")
	}
}

// pauseProbePeer injects a frame the input pump already dequeued, with the
// pre-pause epoch, at the moment the peer is told about the pause.
type pauseProbePeer struct {
	*fakePeer
	input    *inputControl
	inFlight error
}

func (p *pauseProbePeer) SetInputState(epoch uint32, paused bool) error {
	if paused {
		p.inFlight = p.input.inject(context.Background(), InputEvent{kind: inputMove, X: 0.5, Y: 0.5, Display: "monitor-1", Generation: 1, Epoch: epoch - 1})
	}
	return p.fakePeer.SetInputState(epoch, paused)
}

// Regression (ASSIST-T3-ELEVATION-RACE): local injection is paused under the
// input lock before the peer learns the new epoch, so an in-flight frame
// carrying the old epoch can never be injected once a pause has begun.
func TestPauseRemoteInputStopsInFlightInjectionBeforeNotifyingThePeer(t *testing.T) {
	grant := &fakeGrant{control: true}
	input := newInputControl(grant, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, "monitor-1")
	peer := &pauseProbePeer{fakePeer: &fakePeer{input: make(chan []byte, inputQueueSize)}, input: input}
	peer.inputGate.inputEpoch = 1
	r := &sessionResources{grant: grant, peer: peer, input: input}
	epoch, err := pauseRemoteInput(t.Context(), r, time.Second)
	if err != nil || epoch != 2 {
		t.Fatalf("pause = %d, %v", epoch, err)
	}
	if !errors.Is(peer.inFlight, errInvalidInput) {
		t.Fatalf("in-flight pre-pause frame = %v, want refused", peer.inFlight)
	}
	if events, _ := grant.snapshot(); len(events) != 0 {
		t.Fatalf("injected during the pause: %+v", events)
	}
	if peer.inputGate.inputEpoch != 2 || !peer.inputGate.inputPaused {
		t.Fatal("peer did not advance to the paused epoch")
	}
}
