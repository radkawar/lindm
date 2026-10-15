// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

const (
	actionAllow         = "allow"
	actionAllowRecord   = "allow_record"
	actionDecline       = "decline"
	actionStop          = "stop"
	actionStopRecording = "stop_recording"

	maxEndDetail   = 256
	inputQueueSize = 64
)

var (
	errSessionEnded   = errors.New("session_ended")
	errExpired        = errors.New("expired")
	errConsentTimeout = errors.New("consent_timeout")
)

// sessionDeps are the per-session collaborators and timings shared by all
// sessions of one helper.
type sessionDeps struct {
	notifier               Notifier
	portal                 Portal
	capturer               Capturer
	peers                  PeerFactory
	logger                 *slog.Logger
	clock                  func() time.Time
	validator              protovalidate.Validator
	filesUnavailableReason string
	// recordings uploads sealed recording segments; recording and reconnect
	// gates carry the production composition's exact-release admission.
	recordings                 recordingSink
	recordingUnavailableReason string
	reconnectUnavailableReason string
	recordingFlush             time.Duration
	// Tier 3 collaborators, each with the composition's exact-release gate.
	overlay                     Overlay
	annotationUnavailableReason string
	audio                       AudioDevices
	audioUnavailableReason      string
	enrollments                 EnrollmentStore
	unattendedUnavailableReason string
	elevationUnavailableReason  string
	// unattendedRestore bounds restoring the persistent grant; a dialog in
	// its place is a refusal, never something an absent user could answer.
	unattendedRestore time.Duration
	// lockReporting is nil when every lock of this desktop is observable
	// (logind LockedHint or the LockMonitor's logind signals).
	lockReporting error
	// currentDesktop is the session's XDG_CURRENT_DESKTOP; with the
	// executor-observed session type it selects the desktop profile.
	currentDesktop        string
	fixedDesktopQualifier FixedDesktopQualifier

	firstPacketTimeout time.Duration
	captureGrace       time.Duration
	repostInterval     time.Duration
	callTimeout        time.Duration
	cleanupTimeout     time.Duration

	// ended is the latest "Remote assistance ended" notice. GNOME shows one
	// banner at a time and keeps an idle seat's normal banner resident, so
	// a new request (even critical) queued behind it unseen until expiry
	// (org demo finance-desktop, Fedora 44). Each new prompt withdraws it.
	endedMu sync.Mutex
	ended   Notice
}

// replaceEndedNotice withdraws the previous "ended" notice and remembers next
// (nil when a prompt is about to be shown).
func (d *sessionDeps) replaceEndedNotice(ctx context.Context, next Notice) error {
	d.endedMu.Lock()
	previous := d.ended
	d.ended = next
	d.endedMu.Unlock()
	if previous == nil {
		return nil
	}
	return previous.Close(ctx)
}

// session drives one invitation from prompt to end. Its goroutine owns all
// desktop resources; the helper loop only reads reports and forwards
// directives.
type session struct {
	deps        *sessionDeps
	invitation  *agentv1.AssistanceInvitation
	sessionType string
	// profile is the desktop profile that admitted the session; set by drive
	// before the prompt and read only on its goroutine.
	profile         *desktopProfile
	logger          *slog.Logger
	cancel          context.CancelCauseFunc
	done            chan struct{}
	answers         chan string
	commands        chan *agentv1.AssistanceCommand
	authority       *time.Timer
	authorizedUntil time.Time
	life            context.Context
	files           chan *fileOperation

	mu             sync.Mutex
	phase          agentv1.AssistancePhase
	offer          string
	control        bool
	cause          agentv1.AssistanceEndCause
	detail         string
	answered       bool
	prompted       bool
	granted        *agentv1.AssistanceCapabilities
	displays       []*agentv1.AssistanceDisplay
	selected       string
	generation     uint32
	frame          DisplayFrame
	mediaPeer      Peer
	command        *agentv1.AssistanceCommand
	commandResult  *agentv1.AssistanceCommandResult
	commandHistory map[string][32]byte
	commandBusy    bool
	commandEpoch   uint32
	commandCancel  context.CancelFunc
	fileOperation  *fileOperation
	fileReport     *agentv1.AssistanceFileReport
	fileHistory    map[string][32]byte
	fileReserved   uint64
	fileBusy       bool
	inputState     *agentv1.AssistanceInputState
	recorder       *recorder
	audio          *agentv1.AssistanceAudioReport
	annotation     *agentv1.AssistanceAnnotationReport
	unattended     *agentv1.AssistanceUnattendedReport
}

// sessionResources are released by cleanup in a fixed order.
type sessionResources struct {
	prompt      Notice
	grant       Grant
	peer        Peer
	capture     Capture
	forwardDone chan struct{}
	inputDone   chan struct{}
	// indicatorMu guards the indicator and its banner slot between serve,
	// operator messages and in-session notices (prompt_banner.go).
	indicatorMu sync.Mutex
	indicator   Notice
	// prompts counts in-session notices holding the banner; while one does,
	// the indicator is withdrawn (indicatorWithdrawn) and reposted on release.
	prompts            int
	indicatorWithdrawn bool
	// indicatorClosed is set by cleanup; nothing reposts the indicator after.
	indicatorClosed bool
	// indicatorChanged tells serve that the posted indicator changed.
	indicatorChanged chan struct{}
	markup           bool
	input            *inputControl
	captureCancel    context.CancelFunc
	captureDone      chan error
	timeline         rtpTimeline
	commandDone      chan struct{}
	message          Notice
	messageUntil     time.Time
	lastMessage      time.Time
	modalMu          sync.Mutex
	fileDone         chan struct{}
	filePumpDone     chan struct{}
	recorder         *recorder
	// recordingChanged re-posts the indicator when recording stops or fails.
	recordingChanged chan struct{}
	annotation       *annotationControl
	annotationDone   chan struct{}
	audio            *audioControl
}

func startSession(parent context.Context, deps *sessionDeps, directive *agentv1.AssistanceDirective, sessionType string, group *sync.WaitGroup) *session {
	invitation := directive.GetInvitation()
	ctx, cancel := context.WithCancelCause(parent)
	s := &session{
		deps:           deps,
		invitation:     invitation,
		sessionType:    sessionType,
		logger:         deps.logger.With("session_id", invitation.GetSessionId()),
		cancel:         cancel,
		done:           make(chan struct{}),
		answers:        make(chan string, 1),
		commands:       make(chan *agentv1.AssistanceCommand, 1),
		commandHistory: make(map[string][32]byte),
		files:          make(chan *fileOperation, 1),
		fileHistory:    make(map[string][32]byte),
		inputState:     &agentv1.AssistanceInputState{Epoch: 1},
	}
	s.renewAuthority(directive)
	runCtx, release := context.WithDeadlineCause(ctx, invitation.GetEndsAt().AsTime(), errExpired)
	s.life = runCtx
	group.Go(func() {
		defer release()
		s.run(runCtx)
	})
	return s
}

// endedSession is a session known only by its final state.
func endedSession(invitation *agentv1.AssistanceInvitation, cause agentv1.AssistanceEndCause, detail string) *session {
	done := make(chan struct{})
	close(done)
	return &session{
		invitation: invitation,
		cancel:     func(error) {},
		done:       done,
		phase:      agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED,
		cause:      cause,
		detail:     sanitizeDetail(detail),
	}
}

func (s *session) id() string { return s.invitation.GetSessionId() }

// end records the first end cause and stops the session goroutine.
func (s *session) end(cause agentv1.AssistanceEndCause, detail string) {
	s.mu.Lock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		s.mu.Unlock()
		return
	}
	if cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
		cause, detail = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "helper_stopped"
	}
	s.phase, s.cause, s.detail = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, cause, sanitizeDetail(detail)
	s.frame = DisplayFrame{}
	if s.mediaPeer != nil {
		s.mediaPeer.EndDisplayFrames()
	}
	if s.authority != nil {
		s.authority.Stop()
	}
	expireClipboardResult(s.commandResult, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED, "session_ended")
	s.mu.Unlock()
	if s.logger != nil {
		s.logger.Info("remote assistance ended", "cause", cause.String(), "detail", detail)
	}
	s.cancel(errSessionEnded)
}

func (s *session) ended() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED
}

// report returns the helper's observation, or false before the prompt is
// visible (the executor keeps such sessions PENDING).
func (s *session) report() (*agentv1.SessionAssistanceReport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_UNSPECIFIED {
		return nil, false
	}
	report := &agentv1.SessionAssistanceReport{
		SessionId:             s.id(),
		Phase:                 s.phase,
		ControlGranted:        s.control,
		RequestedCapabilities: proto.CloneOf(s.invitation.GetRequestedCapabilities()),
		EffectiveCapabilities: proto.CloneOf(s.invitation.GetEffectiveCapabilities()),
		GrantedCapabilities:   proto.CloneOf(s.granted),
		Displays:              cloneDisplays(s.displays),
		SelectedDisplayId:     s.selected,
		DisplayGeneration:     s.generation,
	}
	report.FileTransfer = proto.CloneOf(s.fileReport)
	report.InputState = proto.CloneOf(s.inputState)
	if s.recorder != nil {
		report.Recording = s.recorder.report()
	}
	report.Audio = proto.CloneOf(s.audio)
	report.Annotation = proto.CloneOf(s.annotation)
	report.Unattended = proto.CloneOf(s.unattended)
	if (s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED || s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE) &&
		s.frame.Generation != 0 && s.frame.Display == s.selected && s.frame.Generation == s.generation {
		report.DisplayFrame = &agentv1.AssistanceDisplayFrame{DisplayId: s.frame.Display, Generation: s.frame.Generation, RtpTimestamp: s.frame.RTPTimestamp}
	}
	if s.commandResult != nil {
		if s.command == nil || !s.deps.clock().Before(s.command.GetDeadline().AsTime()) {
			expireClipboardResult(s.commandResult, agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, "content_expired")
		}
		report.CommandResult = proto.CloneOf(s.commandResult)
	}
	switch s.phase {
	case agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE:
		report.OfferSdp = s.offer
	case agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED:
		report.OfferSdp = s.offer
		report.EndCause = s.cause
		report.EndDetail = s.detail
	}
	return report, true
}

// apply handles one directive idempotently: terminate ends the session;
// the first answer is forwarded once and later copies are ignored.
func (s *session) apply(directive *agentv1.AssistanceDirective) {
	if directive.GetTerminate() {
		cause := directive.GetTerminateCause()
		if cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
			cause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
		}
		s.end(cause, "terminate_directive")
		return
	}
	if !proto.Equal(consentedPolicy(s.invitation), consentedPolicy(directive.GetInvitation())) {
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "capability_authority_changed")
		return
	}
	s.renewAuthority(directive)
	if command := directive.GetCommand(); command != nil {
		s.applyCommand(command)
	}
	s.applyFile(directive.GetFileTransfer())
	answer := directive.GetAnswerSdp()
	if answer == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.answered || s.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED {
		return
	}
	s.answered = true
	s.answers <- answer
}

func (s *session) advance(phase agentv1.AssistancePhase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED || phase <= s.phase {
		return
	}
	s.phase = phase
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		s.prompted = true
	}
}

func (s *session) offered(offer string, control bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return
	}
	s.phase, s.offer, s.control = agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, offer, control
}

func (s *session) run(ctx context.Context) {
	defer close(s.done)
	resources := &sessionResources{indicatorChanged: make(chan struct{}, 1)}
	cause, detail := s.drive(ctx, resources)
	s.end(cause, detail)
	s.cleanup(resources)
}

// drive runs the session until it must end and returns why. Context
// cancellation by end() returns UNSPECIFIED, which end ignores because the
// first cause wins.
func (s *session) drive(ctx context.Context, r *sessionResources) (agentv1.AssistanceEndCause, string) {
	if ctx.Err() != nil {
		return s.failure(ctx, ctx.Err())
	}
	deps := s.deps
	consentCtx, cancelConsent := context.WithDeadlineCause(ctx, s.invitation.GetConsentDeadline().AsTime(), errConsentTimeout)
	defer cancelConsent()

	capabilities, err := deps.notifier.Capabilities(consentCtx)
	if err != nil {
		return s.failure(consentCtx, unavailable("notification_server_unavailable", err))
	}
	if !slices.Contains(capabilities, "actions") {
		return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "notification_actions_unavailable"
	}
	profile, qualificationErr := deps.qualifiedDesktopProfile(consentCtx, s.sessionType)
	admission := admitDesktop(profile, s.invitation.GetMode(), consentedPolicy(s.invitation))
	admission.runtimeErr = qualificationErr
	s.profile = admission.profile
	policy := admission.policy
	request := PortalRequest{Mode: s.invitation.GetMode(), Policy: policy, Lifetime: ctx, RequireRemoteDesktop: s.profile == cosmicWayland}
	if err := s.servable(consentCtx, request, admission); err != nil {
		return s.failure(consentCtx, err)
	}
	recording, err := s.recordingOffer(policy)
	if err != nil {
		return s.failure(consentCtx, err)
	}
	r.markup = slices.Contains(capabilities, "body-markup")
	s.logIfErr("withdraw previous end notice", deps.replaceEndedNotice(consentCtx, nil))
	unattended := s.invitation.GetUnattended() != nil
	enroll := false
	var audio []AudioSource
	audioMode := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	var grant Grant
	if unattended {
		if recording.offered && !recording.required {
			// Nobody attends to opt in to optional recording.
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "unattended_optional_recording"
		}
		record := recording.required
		grant, err = s.openUnattended(consentCtx, r, capabilities, request)
		if err != nil {
			return s.failure(consentCtx, err)
		}
		r.grant = grant
		if cause, detail := s.establish(ctx, consentCtx, r, admission, recording, record, audio, audioMode, "unattended_no_local_choice", false); cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED || detail != "" {
			return cause, detail
		}
		cancelConsent()
		return s.serve(ctx, r, r.captureDone)
	}
	prompt, err := deps.notifier.Notify(consentCtx, s.promptNotification(r.markup, recording, policy))
	if err != nil {
		return s.failure(consentCtx, unavailable("notification_failed", err))
	}
	r.prompt = prompt
	s.advance(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	s.logger.Info("remote assistance prompt shown", "mode", s.invitation.GetMode().String())
	record := false
	select {
	case action := <-prompt.Result():
		r.prompt = nil
		switch action {
		case actionAllow:
			record = recording.required
		case actionAllowRecord:
			if !recording.offered || recording.required {
				return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "prompt_action_invalid"
			}
			record = true
		case actionAllowUnattended:
			if !s.enrollmentOffered(policy, recording) {
				return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "prompt_action_invalid"
			}
			record, enroll = recording.required, true
		case "":
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "prompt_dismissed"
		default:
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "prompt_declined"
		}
	case <-consentCtx.Done():
		return s.failure(consentCtx, consentCtx.Err())
	}
	// Sound and microphone are separate local choices; screen consent never
	// implies either.
	audio, audioMode, audioReason := s.chooseAudio(consentCtx, r, policy)
	if consentCtx.Err() != nil {
		return s.failure(consentCtx, consentCtx.Err())
	}
	request.Persist = enroll
	grant, err = deps.portal.Open(consentCtx, request)
	if err != nil {
		return s.failure(consentCtx, err)
	}
	r.grant = grant
	if cause, detail := s.establish(ctx, consentCtx, r, admission, recording, record, audio, audioMode, audioReason, enroll); cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED || detail != "" {
		return cause, detail
	}
	cancelConsent()
	return s.serve(ctx, r, r.captureDone)
}

// enrollmentOffered reports whether the prompt offers the unattended opt-in
// under policy, the consented policy narrowed to the desktop profile.
// Desktops show at most three actions, so it is never combined with optional
// recording; the server refuses that combination before inviting.
func (s *session) enrollmentOffered(policy *agentv1.AssistancePolicy, recording recordingOffer) bool {
	return policyEnabled(policy.GetUnattended()) && s.deps.enrollments != nil && s.deps.unattendedUnavailableReason == "" && (!recording.offered || recording.required)
}

// establish turns a started portal grant into the offered peer: the local
// grant narrowed by the desktop admission, recording, peer, capture and
// offer. It returns UNSPECIFIED with an empty detail on success.
func (s *session) establish(ctx, consentCtx context.Context, r *sessionResources, admission desktopAdmission, recording recordingOffer, record bool, audio []AudioSource, audioMode agentv1.AssistancePolicyMode, audioReason string, enroll bool) (agentv1.AssistanceEndCause, string) {
	deps := s.deps
	grant := r.grant
	control := s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL && grant.ControlGranted()
	streams := grant.Streams()
	if len(streams) == 0 || len(streams) > 8 {
		return s.failure(consentCtx, unavailable("portal_stream_missing", nil))
	}
	granted := grantedCapabilities(admission.policy, grant)
	admission.annotate(granted, grant.PortalVersions())
	if err := s.prepareRecording(r, granted, recording, record, streams[0]); err != nil {
		return s.failure(consentCtx, err)
	}
	unattendedReport := s.enrollUnattended(grant, granted, enroll)
	s.grantTierThree(consentCtx, granted, streams, audio, audioMode, audioReason)
	if !policyEnabled(granted.GetPolicy().GetAudio()) {
		audio = nil
	}
	s.adoptGrant(r, granted, streams, unattendedReport)
	r.input = newInputControl(grant, s.granted.GetPolicy().GetKeyboard(), streams[0].ID)
	annotate := policyEnabled(s.granted.GetPolicy().GetAnnotation())
	peer, err := deps.peers.NewPeer(PeerConfig{ICEServers: s.invitation.GetIceServers(), Input: control, Files: policyEnabled(s.granted.GetPolicy().GetFiles()), Annotation: annotate, Audio: len(audio) != 0})
	if err != nil {
		return s.failure(consentCtx, unavailable("peer_setup_failed", err))
	}
	r.peer = peer
	s.mu.Lock()
	s.mediaPeer = peer
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		peer.EndDisplayFrames()
	}
	s.mu.Unlock()
	if annotate {
		r.annotation = newAnnotationControl(s, deps.overlay, s.granted.GetPolicy().GetAnnotation())
		r.annotation.publish()
	}
	if policyEnabled(admission.policy.GetAudio()) {
		r.audio = newAudioControl(s, deps.audio, audio)
	}
	r.captureDone = make(chan error, 1)
	if err := s.startCapture(ctx, consentCtx, r, streams[0]); err != nil {
		return s.failure(consentCtx, err)
	}
	offer, err := peer.Offer(consentCtx)
	if err != nil {
		return s.failure(consentCtx, unavailable("offer_failed", err))
	}
	if err := relayOnly(offer); err != nil {
		return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, err.Error()
	}
	s.offered(offer, control)
	s.logger.Info("remote assistance offered", "control_granted", control, "unattended", s.invitation.GetUnattended() != nil)
	if control {
		r.inputDone = make(chan struct{})
		go s.forwardInput(ctx, r.input, peer.Input(), r.inputDone)
	}
	r.commandDone = make(chan struct{})
	go s.commandLoop(ctx, r)
	if policyEnabled(s.granted.GetPolicy().GetFiles()) {
		r.fileDone, r.filePumpDone = make(chan struct{}), make(chan struct{})
		go s.fileLoop(ctx, r)
		go s.filePump(ctx, r)
	}
	if r.annotation != nil {
		r.annotationDone = make(chan struct{})
		go s.annotationLoop(ctx, r, r.annotationDone)
	}
	if r.audio != nil {
		r.audio.start(ctx, r)
	}
	return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED, ""
}

// grantTierThree applies each Tier 3 capability's local gate to the grant.
// A missing overlay, audio choice or release qualification withholds that
// capability with an exact reason; it never ends the session.
func (s *session) grantTierThree(ctx context.Context, granted *agentv1.AssistanceCapabilities, streams []Stream, audio []AudioSource, audioMode agentv1.AssistancePolicyMode, audioReason string) {
	p := granted.Policy
	off := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	if policyEnabled(p.GetElevation()) && s.deps.elevationUnavailableReason != "" {
		p.Elevation, granted.ElevationReason = off, s.deps.elevationUnavailableReason
	}
	if policyEnabled(p.GetAnnotation()) {
		reason := s.deps.annotationUnavailableReason
		switch {
		case reason != "":
		case s.deps.overlay == nil:
			reason = "overlay_unavailable"
		case len(streams) > 1 && slices.ContainsFunc(streams, func(stream Stream) bool { return !stream.Positioned }):
			// Without each monitor's position marks could land on the wrong one.
			reason = "overlay_monitor_position_unknown"
		default:
			if err := s.deps.overlay.Check(ctx); err != nil {
				reason = "overlay_unavailable"
				var endErr *EndError
				if errors.As(err, &endErr) {
					reason = endErr.Detail
				}
			}
		}
		if reason != "" {
			p.Annotation, granted.AnnotationReason = off, reason
		}
	}
	if policyEnabled(p.GetAudio()) {
		if len(audio) == 0 {
			p.Audio, granted.AudioReason = off, audioReason
		} else {
			p.Audio = min(p.GetAudio(), audioMode)
		}
	}
}

// adoptGrant publishes the consented capabilities, recorder, unattended
// enrollment and displays.
func (s *session) adoptGrant(r *sessionResources, granted *agentv1.AssistanceCapabilities, streams []Stream, unattended *agentv1.AssistanceUnattendedReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted = granted
	s.unattended = unattended
	s.recorder = r.recorder
	if s.deps.filesUnavailableReason != "" && policyEnabled(s.granted.GetPolicy().GetFiles()) {
		s.granted.Policy.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		s.granted.Policy.FileLimits = nil
		s.granted.FilesReason = s.deps.filesUnavailableReason
	}
	s.selected, s.generation = streams[0].ID, 1
	for _, stream := range streams {
		s.displays = append(s.displays, &agentv1.AssistanceDisplay{Id: stream.ID, Label: stream.Label, Width: uint32(stream.Width), Height: uint32(stream.Height)})
	}
}

// servable refuses, before any prompt, a session this desktop cannot honour.
// The request is already narrowed to the desktop profile, so the portal is
// asked only for that. Native gaps are named first: a missing ScreenCast (or,
// for CONTROL and all COSMIC requests, RemoteDesktop) portal; a notification
// server with hidden or unverified action buttons, which would present a
// prompt without visible Allow/Decline where activating it allows; then a
// desktop whose locks lindm cannot observe, which would keep sharing a locked
// screen. Then the Tier 3 desktop gate and qualification table refuse what
// policy or evidence does not admit.
func (s *session) servable(ctx context.Context, request PortalRequest, admission desktopAdmission) error {
	if err := s.deps.portal.Check(ctx, request); err != nil {
		return unavailable("portal_unavailable", err)
	}
	server, version, err := s.deps.notifier.ServerInformation(ctx)
	if err != nil {
		return unavailable("notification_server_unavailable", err)
	}
	if reason := platform.NotificationActionsUnavailable(server, version); reason != "" {
		return unavailable(reason, nil)
	}
	if admission.runtimeErr != nil {
		return unavailable("desktop_runtime_unqualified", admission.runtimeErr)
	}
	if s.deps.lockReporting != nil && !admission.profile.fixedTuple {
		return s.deps.lockReporting
	}
	if admission.refusal != "" {
		return unavailable(admission.refusal, fmt.Errorf("desktop profile %s", admission.profile.name))
	}
	return nil
}

// recordingOffer is the recording the prompt may disclose on this device.
// Required recording that this release cannot provide is refused before any
// prompt or capture; optional recording is simply not offered.
func (s *session) recordingOffer(policy *agentv1.AssistancePolicy) (recordingOffer, error) {
	recording, err := offerRecording(s.invitation, policy)
	if err != nil || !recording.offered || (s.deps.recordingUnavailableReason == "" && s.deps.recordings != nil) {
		return recording, err
	}
	if recording.required {
		return recordingOffer{}, &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, Detail: "recording_unavailable"}
	}
	return recordingOffer{}, nil
}

// prepareRecording applies the local recording decision to the grant and
// starts sealing before the first captured frame. Required recording that
// cannot start ends the session; optional recording is withheld instead.
func (s *session) prepareRecording(r *sessionResources, granted *agentv1.AssistanceCapabilities, recording recordingOffer, record bool, stream Stream) error {
	deps := s.deps
	if deps.reconnectUnavailableReason != "" && policyEnabled(granted.GetPolicy().GetReconnect()) {
		granted.Policy.Reconnect, granted.Policy.ReconnectLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
		granted.ReconnectReason = deps.reconnectUnavailableReason
	}
	switch {
	case !recording.offered:
		if policyEnabled(granted.GetPolicy().GetRecording()) {
			withholdRecording(granted, cmp.Or(deps.recordingUnavailableReason, "recording_unavailable"))
		}
		return nil
	case !record:
		withholdRecording(granted, "user_declined")
		return nil
	}
	width, height, ok := scaledSize(stream.Width, stream.Height)
	if !ok {
		width, height = 1280, 720
	}
	r.recordingChanged = make(chan struct{}, 1)
	r.recorder = newRecorder(s.id(), s.invitation.GetRecording(), deps.recordings, s.logger, deps.clock, deps.callTimeout, deps.recordingFlush, func(string) {
		if recording.required {
			s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_failed")
			return
		}
		select {
		case r.recordingChanged <- struct{}{}:
		default:
		}
	})
	if err := r.recorder.start(uint32(width), uint32(height)); err != nil {
		r.recorder = nil
		if recording.required {
			return &EndError{Cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, Detail: "recording_key_invalid", Err: err}
		}
		withholdRecording(granted, "recording_key_invalid")
	}
	return nil
}

// openIndicator shows the in-progress indicator as the OFFERED phase begins
// and reports an end cause when it cannot.
func (s *session) openIndicator(ctx context.Context, r *sessionResources) (agentv1.AssistanceEndCause, string) {
	indicatorFailed := func(err error) (agentv1.AssistanceEndCause, string) {
		if r.recorder != nil && r.recorder.recording() {
			// Recording is never captured without its continuous indicator.
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_indicator_failed"
		}
		if s.invitation.GetUnattended() != nil {
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "unattended_banner_failed"
		}
		return s.failure(ctx, unavailable("indicator_failed", err))
	}
	if r.prompt == nil {
		if err := s.showIndicator(ctx, r); err != nil {
			return indicatorFailed(err)
		}
		return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED, ""
	}
	select {
	case action := <-r.prompt.Result():
		r.prompt = nil
		return s.failure(ctx, s.unattendedStopped(action))
	default:
	}
	// The unattended banner becomes the indicator in place, so there is never
	// a moment without it. A separate indicator posted while the banner shows
	// waits behind it on GNOME without animations, and closing the banner
	// then stranded it unseen (layers-fedora44-tier3-34).
	if err := r.prompt.Update(ctx, s.indicatorNotification(r.markup, r.recorder)); err != nil {
		return indicatorFailed(err)
	}
	r.indicatorMu.Lock()
	r.indicator = r.prompt
	r.indicatorMu.Unlock()
	r.prompt = nil
	return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED, ""
}

// serve runs the OFFERED/ACTIVE phase.
func (s *session) serve(ctx context.Context, r *sessionResources, captureDone <-chan error) (agentv1.AssistanceEndCause, string) {
	if cause, detail := s.openIndicator(ctx, r); cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
		return cause, detail
	}
	lastPost := s.deps.clock()
	indicator := r.currentIndicator()
	indicatorResult := noticeResult(indicator)
	var repost *time.Timer
	var repostC <-chan time.Time
	defer func() {
		if repost != nil {
			repost.Stop()
		}
	}()
	connected := r.peer.Connected()
	answers := s.answers
	for {
		select {
		case <-r.recordingChanged:
			// Recording stopped or failed: the continuous indicator must
			// never claim, or omit, recording that is not, or is, happening.
			r.indicatorMu.Lock()
			old := r.indicator
			r.indicator = nil
			r.indicatorMu.Unlock()
			if old != nil {
				s.logIfErr("replace indicator", old.Close(ctx))
			}
			if repost != nil {
				repost.Stop()
				repost, repostC = nil, nil
			}
			if err := s.showIndicator(ctx, r); err != nil {
				return s.failure(ctx, unavailable("indicator_failed", err))
			}
			indicator = r.currentIndicator()
			indicatorResult, lastPost = noticeResult(indicator), s.deps.clock()
		case <-r.indicatorChanged:
			// An in-session notice withdrew the indicator or gave it back.
			if repost != nil {
				repost.Stop()
				repost, repostC = nil, nil
			}
			indicator = r.currentIndicator()
			indicatorResult = noticeResult(indicator)
			if indicator != nil {
				lastPost = s.deps.clock()
			}
		case <-ctx.Done():
			return s.failure(ctx, ctx.Err())
		case sdp := <-answers:
			answers = nil
			// The server already enforces this; the helper never pairs with
			// a non-relay remote either.
			if err := relayOnly(sdp); err != nil {
				return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "answer_" + err.Error()
			}
			if err := r.peer.Answer(sdp); err != nil {
				s.logger.Warn("remote assistance answer rejected", "err", err)
				return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "answer_rejected"
			}
		case <-connected:
			connected = nil
			s.advance(agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE)
			s.logger.Info("remote assistance active")
		case <-r.peer.Failed():
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED, "peer_connection_failed"
		case <-r.grant.Closed():
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED, "portal_session_closed"
		case err := <-captureDone:
			// Closing the portal also ends pipewiresrc; prefer that cause.
			grace := time.NewTimer(s.deps.captureGrace)
			select {
			case <-r.grant.Closed():
				grace.Stop()
				return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED, "portal_session_closed"
			case <-grace.C:
			}
			s.logger.Warn("remote assistance capture exited", "err", err)
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_exited"
		case action := <-indicatorResult:
			indicatorResult = nil
			if action == actionStop {
				return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED, "local_stop"
			}
			if action == actionUnattendedOff && s.invitation.GetUnattended() != nil {
				return s.failure(ctx, s.unattendedStopped(action))
			}
			if action == actionElevationPause && policyEnabled(s.granted.GetPolicy().GetElevation()) {
				go s.localElevation(ctx, r)
			}
			if action == actionStopRecording && r.recorder != nil && r.recorder.recording() && !r.recorder.authority.GetRequired() {
				rec := r.recorder
				go func() {
					rec.finish("user_stopped")
					select {
					case r.recordingChanged <- struct{}{}:
					default:
					}
				}()
			}
			r.clearIndicator(indicator)
			repost = time.NewTimer(max(0, lastPost.Add(s.deps.repostInterval).Sub(s.deps.clock())))
			repostC = repost.C
		case <-repostC:
			repostC, repost = nil, nil
			if err := s.showIndicator(ctx, r); err != nil {
				if r.recorder != nil && r.recorder.recording() {
					return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED, "recording_indicator_failed"
				}
				return s.failure(ctx, unavailable("indicator_failed", err))
			}
			indicator = r.currentIndicator()
			indicatorResult, lastPost = noticeResult(indicator), s.deps.clock()
		}
	}
}

// clearIndicator forgets indicator once the employee acted on it, unless an
// in-session notice already replaced it.
func (r *sessionResources) clearIndicator(indicator Notice) {
	r.indicatorMu.Lock()
	if r.indicator == indicator {
		r.indicator = nil
	}
	r.indicatorMu.Unlock()
}

func noticeResult(notice Notice) <-chan string {
	if notice == nil {
		return nil
	}
	return notice.Result()
}

// failure maps a step error to an end cause. Context causes win because
// component errors after cancellation are consequences, not causes.
func (s *session) failure(ctx context.Context, err error) (agentv1.AssistanceEndCause, string) {
	if ctx.Err() != nil {
		switch cause := context.Cause(ctx); {
		case errors.Is(cause, errSessionEnded):
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED, ""
		case errors.Is(cause, errExpired):
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED, "ends_at_reached"
		case errors.Is(cause, errConsentTimeout):
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT, "consent_deadline_reached"
		case errors.Is(cause, errFileProtocol):
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "file_authority_invalid"
		default:
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "helper_stopped"
		}
	}
	if errors.Is(err, ErrPortalCancelled) {
		return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "portal_cancelled"
	}
	var endErr *EndError
	if errors.As(err, &endErr) {
		s.logger.Warn("remote assistance step failed", "detail", endErr.Detail, "err", endErr.Err)
		return endErr.Cause, endErr.Detail
	}
	s.logger.Warn("remote assistance step failed", "err", err)
	return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "unavailable"
}

// forwardMedia copies encoder packets to the peer until the capture ends.
func (s *session) forwardMedia(ctx context.Context, r *sessionResources, capture Capture, display string, generation uint32, firstPacket chan<- struct{}, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, maxRTPPacket)
	first := true
	marked := false
	for {
		n, err := capture.ReadPacket(buf)
		if err != nil {
			if ctx.Err() == nil {
				select {
				case r.captureDone <- err:
				case <-ctx.Done():
				}
			}
			return
		}
		if err := ctx.Err(); err != nil {
			return
		}
		if err := r.timeline.rewrite(buf[:n], first, s.deps.clock()); err != nil {
			select {
			case r.captureDone <- err:
			case <-ctx.Done():
			}
			return
		}
		if first {
			first = false
			close(firstPacket)
		}
		if r.recorder != nil {
			r.recorder.write(buf[:n])
		}
		emitted, err := r.peer.WriteRTP(buf[:n])
		if err != nil {
			s.logger.Debug("remote assistance rtp write failed", "err", err)
			continue
		}
		if emitted && !marked {
			if err := ctx.Err(); err != nil {
				return
			}
			frame := DisplayFrame{Display: display, Generation: generation, RTPTimestamp: binary.BigEndian.Uint32(buf[4:8])}
			if err := s.publishDisplayFrame(r, frame); err != nil {
				select {
				case r.captureDone <- err:
				case <-ctx.Done():
				}
				return
			}
			marked = true
		}
	}
}

// The same exact media witness feeds CONTROL's reliable channel and the typed
// report (also used by VIEW, which has no data channel). A switch's candidate
// remains private until selected/gen/result are atomically published.
func (s *session) publishDisplayFrame(r *sessionResources, frame DisplayFrame) error {
	r.input.mu.Lock()
	defer r.input.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return errSessionEnded
	}
	if frame.Display != r.input.display || frame.Generation != r.input.generation {
		return nil
	}
	if s.frame.Display == frame.Display && s.frame.Generation == frame.Generation {
		return nil
	}
	if err := r.peer.PublishDisplayFrame(frame); err != nil {
		return err
	}
	s.frame = frame
	return nil
}

// forwardInput injects rate-limited, validated operator input and releases
// every held key and button when the session ends.
func (s *session) forwardInput(ctx context.Context, input *inputControl, messages <-chan []byte, done chan<- struct{}) {
	defer close(done)
	limiter := newInputLimiter(s.deps.clock())
	var dropped, rejected int
	defer func() {
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.deps.callTimeout)
		defer cancel()
		if err := input.releaseAll(release); err != nil {
			s.logger.Warn("remote assistance input release failed", "err", err)
		}
		if dropped > 0 || rejected > 0 {
			s.logger.Info("remote assistance input dropped", "rate_limited", dropped, "invalid", rejected)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-messages:
			if !ok {
				return
			}
			event, err := parseInput(message)
			if err != nil {
				rejected++
				continue
			}
			// Never rate-drop releases: a burst must not leave a key held.
			releasing := event.kind == inputRelease || ((event.kind == inputKey || event.kind == inputKeysym || event.kind == inputButton) && !event.Down)
			if !releasing && !limiter.allow(s.deps.clock()) {
				dropped++
				continue
			}
			call, cancel := context.WithTimeout(ctx, s.deps.callTimeout)
			err = input.inject(call, event)
			cancel()
			if errors.Is(err, errInvalidInput) {
				rejected++
				continue
			}
			if err != nil && ctx.Err() == nil {
				s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "input_injection_failed")
				return
			}
		}
	}
}

// cleanup releases resources: media and data first, then held input, the
// portal session, the encoder and the notifications.
func (s *session) cleanup(r *sessionResources) {
	ctx, cancel := context.WithTimeout(context.Background(), s.deps.cleanupTimeout)
	defer cancel()
	if r.commandDone != nil {
		<-r.commandDone
	}
	if r.fileDone != nil {
		<-r.fileDone
	}
	if r.filePumpDone != nil {
		<-r.filePumpDone
	}
	s.mu.Lock()
	if s.command != nil {
		s.command.Text = ""
	}
	for len(s.commands) > 0 {
		<-s.commands
	}
	s.mu.Unlock()
	if r.annotationDone != nil {
		<-r.annotationDone
	}
	if r.annotation != nil {
		s.logIfErr("close overlay", r.annotation.close(ctx))
	}
	if r.audio != nil {
		// Sound capture stops before the peer and portal session close.
		r.audio.close(ctx)
	}
	if r.captureCancel != nil {
		r.captureCancel()
	}
	if r.prompt != nil {
		s.logIfErr("close prompt", r.prompt.Close(ctx))
	}
	if r.peer != nil {
		s.logIfErr("close peer", r.peer.Close())
	}
	if r.inputDone != nil {
		<-r.inputDone
	}
	if r.grant != nil {
		s.logIfErr("close portal session", r.grant.Close(ctx))
	}
	if r.capture != nil {
		s.logIfErr("stop capture", r.capture.Close())
		if r.forwardDone != nil {
			<-r.forwardDone
		}
	}
	if r.recorder != nil {
		// No frame after termination is recorded; the final segment seals
		// only what was captured before capture stopped.
		r.recorder.finish("session_ended")
	}
	r.indicatorMu.Lock()
	indicator := r.indicator
	r.indicator, r.indicatorClosed = nil, true
	r.indicatorMu.Unlock()
	if indicator != nil {
		s.logIfErr("close indicator", indicator.Close(ctx))
	}
	if r.message != nil {
		s.logIfErr("close operator message", r.message.Close(ctx))
	}
	s.mu.Lock()
	prompted, cause := s.prompted, s.cause
	s.mu.Unlock()
	if prompted && cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED {
		notice, err := s.deps.notifier.Notify(ctx, Notification{
			Summary:  "Remote assistance ended",
			Body:     sentence(causeText(cause)),
			Lifetime: 10 * time.Second,
		})
		s.logIfErr("post end notice", err)
		if err == nil {
			s.logIfErr("withdraw previous end notice", s.deps.replaceEndedNotice(ctx, notice))
		}
	}
}

func (s *session) logIfErr(step string, err error) {
	if err != nil {
		s.logger.Warn("remote assistance cleanup failed", "step", step, "err", err)
	}
}

// promptNotification discloses policy, the consented policy already narrowed
// to the desktop profile.
func (s *session) promptNotification(markup bool, offer recordingOffer, policy *agentv1.AssistancePolicy) Notification {
	operator, reason := s.invitation.GetOperatorDisplay(), s.invitation.GetReason()
	if markup {
		operator, reason = html.EscapeString(operator), html.EscapeString(reason)
	}
	var body strings.Builder
	if s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		if policyEnabled(policy.GetKeyboard()) {
			fmt.Fprintf(&body, "%s asks to view your screen and control your keyboard and pointer.\n", operator)
		} else {
			fmt.Fprintf(&body, "%s asks to view your screen and control your pointer. Keyboard control is not requested.\n", operator)
		}
	} else {
		fmt.Fprintf(&body, "%s asks to view your screen.\n", operator)
	}
	fmt.Fprintf(&body, "Reason: %s\n", reason)
	if s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		if s.profile != nil && s.profile.sharedControlDialog {
			body.WriteString("Control is requested. On this desktop the system dialog that follows approves sharing your whole screen, every monitor, together with control; choose Decline here to refuse both.")
		} else if s.profile != nil && s.profile.selectedControlDialog {
			body.WriteString("Control is requested. This desktop's system consent grants your selected screen together with control; there is no view-only choice. Choose Decline here to refuse both.")
		} else {
			body.WriteString("Control is requested. The system dialog that follows lets you allow viewing only.")
		}
	} else {
		body.WriteString("Control is not requested. The system dialog that follows selects what is shared.")
	}
	policy = proto.CloneOf(policy)
	if s.deps != nil && s.deps.filesUnavailableReason != "" {
		policy.Files, policy.FileLimits = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, nil
	}
	body.WriteString(capabilityConsentText(policy))
	body.WriteString(recordingConsentText(offer))
	actions := []NotificationAction{{Key: actionAllow, Label: "Allow"}, {Key: actionDecline, Label: "Decline"}}
	switch {
	case offer.required:
		actions[0].Label = "Allow (recorded)"
	case offer.offered:
		actions = []NotificationAction{{Key: actionAllowRecord, Label: "Allow and record"}, {Key: actionAllow, Label: "Allow without recording"}, {Key: actionDecline, Label: "Decline"}}
	}
	if s.deps != nil && s.enrollmentOffered(policy, offer) {
		body.WriteString(unattendedConsentText(policy, s.invitation.GetUnattendedEnrollment()))
		actions = append([]NotificationAction{actions[0], {Key: actionAllowUnattended, Label: "Allow and enable unattended"}}, actions[1:]...)
	}
	// The banner summary stays visible when a desktop truncates the body, so
	// it carries the recording disclosure itself.
	summary := "Remote assistance request"
	if s.invitation.GetReconnectOf() != "" {
		summary = "Remote assistance reconnect request"
		body.WriteString("\nThis continues an earlier support session that ended. Nothing you allowed before carries over; choose again.")
	}
	switch {
	case offer.required:
		summary += " (recorded)"
	case offer.offered:
		summary += " (recording requested)"
	}
	return Notification{
		Summary:    summary,
		Body:       body.String(),
		Actions:    actions,
		Critical:   true,
		Persistent: true,
		Reshow:     true,
	}
}

func (s *session) indicatorNotification(markup bool, rec *recorder) Notification {
	if s.invitation.GetUnattended() != nil {
		return s.unattendedNotification(markup, true)
	}
	operator := s.invitation.GetOperatorDisplay()
	if markup {
		operator = html.EscapeString(operator)
	}
	s.mu.Lock()
	control := s.control
	s.mu.Unlock()
	activity := "viewing"
	if control {
		activity = "viewing and controlling"
	}
	summary := "Remote assistance in progress"
	body := fmt.Sprintf("%s is %s your screen.", operator, activity)
	actions := []NotificationAction{{Key: actionStop, Label: "Stop"}}
	if rec != nil && rec.recording() {
		summary = "Remote assistance in progress — recording"
		body += fmt.Sprintf(" This session is being recorded. Your organization keeps the encrypted recording for up to %d days and people it authorizes can play it back later.", rec.authority.GetRetentionDays())
		if !rec.authority.GetRequired() {
			actions = append(actions, NotificationAction{Key: actionStopRecording, Label: "Stop recording"})
		}
	}
	s.mu.Lock()
	elevation := policyEnabled(s.granted.GetPolicy().GetElevation())
	s.mu.Unlock()
	if elevation {
		actions = append(actions, NotificationAction{Key: actionElevationPause, Label: "Pause for password"})
	}
	return Notification{
		Summary:    summary,
		Body:       body,
		Actions:    actions,
		Critical:   true,
		Persistent: true,
	}
}

// sentence capitalizes a lowercase cause fragment and ends it with a period,
// so a notice body reads as a sentence and never repeats its title.
func sentence(fragment string) string {
	if fragment == "" {
		return ""
	}
	return strings.ToUpper(fragment[:1]) + fragment[1:] + "."
}

// relayOnly requires at least one candidate and only relay candidates.
func relayOnly(sdp string) error {
	relay := 0
	for line := range strings.Lines(sdp) {
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		if !strings.Contains(line, " typ relay") {
			return errors.New("non_relay_candidate")
		}
		relay++
	}
	if relay == 0 {
		return errors.New("no_relay_candidate")
	}
	return nil
}

func sanitizeDetail(detail string) string {
	var out strings.Builder
	for _, r := range detail {
		if out.Len() == maxEndDetail {
			break
		}
		if r < ' ' || r > '~' {
			r = '_'
		}
		out.WriteRune(r)
	}
	return out.String()
}

func causeText(cause agentv1.AssistanceEndCause) string {
	switch cause {
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED:
		return "declined"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT:
		return "no response in time"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED:
		return "stopped by the operator"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED:
		return "stopped by you"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED:
		return "screen sharing was stopped"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED:
		return "the session was locked"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED:
		return "the session ended"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED:
		return "the time limit was reached"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST:
		return "authorization was lost"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE:
		return "screen sharing is unavailable"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED:
		return "the connection failed"
	case agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DISABLED:
		return "remote assistance is disabled"
	default:
		return "ended"
	}
}
