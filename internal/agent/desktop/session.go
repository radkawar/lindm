// SPDX-License-Identifier: Apache-2.0

package desktop

import (
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
	actionAllow   = "allow"
	actionDecline = "decline"
	actionStop    = "stop"

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
	notifier  Notifier
	portal    Portal
	capturer  Capturer
	peers     PeerFactory
	logger    *slog.Logger
	clock     func() time.Time
	validator protovalidate.Validator
	// lockReporting is nil when every lock of this desktop is observable
	// (logind LockedHint or the LockMonitor's logind signals).
	lockReporting error

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
	deps            *sessionDeps
	invitation      *agentv1.AssistanceInvitation
	logger          *slog.Logger
	cancel          context.CancelCauseFunc
	done            chan struct{}
	answers         chan string
	commands        chan *agentv1.AssistanceCommand
	authority       *time.Timer
	authorizedUntil time.Time

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
}

// sessionResources are released by cleanup in a fixed order.
type sessionResources struct {
	prompt      Notice
	grant       Grant
	peer        Peer
	capture     Capture
	forwardDone chan struct{}
	inputDone   chan struct{}
	// indicatorMu guards indicator between serve and operator messages.
	indicatorMu   sync.Mutex
	indicator     Notice
	markup        bool
	input         *inputControl
	captureCancel context.CancelFunc
	captureDone   chan error
	timeline      rtpTimeline
	commandDone   chan struct{}
	message       Notice
	messageUntil  time.Time
	lastMessage   time.Time
}

func startSession(parent context.Context, deps *sessionDeps, directive *agentv1.AssistanceDirective, group *sync.WaitGroup) *session {
	invitation := directive.GetInvitation()
	ctx, cancel := context.WithCancelCause(parent)
	s := &session{
		deps:           deps,
		invitation:     invitation,
		logger:         deps.logger.With("session_id", invitation.GetSessionId()),
		cancel:         cancel,
		done:           make(chan struct{}),
		answers:        make(chan string, 1),
		commands:       make(chan *agentv1.AssistanceCommand, 1),
		commandHistory: make(map[string][32]byte),
	}
	s.renewAuthority(directive)
	runCtx, release := context.WithDeadlineCause(ctx, invitation.GetEndsAt().AsTime(), errExpired)
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
	resources := &sessionResources{}
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
	// Never ask for consent the desktop cannot honour: a missing ScreenCast
	// (or, for CONTROL, RemoteDesktop) portal ends the session before the prompt.
	policy := consentedPolicy(s.invitation)
	request := PortalRequest{Mode: s.invitation.GetMode(), Policy: policy, Lifetime: ctx}
	if err := deps.portal.Check(consentCtx, request); err != nil {
		return s.failure(consentCtx, unavailable("portal_unavailable", err))
	}
	// A server that advertises actions but never shows them would present a
	// prompt without visible Allow/Decline, where activating it allows.
	server, err := deps.notifier.ServerName(consentCtx)
	if err != nil {
		return s.failure(consentCtx, unavailable("notification_server_unavailable", err))
	}
	if platform.NotificationActionsHidden(server) {
		return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "notification_actions_hidden"
	}
	// A desktop whose locks lindm cannot observe would keep sharing a locked
	// screen; such a session is refused before consent rather than started
	// with a lock guarantee that does not hold.
	if deps.lockReporting != nil {
		return s.failure(consentCtx, deps.lockReporting)
	}
	r.markup = slices.Contains(capabilities, "body-markup")
	s.logIfErr("withdraw previous end notice", deps.replaceEndedNotice(consentCtx, nil))
	prompt, err := deps.notifier.Notify(consentCtx, s.promptNotification(r.markup))
	if err != nil {
		return s.failure(consentCtx, unavailable("notification_failed", err))
	}
	r.prompt = prompt
	s.advance(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	s.logger.Info("remote assistance prompt shown", "mode", s.invitation.GetMode().String())
	select {
	case action := <-prompt.Result():
		r.prompt = nil
		switch action {
		case actionAllow:
		case "":
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "prompt_dismissed"
		default:
			return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, "prompt_declined"
		}
	case <-consentCtx.Done():
		return s.failure(consentCtx, consentCtx.Err())
	}

	grant, err := deps.portal.Open(consentCtx, request)
	if err != nil {
		return s.failure(consentCtx, err)
	}
	r.grant = grant
	control := s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL && grant.ControlGranted()
	streams := grant.Streams()
	if len(streams) == 0 || len(streams) > 8 {
		return s.failure(consentCtx, unavailable("portal_stream_missing", nil))
	}
	s.mu.Lock()
	s.granted = grantedCapabilities(policy, grant)
	s.selected, s.generation = streams[0].ID, 1
	for _, stream := range streams {
		s.displays = append(s.displays, &agentv1.AssistanceDisplay{Id: stream.ID, Label: stream.Label, Width: uint32(stream.Width), Height: uint32(stream.Height)})
	}
	s.mu.Unlock()
	r.input = newInputControl(grant, s.granted.GetPolicy().GetKeyboard(), streams[0].ID)
	peer, err := deps.peers.NewPeer(PeerConfig{ICEServers: s.invitation.GetIceServers(), Input: control})
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
	cancelConsent()
	s.offered(offer, control)
	s.logger.Info("remote assistance offered", "control_granted", control)
	if control {
		r.inputDone = make(chan struct{})
		go s.forwardInput(ctx, r.input, peer.Input(), r.inputDone)
	}
	r.commandDone = make(chan struct{})
	go s.commandLoop(ctx, r)
	return s.serve(ctx, r, r.captureDone)
}

// serve runs the OFFERED/ACTIVE phase.
func (s *session) serve(ctx context.Context, r *sessionResources, captureDone <-chan error) (agentv1.AssistanceEndCause, string) {
	indicator, err := s.deps.notifier.Notify(ctx, s.indicatorNotification(r.markup))
	if err != nil {
		return s.failure(ctx, unavailable("indicator_failed", err))
	}
	r.setIndicator(indicator)
	lastPost := s.deps.clock()
	indicatorResult := indicator.Result()
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
			r.setIndicator(nil)
			repost = time.NewTimer(max(0, lastPost.Add(s.deps.repostInterval).Sub(s.deps.clock())))
			repostC = repost.C
		case <-repostC:
			repostC, repost = nil, nil
			indicator, err := s.deps.notifier.Notify(ctx, s.indicatorNotification(r.markup))
			if err != nil {
				return s.failure(ctx, unavailable("indicator_failed", err))
			}
			r.setIndicator(indicator)
			indicatorResult, lastPost = indicator.Result(), s.deps.clock()
		}
	}
}

func (r *sessionResources) setIndicator(indicator Notice) {
	r.indicatorMu.Lock()
	r.indicator = indicator
	r.indicatorMu.Unlock()
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
	s.mu.Lock()
	if s.command != nil {
		s.command.Text = ""
	}
	for len(s.commands) > 0 {
		<-s.commands
	}
	s.mu.Unlock()
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
	if r.indicator != nil {
		s.logIfErr("close indicator", r.indicator.Close(ctx))
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

func (s *session) promptNotification(markup bool) Notification {
	operator, reason := s.invitation.GetOperatorDisplay(), s.invitation.GetReason()
	if markup {
		operator, reason = html.EscapeString(operator), html.EscapeString(reason)
	}
	var body strings.Builder
	if s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		if policyEnabled(consentedPolicy(s.invitation).GetKeyboard()) {
			fmt.Fprintf(&body, "%s asks to view your screen and control your keyboard and pointer.\n", operator)
		} else {
			fmt.Fprintf(&body, "%s asks to view your screen and control your pointer. Keyboard control is not requested.\n", operator)
		}
	} else {
		fmt.Fprintf(&body, "%s asks to view your screen.\n", operator)
	}
	fmt.Fprintf(&body, "Reason: %s\n", reason)
	if s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		body.WriteString("Control is requested. The system dialog that follows lets you allow viewing only.")
	} else {
		body.WriteString("Control is not requested. The system dialog that follows selects what is shared.")
	}
	body.WriteString(capabilityConsentText(consentedPolicy(s.invitation)))
	return Notification{
		Summary:    "Remote assistance request",
		Body:       body.String(),
		Actions:    []NotificationAction{{Key: actionAllow, Label: "Allow"}, {Key: actionDecline, Label: "Decline"}},
		Critical:   true,
		Persistent: true,
		Reshow:     true,
	}
}

func (s *session) indicatorNotification(markup bool) Notification {
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
	return Notification{
		Summary:    "Remote assistance in progress",
		Body:       fmt.Sprintf("%s is %s your screen.", operator, activity),
		Actions:    []NotificationAction{{Key: actionStop, Label: "Stop"}},
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
