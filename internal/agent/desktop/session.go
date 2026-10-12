package desktop

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

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
	notifier Notifier
	portal   Portal
	capturer Capturer
	peers    PeerFactory
	logger   *slog.Logger
	clock    func() time.Time
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
	deps       *sessionDeps
	invitation *agentv1.AssistanceInvitation
	logger     *slog.Logger
	cancel     context.CancelCauseFunc
	done       chan struct{}
	answers    chan string

	mu       sync.Mutex
	phase    agentv1.AssistancePhase
	offer    string
	control  bool
	cause    agentv1.AssistanceEndCause
	detail   string
	answered bool
	prompted bool
}

// sessionResources are released by cleanup in a fixed order.
type sessionResources struct {
	prompt      Notice
	grant       Grant
	peer        Peer
	capture     Capture
	forwardDone chan struct{}
	inputDone   chan struct{}
	indicator   Notice
	markup      bool
}

func startSession(parent context.Context, deps *sessionDeps, invitation *agentv1.AssistanceInvitation, group *sync.WaitGroup) *session {
	ctx, cancel := context.WithCancelCause(parent)
	s := &session{
		deps:       deps,
		invitation: invitation,
		logger:     deps.logger.With("session_id", invitation.GetSessionId()),
		cancel:     cancel,
		done:       make(chan struct{}),
		answers:    make(chan string, 1),
	}
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
		SessionId:      s.id(),
		Phase:          s.phase,
		ControlGranted: s.control,
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
	if err := deps.portal.Check(consentCtx, s.invitation.GetMode()); err != nil {
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

	grant, err := deps.portal.Open(consentCtx, s.invitation.GetMode())
	if err != nil {
		return s.failure(consentCtx, err)
	}
	r.grant = grant
	control := s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL && grant.ControlGranted()
	pipeWire, err := grant.OpenPipeWire(consentCtx)
	if err != nil {
		return s.failure(consentCtx, unavailable("pipewire_unavailable", err))
	}
	peer, err := deps.peers.NewPeer(PeerConfig{ICEServers: s.invitation.GetIceServers(), Input: control})
	if err != nil {
		_ = pipeWire.Close()
		return s.failure(consentCtx, unavailable("peer_setup_failed", err))
	}
	r.peer = peer
	capture, err := deps.capturer.Start(ctx, CaptureRequest{PipeWire: pipeWire, Stream: grant.Stream()})
	closeErr := pipeWire.Close()
	if err != nil {
		return s.failure(consentCtx, unavailable("capture_start_failed", err))
	}
	r.capture = capture
	if closeErr != nil {
		return s.failure(consentCtx, unavailable("pipewire_close_failed", closeErr))
	}
	firstPacket := make(chan struct{})
	captureDone := make(chan error, 1)
	r.forwardDone = make(chan struct{})
	go s.forwardMedia(capture, peer, firstPacket, captureDone, r.forwardDone)
	firstTimer := time.NewTimer(deps.firstPacketTimeout)
	select {
	case <-firstPacket:
		firstTimer.Stop()
	case err := <-captureDone:
		firstTimer.Stop()
		return s.failure(consentCtx, unavailable("capture_exited", err))
	case <-firstTimer.C:
		return agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_no_frames"
	case <-consentCtx.Done():
		firstTimer.Stop()
		return s.failure(consentCtx, consentCtx.Err())
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
		go s.forwardInput(ctx, grant, peer.Input(), r.inputDone)
	}
	return s.serve(ctx, r, captureDone)
}

// serve runs the OFFERED/ACTIVE phase.
func (s *session) serve(ctx context.Context, r *sessionResources, captureDone <-chan error) (agentv1.AssistanceEndCause, string) {
	indicator, err := s.deps.notifier.Notify(ctx, s.indicatorNotification(r.markup))
	if err != nil {
		return s.failure(ctx, unavailable("indicator_failed", err))
	}
	r.indicator = indicator
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
			r.indicator = nil
			repost = time.NewTimer(max(0, lastPost.Add(s.deps.repostInterval).Sub(s.deps.clock())))
			repostC = repost.C
		case <-repostC:
			repostC, repost = nil, nil
			indicator, err := s.deps.notifier.Notify(ctx, s.indicatorNotification(r.markup))
			if err != nil {
				return s.failure(ctx, unavailable("indicator_failed", err))
			}
			r.indicator, indicatorResult, lastPost = indicator, indicator.Result(), s.deps.clock()
		}
	}
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
func (s *session) forwardMedia(capture Capture, peer Peer, firstPacket chan<- struct{}, captureDone chan<- error, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, maxRTPPacket)
	first := true
	for {
		n, err := capture.ReadPacket(buf)
		if err != nil {
			captureDone <- err
			return
		}
		if first {
			first = false
			close(firstPacket)
		}
		if err := peer.WriteRTP(buf[:n]); err != nil {
			s.logger.Debug("remote assistance rtp write failed", "err", err)
		}
	}
}

// forwardInput injects rate-limited, validated operator input and releases
// every held key and button when the session ends.
func (s *session) forwardInput(ctx context.Context, grant Grant, messages <-chan []byte, done chan<- struct{}) {
	defer close(done)
	limiter := newInputLimiter(s.deps.clock())
	pressed := newPressedInput()
	var dropped, rejected int
	defer func() {
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.deps.callTimeout)
		defer cancel()
		for _, event := range pressed.releases() {
			if err := grant.Inject(release, event); err != nil {
				s.logger.Warn("remote assistance input release failed", "err", err)
			}
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
			if !limiter.allow(s.deps.clock()) {
				dropped++
				continue
			}
			event, err := parseInput(message)
			if err != nil {
				rejected++
				continue
			}
			pressed.observe(event)
			call, cancel := context.WithTimeout(ctx, s.deps.callTimeout)
			err = grant.Inject(call, event)
			cancel()
			if err != nil && ctx.Err() == nil {
				s.logger.Warn("remote assistance input injection failed", "err", err)
			}
		}
	}
}

// cleanup releases resources: media and data first, then held input, the
// portal session, the encoder and the notifications.
func (s *session) cleanup(r *sessionResources) {
	ctx, cancel := context.WithTimeout(context.Background(), s.deps.cleanupTimeout)
	defer cancel()
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
	s.mu.Lock()
	prompted, cause := s.prompted, s.cause
	s.mu.Unlock()
	if prompted && cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED {
		notice, err := s.deps.notifier.Notify(ctx, Notification{
			Summary:  "Remote assistance ended",
			Body:     "Remote assistance ended: " + causeText(cause),
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
		fmt.Fprintf(&body, "%s asks to view your screen and control your keyboard and pointer.\n", operator)
	} else {
		fmt.Fprintf(&body, "%s asks to view your screen.\n", operator)
	}
	fmt.Fprintf(&body, "Reason: %s\n", reason)
	if s.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		body.WriteString("Control is requested. The system dialog that follows lets you allow viewing only.")
	} else {
		body.WriteString("Control is not requested. The system dialog that follows selects what is shared.")
	}
	return Notification{
		Summary:    "Remote assistance request",
		Body:       body.String(),
		Actions:    []NotificationAction{{Key: actionAllow, Label: "Allow"}, {Key: actionDecline, Label: "Decline"}},
		Critical:   true,
		Persistent: true,
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
		Body:       fmt.Sprintf("Remote assistance in progress — %s is %s your screen.", operator, activity),
		Actions:    []NotificationAction{{Key: actionStop, Label: "Stop"}},
		Critical:   true,
		Persistent: true,
	}
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
