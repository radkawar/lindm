// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/internal/rpcreason"
)

// Executor sync contract.
const (
	idleSyncInterval    = 2 * time.Second
	activeSyncInterval  = 1 * time.Second
	executorLossTimeout = 30 * time.Second
	syncCallTimeout     = 5 * time.Second
	finalSyncTimeout    = 2 * time.Second
	maxSessions         = 4
	maxTombstones       = 32
)

// Config holds the helper's collaborators.
type Config struct {
	Client   agentv1connect.SessionServiceClient
	Notifier Notifier
	Portal   Portal
	Capturer Capturer
	Peers    PeerFactory
	Locks    LockMonitor
	// CurrentDesktop is the session's XDG_CURRENT_DESKTOP.
	CurrentDesktop string
	Logger         *slog.Logger
	// FilesUnavailableReason is the production composition's exact-release gate.
	FilesUnavailableReason string
	// RecordingUnavailableReason and ReconnectUnavailableReason are the
	// exact-release gates for recording and reconnect workflows.
	RecordingUnavailableReason string
	ReconnectUnavailableReason string
	// Tier 3 collaborators are optional: a nil one withholds its capability
	// with an exact reason. Each has the composition's exact-release gate.
	Overlay                     Overlay
	Audio                       AudioDevices
	Enrollments                 EnrollmentStore
	UnattendedUnavailableReason string
	ElevationUnavailableReason  string
	AnnotationUnavailableReason string
	AudioUnavailableReason      string
}

// Helper is the session helper's executor sync loop and session registry.
// Run owns all mutable state; sessions run in their own bounded goroutines.
type Helper struct {
	client agentv1connect.SessionServiceClient
	deps   *sessionDeps
	logger *slog.Logger
	locks  LockMonitor
	// lockWatch observes lock requests of lockSession, the bound logind
	// session. Without it no new session starts.
	lockWatch   LockSubscription
	lockSession string
	uid         uint32

	idleInterval   time.Duration
	activeInterval time.Duration
	lossTimeout    time.Duration

	sessions    map[string]*session
	tombstones  map[string]*session
	tombOrder   []string
	lastSuccess time.Time
	failing     bool
	boundLocal  string
	// sessionType is the bound logind session's type as the executor
	// observed it; it selects X11 or Wayland desktop qualification.
	sessionType   string
	group         sync.WaitGroup
	reboot        *agentv1.OSUpdateRebootNotice
	rebootNotice  Notice
	rebootRequest *agentv1.OSUpdateRebootDeferralRequest
}

// New validates the collaborators. It refuses to construct a helper for
// effective UID 0: the helper never holds privileged authority.
func New(config Config) (*Helper, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("desktop: session helper refuses to run as root")
	}
	return newHelper(config, uint32(os.Getuid()))
}

func newHelper(config Config, uid uint32) (*Helper, error) {
	if config.Client == nil || config.Notifier == nil || config.Portal == nil || config.Capturer == nil || config.Peers == nil || config.Locks == nil || config.Logger == nil {
		return nil, errors.New("desktop: missing helper dependency")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.AssistanceCommand{}, &agentv1.AssistanceFileDirective{}, &agentv1.AssistanceFileFrame{}, &agentv1.AssistanceRecordingAuthority{}), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	return &Helper{
		client: config.Client,
		deps: &sessionDeps{
			notifier:                    config.Notifier,
			portal:                      config.Portal,
			capturer:                    config.Capturer,
			peers:                       config.Peers,
			logger:                      config.Logger,
			clock:                       time.Now,
			lockReporting:               lockReporting(config.CurrentDesktop),
			currentDesktop:              config.CurrentDesktop,
			validator:                   validator,
			filesUnavailableReason:      config.FilesUnavailableReason,
			recordings:                  config.Client,
			recordingUnavailableReason:  config.RecordingUnavailableReason,
			reconnectUnavailableReason:  config.ReconnectUnavailableReason,
			overlay:                     config.Overlay,
			annotationUnavailableReason: config.AnnotationUnavailableReason,
			audio:                       config.Audio,
			audioUnavailableReason:      config.AudioUnavailableReason,
			enrollments:                 config.Enrollments,
			unattendedUnavailableReason: config.UnattendedUnavailableReason,
			elevationUnavailableReason:  config.ElevationUnavailableReason,
			unattendedRestore:           unattendedRestoreLimit,
			firstPacketTimeout:          10 * time.Second,
			captureGrace:                time.Second,
			repostInterval:              2 * time.Second,
			callTimeout:                 2 * time.Second,
			cleanupTimeout:              5 * time.Second,
			// Unset, the recorder's flush ticker panicked the helper the
			// moment a recorded session started (layers-fedora44-tier2-05).
			recordingFlush: recorderFlushInterval,
		},
		logger:         config.Logger,
		uid:            uid,
		locks:          config.Locks,
		idleInterval:   idleSyncInterval,
		activeInterval: activeSyncInterval,
		lossTimeout:    executorLossTimeout,
		sessions:       map[string]*session{},
		tombstones:     map[string]*session{},
	}, nil
}

// Run polls the executor until ctx ends, then ends every session, waits
// for their cleanup and reports the final state once.
func (h *Helper) Run(ctx context.Context) error {
	base := context.WithoutCancel(ctx)
	h.lastSuccess = h.deps.clock()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			h.shutdown(base)
			return nil
		case <-timer.C:
		case detail, ok := <-h.lockEvents():
			// Report the lock at once rather than at the next interval.
			h.lockObserved(detail, ok)
		}
		h.syncOnce(ctx, base)
		timer.Reset(h.interval())
	}
}

func (h *Helper) interval() time.Duration {
	if len(h.sessions) > 0 {
		return h.activeInterval
	}
	return h.idleInterval
}

func (h *Helper) shutdown(base context.Context) {
	h.closeRebootNotice(base)
	h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "helper_stopped")
	h.group.Wait()
	h.closeLockWatch()
	if len(h.sessions) == 0 {
		return
	}
	call, cancel := context.WithTimeout(base, finalSyncTimeout)
	defer cancel()
	if _, err := h.client.SyncSession(call, connect.NewRequest(&agentv1.SyncSessionRequest{Reports: h.reports()})); err != nil {
		h.logger.Warn("final session sync failed", "err", err)
	}
}

// syncOnce exchanges reports for directives once. sessionParent is the
// parent of new session goroutines.
func (h *Helper) syncOnce(ctx, sessionParent context.Context) {
	h.drainLocks()
	h.rebootAction()
	call, cancel := context.WithTimeout(ctx, syncCallTimeout)
	response, err := h.client.SyncSession(call, connect.NewRequest(&agentv1.SyncSessionRequest{Reports: h.reports(), RebootDeferral: h.rebootRequest}))
	cancel()
	now := h.deps.clock()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		h.syncFailed(now, err)
		return
	}
	if h.failing {
		h.logger.Info("executor session sync recovered")
		h.failing = false
	}
	h.lastSuccess = now
	h.rebootRequest = nil
	h.apply(sessionParent, response.Msg)
}

// syncFailed applies the loss rules: an authoritative refusal stops every
// session immediately; transport failures stop them after lossTimeout.
func (h *Helper) syncFailed(now time.Time, err error) {
	h.closeRebootNotice(context.Background())
	if !h.failing {
		if h.rebootRequest != nil {
			h.rebootUncertain()
		}
		h.logger.Warn("executor session sync failed", "err", err)
		h.failing = true
	}
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied, connect.CodeUnauthenticated:
		reason := "session_refused"
		var connectErr *connect.Error
		if errors.As(err, &connectErr) {
			if value := rpcreason.Get(connectErr); value != "" {
				reason = value
			}
		}
		h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, reason)
	default:
		if now.Sub(h.lastSuccess) >= h.lossTimeout {
			h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "executor_unreachable")
		}
	}
}

func (h *Helper) endAll(cause agentv1.AssistanceEndCause, detail string) {
	for _, s := range h.sessions {
		s.end(cause, detail)
	}
}

// lockEvents is the bound session's lock channel, nil without a watch.
func (h *Helper) lockEvents() <-chan string {
	if h.lockWatch == nil {
		return nil
	}
	return h.lockWatch.Locked()
}

// lockObserved ends every session on a lock request; a lost watch ends them
// too, because a later lock could no longer be observed.
func (h *Helper) lockObserved(detail string, ok bool) {
	h.closeRebootNotice(context.Background())
	if !ok {
		h.logger.Warn("logind lock watch lost", "logind_session", h.lockSession)
		h.closeLockWatch()
		h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "lock_watch_lost")
		return
	}
	h.logger.Info("session lock observed", "logind_session", h.lockSession, "detail", detail)
	h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED, detail)
}

// drainLocks applies lock requests that arrived since the last sync.
func (h *Helper) drainLocks() {
	for h.lockWatch != nil {
		select {
		case detail, ok := <-h.lockWatch.Locked():
			h.lockObserved(detail, ok)
		default:
			return
		}
	}
}

// watchLocks keeps one lock watch on the bound logind session.
func (h *Helper) watchLocks(parent context.Context, sessionID string) {
	if h.lockWatch != nil && h.lockSession == sessionID {
		return
	}
	h.closeLockWatch()
	ctx, cancel := context.WithTimeout(parent, syncCallTimeout)
	defer cancel()
	watch, err := h.locks.Subscribe(ctx, sessionID)
	if err != nil {
		h.logger.Warn("logind lock watch unavailable", "logind_session", sessionID, "err", err)
		return
	}
	h.lockWatch, h.lockSession = watch, sessionID
}

func (h *Helper) closeLockWatch() {
	if h.lockWatch == nil {
		return
	}
	if err := h.lockWatch.Close(); err != nil {
		h.logger.Warn("close logind lock watch", "err", err)
	}
	h.lockWatch, h.lockSession = nil, ""
}

// apply reconciles sessions with the executor's complete directive set.
func (h *Helper) apply(parent context.Context, response *agentv1.SyncSessionResponse) {
	local := response.GetLocalSession()
	h.applyReboot(parent, response)
	if local.GetUid() != h.uid {
		h.logger.Error("executor bound a different uid; refusing directives", "uid", local.GetUid())
		h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_mismatch")
		return
	}
	if h.boundLocal != "" && h.boundLocal != local.GetLogindSessionId() {
		h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_changed")
	}
	h.boundLocal, h.sessionType = local.GetLogindSessionId(), local.GetSessionType()
	h.watchLocks(parent, h.boundLocal)

	present := make(map[string]struct{}, len(response.GetDirectives()))
	for _, directive := range response.GetDirectives() {
		invitation := directive.GetInvitation()
		id := invitation.GetSessionId()
		if id == "" {
			continue
		}
		present[id] = struct{}{}
		if s, ok := h.sessions[id]; ok {
			s.apply(directive)
			continue
		}
		if s, ok := h.tombstones[id]; ok {
			h.sessions[id] = s
			continue
		}
		h.admit(parent, directive)
	}
	for id, s := range h.sessions {
		if _, ok := present[id]; ok {
			continue
		}
		// Absent means no longer authorized for this caller.
		s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "directive_absent")
		delete(h.sessions, id)
		h.bury(s)
	}
}

func (h *Helper) admit(parent context.Context, directive *agentv1.AssistanceDirective) {
	invitation := directive.GetInvitation()
	id := invitation.GetSessionId()
	if directive.GetTerminate() {
		cause := directive.GetTerminateCause()
		if cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
			cause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
		}
		h.sessions[id] = endedSession(invitation, cause, "terminate_directive")
		return
	}
	if directive.GetCommand() != nil || directive.GetFileTransfer() != nil {
		h.sessions[id] = endedSession(invitation, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "unknown_command_session")
		return
	}
	if !h.deps.clock().Before(invitation.GetEndsAt().AsTime()) {
		h.sessions[id] = endedSession(invitation, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED, "ends_at_reached")
		return
	}
	live := 0
	for _, s := range h.sessions {
		if !s.ended() {
			live++
		}
	}
	if live >= maxSessions || len(h.sessions) >= maxSessions {
		h.logger.Warn("remote assistance invitation ignored: session limit", "session_id", id)
		return
	}
	if h.lockWatch == nil {
		// Without a lock watch a lock could go unobserved: never prompt.
		h.sessions[id] = endedSession(invitation, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "lock_watch_unavailable")
		return
	}
	h.logger.Info("remote assistance invitation received", "session_id", id, "mode", invitation.GetMode().String())
	h.sessions[id] = startSession(parent, h.deps, directive, h.sessionType, &h.group)
}

// bury remembers the final state of a forgotten session so a reappearing
// directive is answered with ENDED instead of a fresh prompt.
func (h *Helper) bury(s *session) {
	if _, ok := h.tombstones[s.id()]; ok {
		return
	}
	if len(h.tombOrder) == maxTombstones {
		delete(h.tombstones, h.tombOrder[0])
		h.tombOrder = h.tombOrder[1:]
	}
	h.tombstones[s.id()] = s
	h.tombOrder = append(h.tombOrder, s.id())
}

// reports returns the current observation of every held session in a
// stable order.
func (h *Helper) reports() []*agentv1.SessionAssistanceReport {
	ids := make([]string, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	reports := make([]*agentv1.SessionAssistanceReport, 0, len(ids))
	for _, id := range ids {
		if report, ok := h.sessions[id].report(); ok && len(reports) < maxSessions {
			reports = append(reports, report)
		}
	}
	return reports
}
