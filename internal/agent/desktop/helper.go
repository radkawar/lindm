package desktop

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

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
	Logger   *slog.Logger
}

// Helper is the session helper's executor sync loop and session registry.
// Run owns all mutable state; sessions run in their own bounded goroutines.
type Helper struct {
	client agentv1connect.SessionServiceClient
	deps   *sessionDeps
	logger *slog.Logger
	uid    uint32

	idleInterval   time.Duration
	activeInterval time.Duration
	lossTimeout    time.Duration

	sessions    map[string]*session
	tombstones  map[string]*session
	tombOrder   []string
	lastSuccess time.Time
	failing     bool
	boundLocal  string
	group       sync.WaitGroup
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
	if config.Client == nil || config.Notifier == nil || config.Portal == nil || config.Capturer == nil || config.Peers == nil || config.Logger == nil {
		return nil, errors.New("desktop: missing helper dependency")
	}
	return &Helper{
		client: config.Client,
		deps: &sessionDeps{
			notifier:           config.Notifier,
			portal:             config.Portal,
			capturer:           config.Capturer,
			peers:              config.Peers,
			logger:             config.Logger,
			clock:              time.Now,
			firstPacketTimeout: 10 * time.Second,
			captureGrace:       time.Second,
			repostInterval:     2 * time.Second,
			callTimeout:        2 * time.Second,
			cleanupTimeout:     5 * time.Second,
		},
		logger:         config.Logger,
		uid:            uid,
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
	h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "helper_stopped")
	h.group.Wait()
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
	call, cancel := context.WithTimeout(ctx, syncCallTimeout)
	response, err := h.client.SyncSession(call, connect.NewRequest(&agentv1.SyncSessionRequest{Reports: h.reports()}))
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
	h.apply(sessionParent, response.Msg)
}

// syncFailed applies the loss rules: an authoritative refusal stops every
// session immediately; transport failures stop them after lossTimeout.
func (h *Helper) syncFailed(now time.Time, err error) {
	if !h.failing {
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

// apply reconciles sessions with the executor's complete directive set.
func (h *Helper) apply(parent context.Context, response *agentv1.SyncSessionResponse) {
	local := response.GetLocalSession()
	if local.GetUid() != h.uid {
		h.logger.Error("executor bound a different uid; refusing directives", "uid", local.GetUid())
		h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_mismatch")
		return
	}
	if h.boundLocal != "" && h.boundLocal != local.GetLogindSessionId() {
		h.endAll(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "local_session_changed")
	}
	h.boundLocal = local.GetLogindSessionId()

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
	h.logger.Info("remote assistance invitation received", "session_id", id, "mode", invitation.GetMode().String())
	h.sessions[id] = startSession(parent, h.deps, invitation, &h.group)
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
