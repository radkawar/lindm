//go:build linux

package executor

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/protodata"
)

const (
	assistanceMaxSessions     = 8
	assistanceMaxTombstones   = 32
	assistanceHelperDirective = 4
	// Without a fresh server directive for this long, a session is unauthorized.
	assistanceReauthorization = 30 * time.Second
	// A bound helper that has not reported a PROMPTED+ session for this long is gone.
	assistanceHelperAbsence = 10 * time.Second
	// A helper-reported portal closure is held this long before it becomes
	// final. Desktops close sharing sessions themselves when the screen locks
	// (GNOME 46 does so before logind LockedHint is set), so the lock must be
	// observed first to record SESSION_LOCKED rather than PORTAL_CLOSED.
	assistancePortalCloseSettle = 5 * time.Second
)

var (
	errNoGraphicalSession        = errors.New("no_graphical_session")
	errAmbiguousGraphicalSession = errors.New("ambiguous_graphical_session")
	errLogindUnavailable         = errors.New("logind_unavailable")
)

// logindLookup reads the logind sessions selected by match from a trusted
// source. Production uses actionprovider.ReadLogindSessions.
type logindLookup func(ctx context.Context, match func(id string, uid uint32) bool) ([]actionprovider.LogindSession, error)

// assistanceBroker is the executor's in-memory remote-assistance authority. It
// is deliberately not journaled: an executor restart forgets every session and
// the server and helper fail closed through their reauthorization windows. It
// never trusts a helper for identity; local sessions come from SO_PEERCRED and
// logind only.
type assistanceBroker struct {
	mu         sync.Mutex
	enabled    bool
	ceiling    *agentv1.AssistancePolicy
	clock      func() time.Time
	lookup     logindLookup
	validator  protovalidate.Validator
	sessions   map[string]*assistanceSession
	tombstones map[string]assistanceTombstone
	// Every network sync carrying assistance invalidates employee reboot prompts.
	rebootEpoch uint64
}

type assistanceSession struct {
	invitation        *agentv1.AssistanceInvitation
	answerSDP         string
	created           time.Time
	lastDirective     time.Time
	lastHelper        time.Time
	authorizedUntil   time.Time
	command           *agentv1.AssistanceCommand
	commandResult     *agentv1.AssistanceCommandResult
	granted           *agentv1.AssistanceCapabilities
	displays          []*agentv1.AssistanceDisplay
	selectedDisplayID string
	displayGeneration uint32
	displayFrame      *agentv1.AssistanceDisplayFrame
	capabilitiesSet   bool
	commandDeadline   time.Time
	commandTimer      *time.Timer
	commandDigests    map[string][32]byte
	phase             agentv1.AssistancePhase
	offerSDP          string
	controlGranted    bool
	endCause          agentv1.AssistanceEndCause
	endDetail         string
	local             *agentv1.AssistanceLocalSession
	// helperEnded records that the bound helper itself reported ENDED, so a
	// terminate directive no longer needs to reach it.
	helperEnded bool
	// portalClosed holds a helper-reported PORTAL_CLOSED until
	// assistancePortalCloseSettle elapses or a lock/logout supersedes it.
	portalClosed       time.Time
	portalClosedDetail string
}

// assistanceTombstone keeps the outcome of a forgotten session so a late
// directive for it is reported ENDED again instead of re-prompting the user.
type assistanceTombstone struct {
	cause  agentv1.AssistanceEndCause
	detail string
	local  *agentv1.AssistanceLocalSession
	until  time.Time
}

// assistanceRules compiles the assistance schemas once per process; see
// requestRules.
var assistanceRules = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&agentv1.SyncAssistanceRequest{}, &agentv1.SyncSessionRequest{}, &agentv1.AssistanceLocalSession{},
		&agentv1.SyncAssistanceResponse{}, &agentv1.SyncSessionResponse{},
	), protovalidate.WithDisableLazy())
})

func newAssistanceBroker(enabled bool, ceiling *agentv1.AssistancePolicy, clock func() time.Time, lookup logindLookup) (*assistanceBroker, error) {
	if clock == nil || lookup == nil {
		return nil, errors.New("executor: assistance broker requires a clock and logind lookup")
	}
	validator, err := assistanceRules()
	if err != nil {
		return nil, err
	}
	return &assistanceBroker{
		enabled:    enabled,
		ceiling:    proto.CloneOf(ceiling),
		clock:      clock,
		lookup:     lookup,
		validator:  validator,
		sessions:   make(map[string]*assistanceSession),
		tombstones: make(map[string]assistanceTombstone),
	}, nil
}

func (b *assistanceBroker) admit(msg proto.Message) error {
	if msg == nil || !msg.ProtoReflect().IsValid() || proto.Size(msg) > 256<<10 {
		return errInvalid
	}
	if err := protodata.ValidateClosed(msg.ProtoReflect()); err != nil || b.validator.Validate(msg) != nil {
		return errInvalid
	}
	return nil
}

// syncNetwork applies the server's complete directives and returns the
// device-observed state of every known session.
func (b *assistanceBroker) syncNetwork(ctx context.Context, req *agentv1.SyncAssistanceRequest) (*agentv1.SyncAssistanceResponse, error) {
	if err := b.admit(req); err != nil {
		return nil, err
	}
	present := make(map[string]*agentv1.AssistanceDirective, len(req.GetDirectives()))
	for _, directive := range req.GetDirectives() {
		id := directive.GetInvitation().GetSessionId()
		if _, duplicate := present[id]; duplicate {
			return nil, errInvalid
		}
		present[id] = directive
	}
	b.mu.Lock()
	if len(req.GetDirectives()) != 0 {
		b.rebootEpoch++
	}
	now := b.clock()
	// A fresh snapshot cannot revive a portal grant across an authority gap.
	b.expire(now)
	b.applyDirectives(now, req.GetDirectives(), present)
	b.expire(now)
	bound := make(map[string]struct{})
	for _, session := range b.sessions {
		if session.local != nil && session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			bound[session.local.GetLogindSessionId()] = struct{}{}
		}
	}
	b.mu.Unlock()
	if len(bound) != 0 {
		// Re-check every bound session on every network sync, outside the
		// broker lock: a slow bus never blocks helpers' liveness bookkeeping.
		found, err := b.lookup(ctx, func(id string, _ uint32) bool {
			_, ok := bound[id]
			return ok
		})
		b.mu.Lock()
		for _, session := range b.sessions {
			// Sessions bound after the snapshot were not looked up; the next sync checks them.
			if _, checked := bound[session.local.GetLogindSessionId()]; checked && session.local != nil {
				b.verify(session, found, err)
			}
		}
		b.mu.Unlock()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expire(b.clock())
	policy := agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_DISABLED
	if b.enabled {
		policy = agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_ENABLED
	}
	response := &agentv1.SyncAssistanceResponse{Reports: b.reports(), Policy: policy}
	if err := b.admit(response); err != nil {
		return nil, err
	}
	return response, nil
}

// syncSession binds the SO_PEERCRED uid to its single eligible logind session,
// applies that helper's observations and returns the directives addressed to it.
func (b *assistanceBroker) syncSession(ctx context.Context, uid uint32, req *agentv1.SyncSessionRequest) (*agentv1.SyncSessionResponse, error) {
	if uid == 0 {
		return nil, errNoGraphicalSession
	}
	if err := b.admit(req); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(req.GetReports()))
	for _, report := range req.GetReports() {
		if _, duplicate := seen[report.GetSessionId()]; duplicate {
			return nil, errInvalid
		}
		seen[report.GetSessionId()] = struct{}{}
	}
	found, lookupErr := b.lookup(ctx, func(_ string, owner uint32) bool { return owner == uid })
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.expire(now)
	for _, session := range b.sessions {
		if session.local != nil && session.local.GetUid() == uid {
			b.verify(session, found, lookupErr)
		}
	}
	if lookupErr != nil {
		slog.Warn("remote assistance logind lookup failed", "uid", uid, "error", lookupErr)
		return nil, errLogindUnavailable
	}
	local, err := b.eligible(uid, found)
	if err != nil {
		return nil, err
	}
	for _, report := range req.GetReports() {
		b.applyReport(now, local, report)
	}
	b.expire(now)
	response := &agentv1.SyncSessionResponse{Directives: b.helperDirectives(local), LocalSession: proto.CloneOf(local)}
	if err := b.admit(response); err != nil {
		return nil, err
	}
	return response, nil
}

// eligible requires exactly one local, active, unlocked user graphical session.
func (b *assistanceBroker) eligible(uid uint32, found []actionprovider.LogindSession) (*agentv1.AssistanceLocalSession, error) {
	var match *actionprovider.LogindSession
	for i := range found {
		session := &found[i]
		if session.UID != uid || !graphicalKind(session) || !session.Active || session.Locked {
			continue
		}
		if match != nil {
			return nil, errAmbiguousGraphicalSession
		}
		match = session
	}
	if match == nil {
		return nil, errNoGraphicalSession
	}
	local := &agentv1.AssistanceLocalSession{Username: match.User, Uid: match.UID, LogindSessionId: match.ID, SessionType: match.Type, Desktop: match.Desktop}
	if b.validator.Validate(local) != nil {
		// Desktop is display-only; never let it make an otherwise valid session ineligible.
		local.Desktop = ""
		if b.validator.Validate(local) != nil {
			return nil, errNoGraphicalSession
		}
	}
	return local, nil
}

func graphicalKind(session *actionprovider.LogindSession) bool {
	return session.Class == "user" && (session.Type == "wayland" || session.Type == "x11") && !session.Remote
}

// verify ends a bound, non-ended session whose logind session is no longer
// the same local, active, unlocked graphical session.
func (b *assistanceBroker) verify(session *assistanceSession, found []actionprovider.LogindSession, lookupErr error) {
	if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return
	}
	if lookupErr != nil {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "logind_unavailable")
		return
	}
	index := slices.IndexFunc(found, func(candidate actionprovider.LogindSession) bool {
		return candidate.ID == session.local.GetLogindSessionId()
	})
	switch {
	case index < 0:
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "logind_session_gone")
	case found[index].UID != session.local.GetUid() || found[index].User != session.local.GetUsername() || !graphicalKind(&found[index]):
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "logind_session_changed")
	case !found[index].Active:
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "logind_session_inactive")
	case found[index].Locked:
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED, "")
	}
}

func (b *assistanceBroker) applyDirectives(now time.Time, directives []*agentv1.AssistanceDirective, present map[string]*agentv1.AssistanceDirective) {
	// An ENDED session absent from directives has been confirmed or abandoned
	// by the server; forget it before admitting new invitations.
	for id, session := range b.sessions {
		if _, ok := present[id]; !ok && session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			b.forget(now, id, session)
		}
	}
	for _, directive := range directives {
		id := directive.GetInvitation().GetSessionId()
		session := b.sessions[id]
		if session == nil {
			session = b.admitInvitation(now, directive)
			if session == nil {
				continue
			}
		}
		session.lastDirective = now
		session.authorizedUntil = directive.GetAuthorizedUntil().AsTime()
		if !directive.GetTerminate() && (!now.Before(session.authorizedUntil) || session.authorizedUntil.After(now.Add(assistanceReauthorization))) {
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "operator_authorization_expired")
		}
		b.applyCommand(now, session, directive.GetCommand())
		// The invitation is immutable once seen; only the answer and
		// termination may arrive later. The answer is single use.
		if session.answerSDP == "" && directive.GetAnswerSdp() != "" {
			session.answerSDP = directive.GetAnswerSdp()
		}
		if directive.GetTerminate() {
			cause := directive.GetTerminateCause()
			if cause == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNSPECIFIED {
				cause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED
			}
			b.end(session, cause, "")
		}
	}
}

func (b *assistanceBroker) admitInvitation(now time.Time, directive *agentv1.AssistanceDirective) *assistanceSession {
	id := directive.GetInvitation().GetSessionId()
	if len(b.sessions) >= assistanceMaxSessions {
		oldest := ""
		for candidate, session := range b.sessions {
			if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED && (oldest == "" || session.created.Before(b.sessions[oldest].created)) {
				oldest = candidate
			}
		}
		if oldest == "" {
			slog.Warn("remote assistance capacity reached; invitation not admitted", "session_id", id)
			return nil
		}
		b.forget(now, oldest, b.sessions[oldest])
	}
	session := &assistanceSession{
		invitation: proto.CloneOf(directive.GetInvitation()),
		created:    now,
		phase:      agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING,
	}
	b.sessions[id] = session
	if tombstone, ok := b.tombstones[id]; ok {
		delete(b.tombstones, id)
		session.phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED
		session.endCause, session.endDetail, session.local = tombstone.cause, tombstone.detail, tombstone.local
		session.helperEnded = true
		return session
	}
	if !b.enabled {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DISABLED, "")
	}
	return session
}

func (b *assistanceBroker) forget(now time.Time, id string, session *assistanceSession) {
	delete(b.sessions, id)
	for candidate, tombstone := range b.tombstones {
		if !now.Before(tombstone.until) {
			delete(b.tombstones, candidate)
		}
	}
	until := session.invitation.GetEndsAt().AsTime()
	if !now.Before(until) {
		return
	}
	if len(b.tombstones) >= assistanceMaxTombstones {
		oldest := ""
		for candidate, tombstone := range b.tombstones {
			if oldest == "" || tombstone.until.Before(b.tombstones[oldest].until) {
				oldest = candidate
			}
		}
		delete(b.tombstones, oldest)
	}
	b.tombstones[id] = assistanceTombstone{cause: session.endCause, detail: session.endDetail, local: session.local, until: until}
}

// expire applies every executor-owned deadline with the executor's clock.
func (b *assistanceBroker) expire(now time.Time) {
	for _, session := range b.sessions {
		expireAssistanceCommand(session, now)
		if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			continue
		}
		switch {
		case !session.portalClosed.IsZero() && now.Sub(session.portalClosed) >= assistancePortalCloseSettle:
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED, session.portalClosedDetail)
		case !now.Before(session.invitation.GetEndsAt().AsTime()):
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED, "")
		case session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING && !now.Before(session.invitation.GetConsentDeadline().AsTime()):
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION, "")
		case session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED && !now.Before(session.invitation.GetConsentDeadline().AsTime()):
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT, "")
		case now.Sub(session.lastDirective) >= assistanceReauthorization || !now.Before(session.authorizedUntil):
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "")
		case session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING && now.Sub(session.lastHelper) >= assistanceHelperAbsence:
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "helper_absent")
		}
	}
}

func (b *assistanceBroker) end(session *assistanceSession, cause agentv1.AssistanceEndCause, detail string) {
	if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		return
	}
	session.phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED
	session.endCause, session.endDetail = cause, detail
	session.command, session.commandResult = nil, nil
	session.displayFrame = nil
	if session.commandTimer != nil {
		session.commandTimer.Stop()
	}
	slog.Info("remote assistance session ended", "session_id", session.invitation.GetSessionId(), "cause", cause.String(), "detail", detail)
}

func (b *assistanceBroker) applyReport(now time.Time, local *agentv1.AssistanceLocalSession, report *agentv1.SessionAssistanceReport) {
	session := b.sessions[report.GetSessionId()]
	if session == nil {
		return
	}
	if session.local == nil {
		// Only an eligible caller may claim a PENDING invitation; claiming binds it.
		if session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING || !targets(session.invitation, local) {
			return
		}
		session.local = proto.CloneOf(local)
		if phase := report.GetPhase(); phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED || phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
			// A helper already past consent for an invitation this executor
			// never delivered (for example after an executor restart) is not
			// re-adopted: capture ends and the helper receives terminate.
			session.lastHelper = now
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "executor_state_lost")
			return
		}
	} else if !sameLocalSession(session.local, local) {
		return
	}
	if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		session.helperEnded = session.helperEnded || report.GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED
		return
	}
	session.lastHelper = now
	phase := report.GetPhase()
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
		session.helperEnded = true
		if report.GetEndCause() == agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED {
			// Capture already stopped on the helper; only the recorded cause
			// waits for a possible lock or logout observation.
			if session.portalClosed.IsZero() {
				session.portalClosed, session.portalClosedDetail = now, report.GetEndDetail()
			}
			return
		}
		b.end(session, report.GetEndCause(), report.GetEndDetail())
		return
	}
	if phase < session.phase {
		// The helper lost state (for example it restarted); its new consent
		// or offer is not the one the server bound.
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "helper_state_lost")
		return
	}
	if session.phase >= agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED && report.GetOfferSdp() != session.offerSDP {
		b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED, "offer_changed")
		return
	}
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE && session.answerSDP == "" {
		// No connection can exist before the authorized answer was delivered.
		phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED
	}
	if phase >= agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED {
		if !b.applyCapabilities(session, report) {
			b.end(session, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, "capability_report_invalid")
			return
		}
		b.applyCommandResult(now, session, report.GetCommandResult())
		if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			return
		}
	}
	if phase <= session.phase {
		return
	}
	if session.phase < agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED && phase >= agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED {
		session.offerSDP = report.GetOfferSdp()
		session.controlGranted = report.GetControlGranted() && session.invitation.GetMode() == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	}
	session.phase = phase
}

func targets(invitation *agentv1.AssistanceInvitation, local *agentv1.AssistanceLocalSession) bool {
	return invitation.GetTargetUsername() == "" || invitation.GetTargetUsername() == local.GetUsername()
}

func sameLocalSession(a, b *agentv1.AssistanceLocalSession) bool {
	return a.GetUid() == b.GetUid() && a.GetLogindSessionId() == b.GetLogindSessionId() && a.GetUsername() == b.GetUsername()
}

func (b *assistanceBroker) ordered() []*assistanceSession {
	sessions := make([]*assistanceSession, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, session)
	}
	slices.SortFunc(sessions, func(x, y *assistanceSession) int {
		if order := x.created.Compare(y.created); order != 0 {
			return order
		}
		return cmp.Compare(x.invitation.GetSessionId(), y.invitation.GetSessionId())
	})
	return sessions
}

func (b *assistanceBroker) helperDirectives(local *agentv1.AssistanceLocalSession) []*agentv1.AssistanceDirective {
	var out []*agentv1.AssistanceDirective
	for _, session := range b.ordered() {
		if len(out) == assistanceHelperDirective {
			break
		}
		switch {
		case session.local == nil:
			if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING && targets(session.invitation, local) {
				out = append(out, b.helperDirective(session))
			}
		case !sameLocalSession(session.local, local):
		case session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED:
			if !session.helperEnded {
				out = append(out, &agentv1.AssistanceDirective{Invitation: proto.CloneOf(session.invitation), Terminate: true, TerminateCause: session.endCause})
			}
		default:
			out = append(out, b.helperDirective(session))
		}
	}
	return out
}

func (b *assistanceBroker) reports() []*agentv1.AssistanceReport {
	var out []*agentv1.AssistanceReport
	for _, session := range b.ordered() {
		report := &agentv1.AssistanceReport{
			SessionId:             session.invitation.GetSessionId(),
			Phase:                 session.phase,
			ControlGranted:        session.controlGranted,
			EndCause:              session.endCause,
			EndDetail:             session.endDetail,
			LocalSession:          proto.CloneOf(session.local),
			GrantedCapabilities:   proto.CloneOf(session.granted),
			Displays:              cloneAssistanceDisplays(session.displays),
			SelectedDisplayId:     session.selectedDisplayID,
			DisplayGeneration:     session.displayGeneration,
			DisplayFrame:          proto.CloneOf(session.displayFrame),
			CommandResult:         proto.CloneOf(session.commandResult),
			RequestedCapabilities: proto.CloneOf(session.invitation.GetRequestedCapabilities()),
			EffectiveCapabilities: assistancePolicyIntersection(session.invitation.GetEffectiveCapabilities(), b.ceiling),
		}
		if session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED || session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
			report.OfferSdp = session.offerSDP
		}
		out = append(out, report)
	}
	return out
}

func expireAssistanceCommand(session *assistanceSession, now time.Time) {
	if session.commandResult != nil && !now.Before(session.commandDeadline) {
		session.commandResult.Text = ""
		if session.commandResult.GetKind() == agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ && session.commandResult.GetStatus() == agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
			session.commandResult.Status = agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED
			session.commandResult.Reason = "content_expired"
		}
	}
	if session.command != nil && !now.Before(session.command.GetDeadline().AsTime()) {
		if session.commandResult == nil {
			session.commandResult = &agentv1.AssistanceCommandResult{RequestId: session.command.GetRequestId(), Kind: session.command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED, Reason: "command_expired", CompletedAt: timestamppb.New(now)}
		}
		session.command = nil
		session.commandResult.Text = ""
	}
}
