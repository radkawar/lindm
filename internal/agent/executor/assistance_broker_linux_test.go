//go:build linux

package executor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
)

const testOffer = "v=0\r\na=fingerprint:sha-256 AA\r\n"

type assistanceFixture struct {
	t      *testing.T
	mu     sync.Mutex
	now    time.Time
	logind []actionprovider.LogindSession
	broker *assistanceBroker
}

func newAssistanceFixture(t *testing.T, enabled bool) *assistanceFixture {
	t.Helper()
	f := &assistanceFixture{t: t, now: time.Date(2031, 9, 1, 12, 0, 0, 0, time.UTC)}
	f.logind = []actionprovider.LogindSession{
		{ID: "2", UID: 1000, User: "alice", Class: "user", Type: "wayland", Desktop: "GNOME", Active: true},
		{ID: "3", UID: 1001, User: "bob", Class: "user", Type: "x11", Active: true},
		{ID: "c1", UID: 1001, User: "bob", Class: "greeter", Type: "wayland", Active: false},
	}
	broker, err := newAssistanceBroker(enabled, f.clock, f.lookup)
	if err != nil {
		t.Fatal(err)
	}
	f.broker = broker
	return f
}

func (f *assistanceFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *assistanceFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *assistanceFixture) setLogind(id string, change func(*actionprovider.LogindSession)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.logind {
		if f.logind[i].ID == id {
			change(&f.logind[i])
		}
	}
}

func (f *assistanceFixture) lookup(_ context.Context, match func(string, uint32) bool) ([]actionprovider.LogindSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []actionprovider.LogindSession
	for _, session := range f.logind {
		if match(session.ID, session.UID) {
			out = append(out, session)
		}
	}
	return out, nil
}

func (f *assistanceFixture) invitation(mode agentv1.AssistanceMode, target string) *agentv1.AssistanceInvitation {
	now := f.clock()
	return &agentv1.AssistanceInvitation{
		SessionId:       uuid.NewString(),
		Mode:            mode,
		Reason:          "printer setup",
		OperatorDisplay: "Operator One",
		ConsentDeadline: timestamppb.New(now.Add(120 * time.Second)),
		EndsAt:          timestamppb.New(now.Add(30 * time.Minute)),
		TargetUsername:  target,
		IceServers:      []*agentv1.AssistanceIceServer{{Urls: []string{"turn:relay.example:3478?transport=udp"}, Username: "1:2:device", Credential: "secret"}},
	}
}

func (f *assistanceFixture) network(directives ...*agentv1.AssistanceDirective) map[string]*agentv1.AssistanceReport {
	f.t.Helper()
	response, err := f.broker.syncNetwork(f.t.Context(), &agentv1.SyncAssistanceRequest{Directives: directives})
	if err != nil {
		f.t.Fatalf("network sync: %v", err)
	}
	if err := protovalidate.Validate(response); err != nil {
		f.t.Fatalf("invalid network response: %v", err)
	}
	out := make(map[string]*agentv1.AssistanceReport, len(response.GetReports()))
	for _, report := range response.GetReports() {
		out[report.GetSessionId()] = report
	}
	return out
}

func (f *assistanceFixture) helper(uid uint32, reports ...*agentv1.SessionAssistanceReport) (*agentv1.SyncSessionResponse, error) {
	return f.broker.syncSession(f.t.Context(), uid, &agentv1.SyncSessionRequest{Reports: reports})
}

func (f *assistanceFixture) mustHelper(uid uint32, reports ...*agentv1.SessionAssistanceReport) map[string]*agentv1.AssistanceDirective {
	f.t.Helper()
	response, err := f.helper(uid, reports...)
	if err != nil {
		f.t.Fatalf("helper sync for uid %d: %v", uid, err)
	}
	if err := protovalidate.Validate(response); err != nil {
		f.t.Fatalf("invalid helper response: %v", err)
	}
	out := make(map[string]*agentv1.AssistanceDirective, len(response.GetDirectives()))
	for _, directive := range response.GetDirectives() {
		out[directive.GetInvitation().GetSessionId()] = directive
	}
	return out
}

func report(id string, phase agentv1.AssistancePhase) *agentv1.SessionAssistanceReport {
	r := &agentv1.SessionAssistanceReport{SessionId: id, Phase: phase}
	if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED || phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
		r.OfferSdp = testOffer
	}
	return r
}

func wantEnded(t *testing.T, got *agentv1.AssistanceReport, cause agentv1.AssistanceEndCause) {
	t.Helper()
	if got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED || got.GetEndCause() != cause {
		t.Fatalf("report = %v/%v (%q), want ENDED/%v", got.GetPhase(), got.GetEndCause(), got.GetEndDetail(), cause)
	}
}

// prompted drives one invitation to PROMPTED bound to alice's session.
func (f *assistanceFixture) prompted(mode agentv1.AssistanceMode) *agentv1.AssistanceDirective {
	f.t.Helper()
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(mode, "")}
	id := directive.GetInvitation().GetSessionId()
	if got := f.network(directive)[id]; got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING || got.GetLocalSession() != nil {
		f.t.Fatalf("new invitation = %v", got)
	}
	if _, ok := f.mustHelper(1000)[id]; !ok {
		f.t.Fatal("eligible helper did not receive the invitation")
	}
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	return directive
}

func TestAssistanceBrokerConsentOfferAnswerActive(t *testing.T) {
	f := newAssistanceFixture(t, true)
	directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL)
	id := directive.GetInvitation().GetSessionId()
	got := f.network(directive)[id]
	if got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		t.Fatalf("phase = %v, want PROMPTED", got.GetPhase())
	}
	local := got.GetLocalSession()
	if local.GetUid() != 1000 || local.GetUsername() != "alice" || local.GetLogindSessionId() != "2" || local.GetSessionType() != "wayland" || local.GetDesktop() != "GNOME" {
		t.Fatalf("local session = %v", local)
	}
	offered := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	offered.ControlGranted = true
	f.mustHelper(1000, offered)
	got = f.network(directive)[id]
	if got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED || got.GetOfferSdp() != testOffer || !got.GetControlGranted() {
		t.Fatalf("offered report = %v", got)
	}
	// ACTIVE cannot precede the authorized answer.
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE))
	if phase := f.network(directive)[id].GetPhase(); phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED {
		t.Fatalf("phase before answer = %v", phase)
	}
	answered := &agentv1.AssistanceDirective{Invitation: directive.GetInvitation(), AnswerSdp: "v=0\r\nanswer\r\n"}
	f.network(answered)
	if got := f.mustHelper(1000, offered)[id]; got.GetAnswerSdp() != answered.GetAnswerSdp() || got.GetTerminate() {
		t.Fatalf("helper directive = %v", got)
	}
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE))
	if got := f.network(answered)[id]; got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE || got.GetOfferSdp() != testOffer {
		t.Fatalf("active report = %v", got)
	}
}

func TestAssistanceBrokerViewNeverGrantsControl(t *testing.T) {
	f := newAssistanceFixture(t, true)
	directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
	id := directive.GetInvitation().GetSessionId()
	offered := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	offered.ControlGranted = true
	f.mustHelper(1000, offered)
	if got := f.network(directive)[id]; got.GetControlGranted() {
		t.Fatal("VIEW session reported control")
	}
}

// An executor restart loses the broker; a still-running helper that reports a
// live session for a re-delivered directive must be terminated, not re-adopted.
func TestAssistanceBrokerDoesNotReadoptLiveHelperSession(t *testing.T) {
	f := newAssistanceFixture(t, true)
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, ""), AnswerSdp: "v=0\r\nanswer\r\n"}
	id := directive.GetInvitation().GetSessionId()
	f.network(directive)
	got := f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE))[id]
	if !got.GetTerminate() {
		t.Fatalf("helper directive = %v, want terminate", got)
	}
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED)
}

func TestAssistanceBrokerLockEndsSession(t *testing.T) {
	t.Run("network sync", func(t *testing.T) {
		f := newAssistanceFixture(t, true)
		directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
		id := directive.GetInvitation().GetSessionId()
		f.setLogind("2", func(s *actionprovider.LogindSession) { s.Locked = true })
		wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED)
		if _, err := f.helper(1000); !errors.Is(err, errNoGraphicalSession) {
			t.Fatalf("locked caller err = %v", err)
		}
	})
	t.Run("helper sync", func(t *testing.T) {
		f := newAssistanceFixture(t, true)
		directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
		id := directive.GetInvitation().GetSessionId()
		f.setLogind("2", func(s *actionprovider.LogindSession) { s.Locked = true })
		if _, err := f.helper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)); !errors.Is(err, errNoGraphicalSession) {
			t.Fatalf("locked caller err = %v", err)
		}
		wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED)
	})
	t.Run("logout", func(t *testing.T) {
		f := newAssistanceFixture(t, true)
		directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
		id := directive.GetInvitation().GetSessionId()
		f.setLogind("2", func(s *actionprovider.LogindSession) { s.ID = "7" })
		wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED)
		// The new session of the same user does not inherit the ended session.
		if got, ok := f.mustHelper(1000)[id]; ok {
			t.Fatalf("new logind session received %v", got)
		}
	})
}

// GNOME closes the sharing portal on lock before logind reports LockedHint;
// the lock observed shortly afterwards must win the recorded cause.
func TestAssistanceBrokerPortalCloseSettlesBehindLock(t *testing.T) {
	closed := func(id string) *agentv1.SessionAssistanceReport {
		r := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED)
		r.EndCause = agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED
		r.EndDetail = "portal_session_closed"
		return r
	}
	t.Run("lock follows", func(t *testing.T) {
		f := newAssistanceFixture(t, true)
		directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
		id := directive.GetInvitation().GetSessionId()
		if got := f.mustHelper(1000, closed(id))[id]; got.GetTerminate() {
			t.Fatalf("helper that ended itself was sent terminate: %v", got)
		}
		f.advance(2 * time.Second)
		f.setLogind("2", func(s *actionprovider.LogindSession) { s.Locked = true })
		wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED)
	})
	t.Run("no lock", func(t *testing.T) {
		f := newAssistanceFixture(t, true)
		directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
		id := directive.GetInvitation().GetSessionId()
		f.mustHelper(1000, closed(id))
		if phase := f.network(directive)[id].GetPhase(); phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			t.Fatal("portal closure became final before the settle window")
		}
		f.advance(5 * time.Second)
		f.mustHelper(1000, closed(id))
		got := f.network(directive)[id]
		wantEnded(t, got, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED)
		if got.GetEndDetail() != "portal_session_closed" {
			t.Fatalf("detail = %q", got.GetEndDetail())
		}
	})
}

func TestAssistanceBrokerHelperAbsence(t *testing.T) {
	f := newAssistanceFixture(t, true)
	directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
	id := directive.GetInvitation().GetSessionId()
	f.advance(9 * time.Second)
	if phase := f.network(directive)[id].GetPhase(); phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		t.Fatalf("phase before absence window = %v", phase)
	}
	// A helper sync that omits the session does not keep it alive.
	f.mustHelper(1000)
	f.advance(time.Second)
	got := f.network(directive)[id]
	wantEnded(t, got, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED)
	if got.GetEndDetail() != "helper_absent" {
		t.Fatalf("detail = %q", got.GetEndDetail())
	}
}

func TestAssistanceBrokerReauthorizationWindow(t *testing.T) {
	f := newAssistanceFixture(t, true)
	directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
	id := directive.GetInvitation().GetSessionId()
	offered := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	for range 5 {
		f.advance(5 * time.Second)
		if got := f.mustHelper(1000, offered)[id]; got.GetTerminate() {
			t.Fatalf("terminated inside the reauthorization window: %v", got)
		}
		// Network syncs without this session's directive do not reauthorize it.
		if got := f.network()[id]; got.GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			t.Fatalf("ended early: %v", got)
		}
	}
	f.advance(5 * time.Second)
	got := f.mustHelper(1000, offered)[id]
	if !got.GetTerminate() || got.GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
		t.Fatalf("helper directive after 30s = %v", got)
	}
}

func TestAssistanceBrokerConsentDeadline(t *testing.T) {
	f := newAssistanceFixture(t, true)
	pending := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
	prompted := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
	for range 23 {
		f.advance(5 * time.Second)
		f.network(pending, prompted)
		f.mustHelper(1000, report(prompted.GetInvitation().GetSessionId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	}
	f.advance(5 * time.Second)
	reports := f.network(pending, prompted)
	wantEnded(t, reports[pending.GetInvitation().GetSessionId()], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION)
	wantEnded(t, reports[prompted.GetInvitation().GetSessionId()], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT)
}

func TestAssistanceBrokerForgetsEndedSessions(t *testing.T) {
	f := newAssistanceFixture(t, true)
	directive := f.prompted(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
	id := directive.GetInvitation().GetSessionId()
	stop := &agentv1.AssistanceDirective{Invitation: directive.GetInvitation(), Terminate: true}
	wantEnded(t, f.network(stop)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	if got := f.mustHelper(1000)[id]; !got.GetTerminate() || got.GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED {
		t.Fatalf("helper directive after stop = %v", got)
	}
	// Still listed while the server keeps sending it.
	wantEnded(t, f.network(stop)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	if reports := f.network(); len(reports) != 0 {
		t.Fatalf("ended session absent from directives was kept: %v", reports)
	}
	// A late directive for a forgotten session is never a new invitation.
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	if got, ok := f.mustHelper(1000)[id]; ok {
		t.Fatalf("forgotten session reached the helper again: %v", got)
	}
}

func TestAssistanceBrokerTargetsOnlyTheNamedUser(t *testing.T) {
	f := newAssistanceFixture(t, true)
	targeted := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "alice")}
	open := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
	targetID, openID := targeted.GetInvitation().GetSessionId(), open.GetInvitation().GetSessionId()
	f.network(targeted, open)
	bob := f.mustHelper(1001, report(targetID, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	if _, ok := bob[targetID]; ok {
		t.Fatal("wrong user received a targeted invitation")
	}
	if _, ok := bob[openID]; !ok {
		t.Fatal("eligible user did not receive an untargeted invitation")
	}
	if got := f.network(targeted, open)[targetID]; got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING || got.GetLocalSession() != nil {
		t.Fatalf("wrong user claimed a targeted invitation: %v", got)
	}
	// Once alice claims the open invitation, bob no longer sees it.
	alice := f.mustHelper(1000, report(openID, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	if _, ok := alice[targetID]; !ok {
		t.Fatal("target user did not receive the invitation")
	}
	if _, ok := f.mustHelper(1001, report(openID, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED))[openID]; ok {
		t.Fatal("other user still received a claimed invitation")
	}
	if got := f.network(targeted, open)[openID]; got.GetLocalSession().GetUsername() != "alice" || got.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED {
		t.Fatalf("claimed session = %v", got)
	}
}

func TestAssistanceBrokerDisabledEndsInvitations(t *testing.T) {
	f := newAssistanceFixture(t, false)
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
	id := directive.GetInvitation().GetSessionId()
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DISABLED)
	if _, ok := f.mustHelper(1000)[id]; ok {
		t.Fatal("disabled invitation reached a helper")
	}
}

// The server refuses requests before they become sessions only if every idle
// sync, not just one carrying an invitation, reports the applied setting.
func TestAssistanceBrokerReportsPolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		want := agentv1.AssistancePolicy_ASSISTANCE_POLICY_DISABLED
		if enabled {
			want = agentv1.AssistancePolicy_ASSISTANCE_POLICY_ENABLED
		}
		f := newAssistanceFixture(t, enabled)
		response, err := f.broker.syncNetwork(t.Context(), &agentv1.SyncAssistanceRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if response.GetPolicy() != want {
			t.Fatalf("enabled=%v reported %v, want %v", enabled, response.GetPolicy(), want)
		}
	}
}

func TestAssistanceBrokerSessionEligibility(t *testing.T) {
	f := newAssistanceFixture(t, true)
	if _, err := f.helper(4242); !errors.Is(err, errNoGraphicalSession) {
		t.Fatalf("uid without a session: %v", err)
	}
	if _, err := f.helper(0); !errors.Is(err, errNoGraphicalSession) {
		t.Fatalf("root caller: %v", err)
	}
	f.setLogind("2", func(s *actionprovider.LogindSession) { s.Remote = true })
	if _, err := f.helper(1000); !errors.Is(err, errNoGraphicalSession) {
		t.Fatalf("remote session: %v", err)
	}
	f.setLogind("2", func(s *actionprovider.LogindSession) { s.Remote = false })
	f.mu.Lock()
	f.logind = append(f.logind, actionprovider.LogindSession{ID: "9", UID: 1000, User: "alice", Class: "user", Type: "x11", Active: true})
	f.mu.Unlock()
	if _, err := f.helper(1000); !errors.Is(err, errAmbiguousGraphicalSession) {
		t.Fatalf("two sessions: %v", err)
	}
	f.setLogind("9", func(s *actionprovider.LogindSession) { s.Active = false })
	response, err := f.helper(1000)
	if err != nil || response.GetLocalSession().GetLogindSessionId() != "2" {
		t.Fatalf("single active session: %v %v", response, err)
	}
}

func TestAssistanceBrokerCapacity(t *testing.T) {
	f := newAssistanceFixture(t, true)
	var directives []*agentv1.AssistanceDirective
	for range assistanceMaxSessions {
		directives = append(directives, &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")})
	}
	if got := f.network(directives...); len(got) != assistanceMaxSessions {
		t.Fatalf("reports = %d", len(got))
	}
	extra := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
	got := f.network(append(directives[1:], extra)...)
	if len(got) != assistanceMaxSessions {
		t.Fatalf("reports beyond capacity = %d", len(got))
	}
	if _, ok := got[extra.GetInvitation().GetSessionId()]; ok {
		t.Fatal("ninth live session admitted")
	}
}
