//go:build integration

package device

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/assistrelay"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

const assistanceRelayIP = "127.0.0.1"

type assistanceFixture struct {
	*enrolledFixture
	relay       *assistrelay.Relay
	creator     identity.Principal
	creatorCtx  context.Context
	otherCtx    context.Context
	epoch       uint64
	relayCandid string
}

// The relay is configured but never bound: these tests cover the server
// contract and credential decisions; relay forwarding is covered in assistrelay.
func newAssistanceFixture(t *testing.T, maxSessions uint32) *assistanceFixture {
	t.Helper()
	f := &assistanceFixture{enrolledFixture: newEnrolled(t, 0)}
	f.svc.clock = func() time.Time { return f.now }
	relay, err := assistrelay.New(&configv1.AssistanceConfig{MaxConcurrentSessions: maxSessions, Relay: &configv1.AssistanceRelayConfig{
		Listener: &configv1.ListenerConfig{Address: assistanceRelayIP, Port: 3478}, RelayAddress: assistanceRelayIP,
		RelayPortMin: 40000, RelayPortMax: 40100, Urls: []string{"turn:relay.example:3478?transport=udp"}, Realm: "relay.example",
	}}, func() time.Time { return f.now }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.relay = relay
	f.svc.assistance = relay
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 1, "assist"))); err != nil {
		t.Fatal(err)
	}
	f.creator = insertPrincipal(t, f.ctx, f.conn, identity.RoleAdmin)
	f.creatorCtx = identity.WithPrincipal(f.ctx, f.creator)
	f.otherCtx = identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleAdmin))
	if err := f.conn.QueryRow(f.ctx, "SELECT session_epoch FROM enrollment_generations WHERE id=$1", f.principal.GenerationID).Scan(&f.epoch); err != nil {
		t.Fatal(err)
	}
	f.relayCandid = "1 1 udp 16777215 " + assistanceRelayIP + " 40001 typ relay raddr 0.0.0.0 rport 0"
	return f
}

func (f *assistanceFixture) advance(d time.Duration) {
	f.now = f.now.Add(d)
}

func (f *assistanceFixture) create(t *testing.T, mode agentv1.AssistanceMode, seconds uint32, target string) *adminv1.AssistanceSession {
	t.Helper()
	response, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.createRequest(mode, seconds, target)))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetSession().GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_REQUESTED {
		t.Fatalf("created state %v", response.Msg.GetSession().GetState())
	}
	return response.Msg.GetSession()
}

func (f *assistanceFixture) createRequest(mode agentv1.AssistanceMode, seconds uint32, target string) *adminv1.CreateAssistanceSessionRequest {
	return &adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Mode: mode, Reason: "printer driver support", MaxDurationSeconds: seconds, TargetUsername: target}
}

func (f *assistanceFixture) sync(t *testing.T, reports ...*agentv1.AssistanceReport) []*agentv1.AssistanceDirective {
	t.Helper()
	response, err := f.svc.SyncAssistance(f.deviceCtx(), connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: f.epoch, Reports: reports}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetDirectives()
}

func (f *assistanceFixture) get(t *testing.T, id string) *adminv1.AssistanceSession {
	t.Helper()
	response, err := f.svc.GetAssistanceSession(f.ownerCtx, connect.NewRequest(&adminv1.GetAssistanceSessionRequest{SessionId: id}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetSession()
}

func (f *assistanceFixture) sdp(fingerprint string, candidates ...string) string {
	if len(candidates) == 0 {
		candidates = []string{f.relayCandid}
	}
	return testAssistanceSDP([]string{"sha-256 " + fingerprint}, candidates...)
}

func localSession(logind string) *agentv1.AssistanceLocalSession {
	return &agentv1.AssistanceLocalSession{Username: "alice", Uid: 1000, LogindSessionId: logind, SessionType: "wayland", Desktop: "GNOME"}
}

func report(id string, phase agentv1.AssistancePhase, local *agentv1.AssistanceLocalSession, offer string) *agentv1.AssistanceReport {
	return &agentv1.AssistanceReport{SessionId: id, Phase: phase, LocalSession: local, OfferSdp: offer, ControlGranted: true}
}

func ended(id string, cause agentv1.AssistanceEndCause) *agentv1.AssistanceReport {
	return &agentv1.AssistanceReport{SessionId: id, Phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, EndCause: cause, EndDetail: "device detail"}
}

func reasonOf(err error) string {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		return ""
	}
	return rpcreason.Get(connectErr)
}

// newEnrolledOn enrolls, activates and observes a second device on f's service.
func newEnrolledOn(t *testing.T, f *assistanceFixture) string {
	t.Helper()
	key := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, f.ctx, f.svc, f.ownerCtx, key)
	principal, err := f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, f.ctx, f.svc, principal, key, 0)
	if _, err := f.svc.ReportHostObservation(withDevicePrincipal(f.ctx, principal), connect.NewRequest(hostObservation(enrolled.Msg.GetEnrollmentGeneration(), 1, "second"))); err != nil {
		t.Fatal(err)
	}
	return enrolled.Msg.GetDeviceId()
}

func wantReason(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if connect.CodeOf(err) != code || reasonOf(err) != reason {
		t.Fatalf("got %v (%q), want %v %q", err, reasonOf(err), code, reason)
	}
}

func (f *assistanceFixture) auditActions(t *testing.T, id string) []string {
	t.Helper()
	rows, err := f.conn.Query(f.ctx, "SELECT action, reason, target_device_id::text, details FROM audit_events WHERE resource_id=$1 ORDER BY occurred_at, action", id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, reason, deviceID string
		var details map[string]string
		if err := rows.Scan(&action, &reason, &deviceID, &details); err != nil {
			t.Fatal(err)
		}
		if deviceID != f.deviceID {
			t.Fatalf("audit %s target %q, want %q", action, deviceID, f.deviceID)
		}
		if action == "assistance.request" {
			if reason != "printer driver support" {
				t.Fatalf("request lost operator reason: %q", reason)
			}
		} else if reason != "" {
			t.Fatalf("audit %s invented operator reason %q", action, reason)
		}
		for key, value := range details {
			if strings.Contains(value, "a=candidate") || strings.Contains(value, "v=0") {
				t.Fatalf("audit %s leaked SDP in %s", action, key)
			}
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(actions)
	return actions
}

func TestAssistanceLifecycleHappyPath(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
	created, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	session := created.Msg.GetSession()
	id := session.GetId()
	if !session.GetEndsAt().AsTime().Equal(f.now.Add(30*time.Minute)) || !session.GetConsentDeadline().AsTime().Equal(f.now.Add(2*time.Minute)) {
		t.Fatalf("deadlines %v %v from %v", session.GetConsentDeadline().AsTime(), session.GetEndsAt().AsTime(), f.now)
	}
	replay, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil || replay.Msg.GetSession().GetId() != id {
		t.Fatalf("idempotent replay: %v", err)
	}
	changed := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	changed.RequestId = request.GetRequestId()
	if _, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed replay: %v", err)
	}

	directives := f.sync(t)
	if len(directives) != 1 || directives[0].GetInvitation().GetSessionId() != id || directives[0].GetTerminate() || directives[0].GetAnswerSdp() != "" {
		t.Fatalf("initial directives %v", directives)
	}
	deviceICE := directives[0].GetInvitation().GetIceServers()
	if len(deviceICE) != 1 || !strings.HasSuffix(deviceICE[0].GetUsername(), ":"+id+":device") || deviceICE[0].GetUrls()[0] != "turn:relay.example:3478?transport=udp" {
		t.Fatalf("device ICE %v", deviceICE)
	}

	f.advance(time.Second)
	f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PENDING, nil, ""))
	f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("3"), ""))
	if got := f.get(t, id); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_PROMPTED || got.GetLocalSession().GetLogindSessionId() != "3" {
		t.Fatalf("prompted %v", got)
	}
	if _, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("join before offer: %v", err)
	}
	offer := f.sdp(testFingerprint)
	f.advance(time.Second)
	f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), offer))
	offered := f.get(t, id)
	if offered.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED || !offered.GetControlGranted() || offered.GetOfferFingerprint() != "sha-256 "+testFingerprint || offered.GetConsentedAt() == nil {
		t.Fatalf("offered %v", offered)
	}

	_, err = f.svc.JoinAssistanceSession(f.otherCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id}))
	wantReason(t, err, connect.CodePermissionDenied, "assistance_not_creator")
	joined, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id}))
	if err != nil {
		t.Fatal(err)
	}
	consoleICE := joined.Msg.GetIceServers()
	if joined.Msg.GetOfferSdp() != offer || len(consoleICE) != 1 || !strings.HasSuffix(consoleICE[0].GetUsername(), ":"+id+":console") {
		t.Fatalf("join response %v", joined.Msg)
	}

	answerFingerprint := strings.Replace(testFingerprint, "AB", "12", 1)
	answer := f.sdp(answerFingerprint)
	_, err = f.svc.AnswerAssistanceSession(f.otherCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: answer}))
	wantReason(t, err, connect.CodePermissionDenied, "assistance_not_creator")
	_, err = f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: f.sdp(answerFingerprint, "2 1 udp 2122260223 10.0.0.5 50000 typ host")}))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_non_relay")
	answered, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: answer}))
	if err != nil || answered.Msg.GetSession().GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ANSWERED || answered.Msg.GetSession().GetAnswerFingerprint() != "sha-256 "+answerFingerprint {
		t.Fatalf("answer: %v %v", err, answered)
	}
	_, err = f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: answer}))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_state")

	f.advance(time.Second)
	directives = f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), offer))
	if len(directives) != 1 || directives[0].GetAnswerSdp() != answer {
		t.Fatalf("answer directive %v", directives)
	}
	f.advance(time.Second)
	f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, localSession("3"), offer))
	if got := f.get(t, id); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE || got.GetStartedAt() == nil {
		t.Fatalf("active %v", got)
	}
	sessionID := uuid.MustParse(id)
	if f.relay.Ended(sessionID) {
		t.Fatal("live session marked ended at the relay")
	}

	// Any authorized operator in scope may stop; stop is idempotent.
	stopped, err := f.svc.StopAssistanceSession(f.otherCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: id}))
	if err != nil || stopped.Msg.GetSession().GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED || stopped.Msg.GetSession().GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED {
		t.Fatalf("stop: %v %v", err, stopped)
	}
	if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: id})); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
	if !f.relay.Ended(sessionID) {
		t.Fatal("stopped session not revoked at the relay")
	}
	f.advance(time.Second)
	directives = f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, localSession("3"), offer))
	if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED || directives[0].GetAnswerSdp() != "" {
		t.Fatalf("terminate directive %v", directives)
	}
	f.sync(t, ended(id, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED))
	if directives := f.sync(t); len(directives) != 0 {
		t.Fatalf("confirmed end still delivered: %v", directives)
	}
	final := f.get(t, id)
	if final.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED || final.GetOfferFingerprint() == "" {
		t.Fatalf("final %v", final)
	}
	want := []string{"assistance.answer", "assistance.consent", "assistance.end", "assistance.join", "assistance.prompt", "assistance.request", "assistance.start", "assistance.stop"}
	if got := f.auditActions(t, id); !slices.Equal(got, want) {
		t.Fatalf("audit actions %v, want %v", got, want)
	}
	var consent map[string]string
	if err := f.conn.QueryRow(f.ctx, "SELECT details FROM audit_events WHERE resource_id=$1 AND action='assistance.consent'", id).Scan(&consent); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"mode": "control", "duration_seconds": "1800", "control_granted": "true", "user": "alice", "uid": "1000", "session": "3"} {
		if consent[key] != value {
			t.Fatalf("consent audit %v: %s = %q, want %q", consent, key, consent[key], value)
		}
	}
	listed, err := f.svc.ListAssistanceSessions(f.ownerCtx, connect.NewRequest(&adminv1.ListAssistanceSessionsRequest{DeviceId: f.deviceID}))
	if err != nil || len(listed.Msg.GetSessions()) != 1 || listed.Msg.GetSessions()[0].GetId() != id {
		t.Fatalf("list: %v %v", err, listed)
	}
}

func TestAssistanceAdmission(t *testing.T) {
	f := newAssistanceFixture(t, 1)
	f.svc.assistance = nil
	_, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_unconfigured")
	f.svc.assistance = f.relay
	helpdesk := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleHelpdesk))
	if _, err := f.svc.CreateAssistanceSession(helpdesk, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, ""))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("helpdesk create: %v", err)
	}
	f.advance(3 * time.Minute)
	_, err = f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")))
	wantReason(t, err, connect.CodeFailedPrecondition, "device_offline")
	f.sync(t)
	first := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	_, err = f.svc.CreateAssistanceSession(f.otherCtx, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_busy")

	// A second device cannot exceed the deployment admission cap of one.
	second := newEnrolledOn(t, f)
	_, err = f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.CreateAssistanceSessionRequest{RequestId: uuid.NewString(), DeviceId: second, Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, Reason: "second device"}))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_capacity")

	if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: first.GetId()})); err != nil {
		t.Fatal(err)
	}
	f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	if _, err := f.svc.SyncAssistance(f.deviceCtx(), connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: f.epoch + 1})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("stale session epoch: %v", err)
	}
}

func TestAssistanceDeadlines(t *testing.T) {
	t.Run("consent timeout", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("3"), ""))
		// The device keeps syncing within the 30 s window while the prompt is shown.
		for range 7 {
			f.advance(17 * time.Second)
			f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("3"), ""))
		}
		if got := f.get(t, session.GetId()); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_PROMPTED {
			t.Fatalf("before deadline %v", got)
		}
		f.advance(time.Second)
		got := f.get(t, session.GetId())
		if got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED || got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT {
			t.Fatalf("consent timeout %v", got)
		}
		// A late offer cannot revive the session.
		directives := f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint)))
		if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONSENT_TIMEOUT {
			t.Fatalf("late offer directives %v", directives)
		}
		if got := f.auditActions(t, session.GetId()); !slices.Contains(got, "assistance.end") {
			t.Fatalf("consent timeout not audited: %v", got)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 60, "")
		id := session.GetId()
		f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint)))
		if got := f.get(t, id); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED {
			t.Fatalf("offer straight from pending %v", got)
		}
		f.advance(60 * time.Second)
		directives := f.sync(t, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint)))
		if len(directives) != 1 || directives[0].GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED {
			t.Fatalf("expiry directives %v", directives)
		}
		_, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id}))
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_ended")
		// Ended directives stop after the two-minute delivery window.
		f.advance(2*time.Minute + time.Second)
		if directives := f.sync(t); len(directives) != 0 {
			t.Fatalf("stale ended directive %v", directives)
		}
	})
	t.Run("device unreachable", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("3"), ""))
		f.advance(29 * time.Second)
		if got := f.get(t, session.GetId()); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_PROMPTED {
			t.Fatalf("ended early %v", got)
		}
		f.advance(time.Second)
		got := f.get(t, session.GetId())
		if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST || got.GetEndDetail() != "device_unreachable" {
			t.Fatalf("unreachable %v", got)
		}
	})
}

func TestAssistanceDeviceIdentityChecks(t *testing.T) {
	t.Run("local session change", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("3"), ""))
		directives := f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("7"), f.sdp(testFingerprint)))
		got := f.get(t, session.GetId())
		if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED || got.GetEndDetail() != "local_session_changed" || got.GetOfferFingerprint() != "" {
			t.Fatalf("identity change %v", got)
		}
		if len(directives) != 1 || !directives[0].GetTerminate() {
			t.Fatalf("identity change directives %v", directives)
		}
	})
	t.Run("target user mismatch", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "bob")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED, localSession("3"), ""))
		if got := f.get(t, session.GetId()); got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_NO_ELIGIBLE_SESSION {
			t.Fatalf("target mismatch %v", got)
		}
	})
	t.Run("non-relay offer", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint, "2 1 udp 2122260223 10.0.0.5 50000 typ host")))
		got := f.get(t, session.GetId())
		if got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_CONNECTION_FAILED || got.GetEndDetail() != "assistance_non_relay" {
			t.Fatalf("non-relay offer %v", got)
		}
	})
	t.Run("view mode never grants control", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint)))
		if got := f.get(t, session.GetId()); got.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_OFFERED || got.GetControlGranted() {
			t.Fatalf("view offer %v", got)
		}
	})
	t.Run("active before answer", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
		f.sync(t, report(session.GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE, localSession("3"), f.sdp(testFingerprint)))
		if got := f.get(t, session.GetId()); got.GetEndDetail() != "active_before_answer" {
			t.Fatalf("unanswered active %v", got)
		}
	})
	t.Run("device ended", func(t *testing.T) {
		f := newAssistanceFixture(t, 0)
		session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
		if directives := f.sync(t, ended(session.GetId(), agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED)); len(directives) != 0 {
			t.Fatalf("device-confirmed end redelivered %v", directives)
		}
		if got := f.get(t, session.GetId()); got.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED || got.GetEndDetail() != "device detail" {
			t.Fatalf("declined %v", got)
		}
	})
}

func TestAssistanceAuditReasonAndStructuredList(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 900, "alice")
	request.Reason = "Help the user: " + strings.Repeat("é", 400)
	created, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	var hostname string
	if err := f.conn.QueryRow(f.ctx, "SELECT hostname FROM devices WHERE id=$1", f.deviceID).Scan(&hostname); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	found := false
	token := ""
	for {
		page, err := f.svc.ListAuditEvents(f.ownerCtx, connect.NewRequest(&adminv1.ListAuditEventsRequest{PageSize: 1, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Msg.GetEvents() {
			if seen[event.GetId()] {
				t.Fatalf("duplicate audit event %s across pages", event.GetId())
			}
			seen[event.GetId()] = true
			if event.GetResourceId() != created.Msg.GetSession().GetId() {
				continue
			}
			found = true
			if event.GetReason() != request.GetReason() || event.GetTargetDeviceId() != f.deviceID || event.GetDeviceHostname() != hostname {
				t.Fatalf("audit lost reason or target: %v", event)
			}
			details := event.GetDetails()
			if details["mode"] != "view" || details["duration_seconds"] != "900" || details["target"] != "alice" {
				t.Fatalf("audit lost structured request context: %v", details)
			}
			if _, duplicated := details["reason"]; duplicated {
				t.Fatal("operator reason duplicated into generated context")
			}
		}
		token = page.Msg.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if !found {
		t.Fatal("assistance request missing from audit API")
	}
}
