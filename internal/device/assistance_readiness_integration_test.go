//go:build integration

package device

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/inventory"
	"lindm/internal/identity"
)

func (f *assistanceFixture) readiness(t *testing.T) *adminv1.AssistanceReadiness {
	t.Helper()
	response, err := f.svc.GetAssistanceReadiness(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceReadinessRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetReadiness()
}

func (f *assistanceFixture) syncPolicy(t *testing.T, policy agentv1.AssistancePolicy) {
	t.Helper()
	if _, err := f.svc.SyncAssistance(f.deviceCtx(), connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: f.epoch, Policy: policy})); err != nil {
		t.Fatal(err)
	}
}

// observeSessions publishes a host observation whose active-session inventory
// holds exactly sessions.
func (f *assistanceFixture) observeSessions(t *testing.T, sequence uint64, sessions ...*inventoryv1.ActiveSession) {
	t.Helper()
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	report := hostObservation(f.generation, sequence, "assist")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.Sessions.ActiveSessions = &inventoryv1.ActiveSessions{Status: success, Sessions: sessions}
	f.advance(inventory.SnapshotAttemptInterval)
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	f.syncPolicy(t, agentv1.AssistancePolicy_ASSISTANCE_POLICY_ENABLED)
}

func activeSession(class, kind string, remote bool) *inventoryv1.ActiveSession {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	seat := observed(success, "seat0")
	if remote || kind == "tty" {
		seat = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE}
	}
	return &inventoryv1.ActiveSession{
		UserName: observed(success, "alice"), SessionClass: observed(success, class), SessionType: observed(success, kind),
		Seat: seat, Remote: &inventoryv1.ObservedBool{Status: success, Value: remote},
	}
}

func (f *assistanceFixture) wantRefused(t *testing.T, reason string) {
	t.Helper()
	_, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")))
	wantReason(t, err, connect.CodeFailedPrecondition, reason)
	listed, err := f.svc.ListAssistanceSessions(f.ownerCtx, connect.NewRequest(&adminv1.ListAssistanceSessionsRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.GetSessions()) != 0 {
		t.Fatalf("refused request %s was recorded as a session: %v", reason, listed.Msg.GetSessions())
	}
}

func wantReadiness(t *testing.T, got *adminv1.AssistanceReadiness, state adminv1.AssistanceReadinessState, policy agentv1.AssistancePolicy, desktop adminv1.AssistanceDesktop) {
	t.Helper()
	if got.GetState() != state || got.GetPolicy() != policy || got.GetDesktop() != desktop {
		t.Fatalf("readiness %v, want %v policy %v desktop %v", got, state, policy, desktop)
	}
}

// A request the device is known to refuse is answered before it exists: the
// operator gets a reason, and no session is recorded to read as "Ended".
func TestAssistanceReadinessRefusesBeforeSession(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	unknownPolicy, unknownDesktop := agentv1.AssistancePolicy_ASSISTANCE_POLICY_UNSPECIFIED, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_UNSPECIFIED
	enabled, disabled := agentv1.AssistancePolicy_ASSISTANCE_POLICY_ENABLED, agentv1.AssistancePolicy_ASSISTANCE_POLICY_DISABLED

	// Evidence not reported by an older agent is left to the device.
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_READY, unknownPolicy, unknownDesktop)

	f.syncPolicy(t, disabled)
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_DISABLED, disabled, unknownDesktop)
	f.wantRefused(t, "assistance_disabled")
	// Policy is a lasting blocker: it is reported even after the device goes quiet.
	f.advance(3 * time.Minute)
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_DISABLED, disabled, unknownDesktop)
	f.wantRefused(t, "assistance_disabled")

	// A headless host: only an SSH and a console login.
	f.observeSessions(t, 2, activeSession("user", "tty", true), activeSession("user", "tty", false))
	readiness := f.readiness(t)
	wantReadiness(t, readiness, adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_NO_DESKTOP, enabled, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_ABSENT)
	if readiness.GetInventoryObservedAt() == nil || readiness.GetLastSeenAt() == nil {
		t.Fatalf("readiness lacks its evidence times: %v", readiness)
	}
	f.wantRefused(t, "assistance_no_desktop")

	// A remote X11 session is not a local desktop; a login screen is.
	f.observeSessions(t, 3, activeSession("user", "x11", true))
	f.wantRefused(t, "assistance_no_desktop")
	f.observeSessions(t, 4, activeSession("greeter", "wayland", false))
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_READY, enabled, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_PRESENT)

	session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	busy := f.readiness(t)
	wantReadiness(t, busy, adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_BUSY, enabled, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_PRESENT)
	if busy.GetOpenSessionId() != session.GetId() {
		t.Fatalf("busy names %q, want %q", busy.GetOpenSessionId(), session.GetId())
	}

	// An agent that stops reporting leaves the policy unknown, not stale.
	f.syncPolicy(t, unknownPolicy)
	if got := f.readiness(t).GetPolicy(); got != unknownPolicy {
		t.Fatalf("unreported policy kept as %v", got)
	}

	// Silence ends the open session lazily; the device then reads offline, not busy.
	f.advance(3 * time.Minute)
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_OFFLINE, unknownPolicy, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_PRESENT)

	f.svc.Assistance = nil
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_UNCONFIGURED, unknownPolicy, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_PRESENT)
}

func TestAssistanceReadinessScope(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	principal := insertPrincipal(t, f.ctx, f.conn, identity.RoleAdmin)
	principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionRunRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}
	request := connect.NewRequest(&adminv1.GetAssistanceReadinessRequest{DeviceId: f.deviceID})
	if _, err := f.svc.GetAssistanceReadiness(identity.WithPrincipal(f.ctx, principal), request); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope readiness: %v", err)
	}
	principal.Bindings[0].Scopes = []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}
	if _, err := f.svc.GetAssistanceReadiness(identity.WithPrincipal(f.ctx, principal), request); err != nil {
		t.Fatalf("in-scope readiness: %v", err)
	}
	reader := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor))
	if _, err := f.svc.GetAssistanceReadiness(reader, request); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("auditor readiness: %v", err)
	}
	missing := connect.NewRequest(&adminv1.GetAssistanceReadinessRequest{DeviceId: uuid.NewString()})
	if _, err := f.svc.GetAssistanceReadiness(f.creatorCtx, missing); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("absent device readiness: %v", err)
	}
}
