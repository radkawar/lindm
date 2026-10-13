//go:build integration

package assistance

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
	"lindm/internal/identity"
)

// nativeDetailsFixture is complete native inventory with every collector
// unavailable; observeSessions fills in the session inventory under test.
func nativeDetailsFixture() *inventoryv1.NativeDetails {
	unavailable := inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	text := func() *inventoryv1.ObservedString { return &inventoryv1.ObservedString{Status: unavailable} }
	number := func() *inventoryv1.ObservedUint64 { return &inventoryv1.ObservedUint64{Status: unavailable} }
	boolean := func() *inventoryv1.ObservedBool { return &inventoryv1.ObservedBool{Status: unavailable} }
	return &inventoryv1.NativeDetails{
		Cpu:               &inventoryv1.CpuDetails{Model: text(), LogicalCores: number(), PhysicalCores: number(), X86_64Level: text()},
		Memory:            &inventoryv1.MemoryDetails{TotalBytes: number(), AvailableBytes: number(), SwapTotalBytes: number()},
		Storage:           &inventoryv1.StorageDetails{Status: unavailable},
		Network:           &inventoryv1.NetworkDetails{Status: unavailable},
		Firmware:          &inventoryv1.FirmwareDetails{Mode: text(), SecureBoot: text()},
		Tpm:               &inventoryv1.TpmDetails{Present: boolean(), Version: text()},
		Power:             &inventoryv1.PowerDetails{Chassis: text(), Batteries: &inventoryv1.BatteryDetails{Status: unavailable}},
		Sessions:          &inventoryv1.SessionCounts{Users: number(), Sessions: number()},
		LocalUsers:        &inventoryv1.LocalUsers{Status: unavailable},
		KernelModuleCount: number(), UptimeSeconds: number(), BootTimeUnixSeconds: number(),
		Backends: &inventoryv1.BackendDetails{Dpkg: boolean(), Rpm: boolean(), Pacman: boolean(), Zypper: boolean(), RpmOstree: boolean(), Nix: boolean(), Flatpak: boolean(), Snap: boolean()},
		Flatpak:  &inventoryv1.ApplicationDetails{Status: unavailable}, Snap: &inventoryv1.ApplicationDetails{Status: unavailable},
	}
}

func (f *assistanceFixture) readiness(t *testing.T) *adminv1.AssistanceReadiness {
	t.Helper()
	response, err := f.svc.GetAssistanceReadiness(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceReadinessRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetReadiness()
}

func (f *assistanceFixture) syncPolicy(t *testing.T, policy agentv1.AssistanceEnablement) {
	t.Helper()
	if _, err := f.svc.SyncAssistance(f.deviceCtx(), connect.NewRequest(&devicev1.SyncAssistanceRequest{SessionEpoch: f.epoch, Policy: policy})); err != nil {
		t.Fatal(err)
	}
}

// observeSessions publishes a host observation whose active-session inventory
// holds exactly sessions. It clears the host-observation rate limit in the
// database rather than advancing the fixture clock: operator authorization
// expiry follows the database clock, so a fixture clock minutes ahead would
// end every new session at once.
func (f *assistanceFixture) observeSessions(t *testing.T, sequence uint64, sessions ...*inventoryv1.ActiveSession) {
	t.Helper()
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	report := hostObservation(f.generation, sequence, "assist")
	report.Observation.Details = nativeDetailsFixture()
	report.Observation.Details.Sessions.ActiveSessions = &inventoryv1.ActiveSessions{Status: success, Sessions: sessions}
	if _, err := f.conn.Exec(f.ctx, "UPDATE enrollment_generations SET last_host_admission_at=NULL WHERE id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	f.syncPolicy(t, agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_ENABLED)
}

func activeSession(class, kind string, remote bool) *inventoryv1.ActiveSession {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	observed := func(value string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: success, Value: value}
	}
	seat := observed("seat0")
	if remote || kind == "tty" {
		seat = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE}
	}
	return &inventoryv1.ActiveSession{
		UserName: observed("alice"), SessionClass: observed(class), SessionType: observed(kind),
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

func wantReadiness(t *testing.T, got *adminv1.AssistanceReadiness, state adminv1.AssistanceReadinessState, policy agentv1.AssistanceEnablement, desktop adminv1.AssistanceDesktop) {
	t.Helper()
	if got.GetState() != state || got.GetPolicy() != policy || got.GetDesktop() != desktop {
		t.Fatalf("readiness %v, want %v policy %v desktop %v", got, state, policy, desktop)
	}
}

// A request the device is known to refuse is answered before it exists: the
// operator gets a reason, and no session is recorded to read as "Ended".
func TestAssistanceReadinessRefusesBeforeSession(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	unknownPolicy, unknownDesktop := agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_UNSPECIFIED, adminv1.AssistanceDesktop_ASSISTANCE_DESKTOP_UNSPECIFIED
	enabled, disabled := agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_ENABLED, agentv1.AssistanceEnablement_ASSISTANCE_ENABLEMENT_DISABLED

	// Evidence not reported by an older agent is left to the device.
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_READY, unknownPolicy, unknownDesktop)

	f.syncPolicy(t, disabled)
	wantReadiness(t, f.readiness(t), adminv1.AssistanceReadinessState_ASSISTANCE_READINESS_STATE_DISABLED, disabled, unknownDesktop)
	f.wantRefused(t, "assistance_disabled")
	// Policy is a lasting blocker: it is reported even after the device goes quiet.
	if _, err := f.conn.Exec(f.ctx, "UPDATE devices SET last_seen_at=$2 WHERE id=$1", f.deviceID, f.now.Add(-3*time.Minute)); err != nil {
		t.Fatal(err)
	}
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
	principal.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionViewRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}}
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
