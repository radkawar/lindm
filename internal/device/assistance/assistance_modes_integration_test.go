//go:build integration

package assistance

import (
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func assistanceModeRoles(t *testing.T, f *assistanceFixture, role string) {
	t.Helper()
	authority, err := identity.New(t.Context(), f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{
		{Name: "view-only", Permissions: []string{string(identity.PermissionViewRemoteAssistance)}},
		{Name: "control-only", Permissions: []string{string(identity.PermissionControlRemoteAssistance)}},
		{Name: "view-control", Permissions: []string{string(identity.PermissionViewRemoteAssistance), string(identity.PermissionControlRemoteAssistance)}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	f.svc.Identity = authority
	setAssistanceRole(t, f, role)
	// Retain the earlier admin browser principal: only freshly observed grants
	// may admit a session, even when its cached display role was more privileged.
}

func setAssistanceRole(t *testing.T, f *assistanceFixture, role string) {
	t.Helper()
	if _, err := f.conn.Exec(f.ctx, "UPDATE local_accounts SET role=$2 WHERE id=$1", f.creator.ID, role); err != nil {
		t.Fatal(err)
	}
}

func TestAssistanceModesRequireIndependentFreshPermissions(t *testing.T) {
	for _, test := range []struct {
		role    string
		mode    agentv1.AssistanceMode
		allowed bool
	}{
		{"view-only", agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, true},
		{"view-only", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, false},
		{"control-only", agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, false},
		{"control-only", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, false},
		{"view-control", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, true},
	} {
		t.Run(test.role+"/"+test.mode.String(), func(t *testing.T) {
			f := newAssistanceFixture(t, 0)
			assistanceModeRoles(t, f, test.role)
			response, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(f.createRequest(test.mode, 0, "")))
			if test.allowed {
				if err != nil || response.Msg.GetSession().GetMode() != test.mode {
					t.Fatalf("authorized mode not admitted: %v", err)
				}
			} else {
				if connect.CodeOf(err) != connect.CodePermissionDenied || response != nil {
					t.Fatalf("fresh role admitted unauthorized mode: %v", err)
				}
				var count int
				if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM assistance_sessions").Scan(&count); err != nil || count != 0 {
					t.Fatalf("denied request created a session: count=%d err=%v", count, err)
				}
			}
		})
	}
}

func TestAssistanceViewCannotEscalateThroughReplayOrConsent(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	assistanceModeRoles(t, f, "view-only")
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
	response, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	id := response.Msg.GetSession().GetId()
	request.Mode = agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	if _, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("view-only replay escalated: %v", err)
	}
	setAssistanceRole(t, f, "view-control")
	if _, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("later control grant changed existing session mode: %v", err)
	}
	setAssistanceRole(t, f, "view-only")
	observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint))
	observation.ControlGranted = true
	f.sync(t, observation)
	joined, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id}))
	if err != nil || joined.Msg.GetSession().GetControlGranted() || joined.Msg.GetSession().GetMode() != agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW {
		t.Fatalf("view consent escalated control: %v", err)
	}
	if _, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: f.sdp(strings.ReplaceAll(testFingerprint, "AB", "CD"))})); err != nil {
		t.Fatal(err)
	}
	observation.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE
	f.sync(t, observation)
	if session := f.get(t, id); session.GetControlGranted() || session.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE {
		t.Fatal("view-only session failed to retain view-only authority")
	}
}

func TestAssistanceControlRevocationFencesNegotiationCommandsAndSync(t *testing.T) {
	for _, phase := range []agentv1.AssistancePhase{agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE} {
		t.Run(phase.String(), func(t *testing.T) {
			f := newAssistanceFixture(t, 0)
			assistanceModeRoles(t, f, "view-control")
			session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
			id := session.GetId()
			observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint))
			f.sync(t, observation)
			answer := &adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: f.sdp(strings.ReplaceAll(testFingerprint, "AB", "CD"))}
			if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
				if _, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(answer)); err != nil {
					t.Fatal(err)
				}
				observation.Phase = phase
				f.sync(t, observation)
			}
			setAssistanceRole(t, f, "view-only")
			if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED {
				if _, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: id})); connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Fatalf("revoked control joined: %v", err)
				}
				if _, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(answer)); connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Fatalf("revoked control answered: %v", err)
				}
			}
			if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(commandRequest(id, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "denied"))); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("revoked control dispatched a command: %v", err)
			}
			directives := f.sync(t, observation)
			if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetCommand() != nil || directives[0].GetAnswerSdp() != "" {
				t.Fatal("control loss retained live device authority")
			}
			ended := f.get(t, id)
			if ended.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST || ended.GetEndDetail() != "operator_scope_lost" || !f.relay.Ended(uuid.MustParse(id)) {
				t.Fatal("control loss did not durably end session and relay")
			}
		})
	}
}

func TestAssistanceControlRequiresIntersectingDeviceScopes(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	principal := identity.Principal{Bindings: []*authv1.RoleBinding{
		{Permissions: []string{string(identity.PermissionViewRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}},
		{Permissions: []string{string(identity.PermissionControlRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}},
	}}
	q := devicedb.New(f.svc.Pool)
	deviceID := uuid.MustParse(f.deviceID)
	if err := scopeAssistanceMode(f.ctx, q, principal, deviceID, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW); err != nil {
		t.Fatal(err)
	}
	if err := scopeAssistanceMode(f.ctx, q, principal, deviceID, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("control borrowed view scope: %v", err)
	}
	principal.Bindings[1].Scopes[0].DeviceIds = []string{f.deviceID}
	if err := scopeAssistanceMode(f.ctx, q, principal, deviceID, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL); err != nil {
		t.Fatal(err)
	}
	principal.Bindings[0].Scopes[0].DeviceIds = []string{uuid.NewString()}
	if err := scopeAssistanceMode(f.ctx, q, principal, deviceID, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("view borrowed control scope: %v", err)
	}
}

func TestAssistanceViewOnlyCanStopControlWithoutEscalation(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
	viewer := f.creator
	viewer.Bindings = []*authv1.RoleBinding{{Permissions: []string{string(identity.PermissionViewRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}}}
	response, err := f.svc.StopAssistanceSession(identity.WithPrincipal(f.ctx, viewer), connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: session.GetId()}))
	if err != nil || response.Msg.GetSession().GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED {
		t.Fatalf("view-only de-escalation failed: %v", err)
	}
}
