//go:build integration

package assistance

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func activeAssistanceCapabilities(t *testing.T, grant *agentv1.AssistancePolicy) (*assistanceFixture, *agentv1.AssistanceReport) {
	t.Helper()
	f := newAssistanceFixture(t, 0)
	f.svc.AssistanceCeiling = allAssistanceCapabilities()
	_, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: allAssistanceCapabilities()}))
	if err != nil {
		t.Fatal(err)
	}
	request := f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
	request.RequestedCapabilities = allAssistanceCapabilities()
	created, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSession().GetId()
	observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint))
	observation.RequestedCapabilities, observation.EffectiveCapabilities = allAssistanceCapabilities(), allAssistanceCapabilities()
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: grant}
	if grant.GetClipboard() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		observation.GrantedCapabilities.ClipboardReason = "unsupported"
	}
	observation.Displays = []*agentv1.AssistanceDisplay{{Id: "monitor-1", Label: "First display", Width: 1920, Height: 1080}, {Id: "monitor-2", Label: "Second display", Width: 1280, Height: 720}}
	observation.SelectedDisplayId, observation.DisplayGeneration = "monitor-1", 1
	f.sync(t, observation)
	var consent map[string]string
	var consentReason, consentTarget string
	var consentActor *uuid.UUID
	if err := f.conn.QueryRow(f.ctx, "SELECT reason, target_device_id::text, actor_id, details FROM audit_events WHERE resource_id=$1 AND action='assistance.consent'", id).Scan(&consentReason, &consentTarget, &consentActor, &consent); err != nil {
		t.Fatal(err)
	}
	if consentReason != "" || consentTarget != f.deviceID || consentActor != nil {
		t.Fatal("local consent lost device identity or invented an operator-authored event")
	}
	for key, value := range map[string]string{
		"mode": "control", "result": "accepted", "operator": f.creator.ID.String(),
		"clipboard": "on", "keyboard": "on", "display_policy": "on", "messages": "on",
		"clipboard_granted": assistancePolicyModeName(grant.GetClipboard()),
		"keyboard_granted":  assistancePolicyModeName(grant.GetKeyboard()),
		"display_granted":   assistancePolicyModeName(grant.GetDisplay()),
		"messages_granted":  assistancePolicyModeName(grant.GetMessages()),
	} {
		if consent[key] != value {
			t.Fatalf("consent metadata %s = %q, want %q", key, consent[key], value)
		}
	}
	if _, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: id, AnswerSdp: f.sdp(strings.ReplaceAll(testFingerprint, "AB", "CD"))})); err != nil {
		t.Fatal(err)
	}
	observation.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE
	f.sync(t, observation)
	if state := f.get(t, id); state.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE {
		t.Fatalf("active negotiation failed: %v", state.GetEndDetail())
	}
	return f, observation
}

func commandRequest(sessionID string, kind agentv1.AssistanceCommandKind, text string) *adminv1.RunAssistanceCommandRequest {
	return &adminv1.RunAssistanceCommandRequest{SessionId: sessionID, Command: &agentv1.AssistanceCommand{RequestId: uuid.NewString(), Kind: kind, Text: text}}
}

func TestAssistancePolicyManagementExactIdentityAndCeiling(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	request := &adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: allAssistanceCapabilities()}
	_, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(request))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_policy_ceiling")
	var ceilingAudit map[string]string
	var reason, target, actor string
	if err := f.conn.QueryRow(f.ctx, "SELECT reason, target_device_id::text, actor_id::text, details FROM audit_events WHERE resource_id=$1 AND action='assistance.policy'", f.deviceID).Scan(&reason, &target, &actor, &ceilingAudit); err != nil {
		t.Fatal(err)
	}
	if reason != "" || target != f.deviceID || actor != f.creator.ID.String() || ceilingAudit["request"] != request.GetRequestId() || ceilingAudit["result"] != "denied" || ceilingAudit["reason"] != "policy_ceiling" || ceilingAudit["clipboard"] != "off" {
		t.Fatalf("denied policy audit lost typed authority: target=%s actor=%s reason=%q details=%v", target, actor, reason, ceilingAudit)
	}
	for _, key := range []string{"mode", "duration_seconds", "session", "device"} {
		if _, exists := ceilingAudit[key]; exists {
			t.Fatalf("device-only policy audit fabricated %s", key)
		}
	}
	f.svc.AssistanceCeiling = allAssistanceCapabilities()
	first, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(first.Msg, replayed.Msg) {
		t.Fatal("exact policy replay changed its outcome")
	}
	changed := proto.CloneOf(request)
	changed.Policy.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed request reused identity: %v", err)
	}
	if _, err := f.svc.UpdateAssistancePolicy(f.otherCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("other creator reused identity: %v", err)
	}
	auditor := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleAuditor))
	if _, err := f.svc.GetAssistancePolicy(auditor, connect.NewRequest(&adminv1.GetAssistancePolicyRequest{DeviceId: f.deviceID})); err != nil {
		t.Fatalf("auditor cannot read metadata: %v", err)
	}
	if _, err := f.svc.UpdateAssistancePolicy(auditor, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("auditor mutated policy: %v", err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.policy' AND details->>'result'='updated'", f.deviceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("exact replay emitted %d policy audits", count)
	}
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.policy' AND details->>'result'='denied'", f.deviceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("policy denials emitted %d audits, want 4", count)
	}
}

func TestAssistanceCommandCompletionAcrossServicesIsNotMutationAcceptance(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	admin := separateAssistanceService(t, f, f.svc.runtime)
	request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, "")
	accepted, err := admin.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING {
		t.Fatal("acceptance claimed native completion")
	}
	get := &adminv1.GetAssistanceCommandRequest{SessionId: request.GetSessionId(), RequestId: request.Command.GetRequestId()}
	pending, err := admin.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(get))
	if err != nil || pending.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_PENDING {
		t.Fatalf("pending state: %v", err)
	}
	directives := f.sync(t, observation)
	if len(directives) != 1 || directives[0].GetCommand().GetRequestId() != get.GetRequestId() || directives[0].GetCommand().GetDeadline() == nil {
		t.Fatal("accepted command not delivered with server deadline")
	}
	deadline := directives[0].GetCommand().GetDeadline().AsTime()
	if deadline.After(f.now.Add(30 * time.Second)) {
		t.Fatal("server overextended operation")
	}
	text := "clipboard-private-" + uuid.NewString()
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: get.GetRequestId(), Kind: request.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, Text: text, Reason: "clipboard_text_read", CompletedAt: timestamppb.New(f.now)}
	if got := f.sync(t, observation); len(got) != 1 || got[0].GetCommand() != nil {
		t.Fatal("completed side effect was redelivered")
	}
	result, err := admin.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(get))
	if err != nil || result.Msg.GetResult().GetText() != text {
		t.Fatalf("creator could not read completion: %v", err)
	}
	if _, err := admin.GetAssistanceCommand(f.otherCtx, connect.NewRequest(get)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different operator obtained clipboard: %v", err)
	}
	replay, err := admin.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request))
	if err != nil || replay.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("exact command recovery: %v", err)
	}
	if replay.Msg.GetResult().GetText() != "" {
		t.Fatal("mutation replay disclosed clipboard outside GetAssistanceCommand")
	}
	f.sync(t, observation)
	var durable, audit, reason, target, actor string
	var details map[string]string
	var projection, digest []byte
	if err := f.conn.QueryRow(f.ctx, "SELECT row_to_json(c)::text, request_digest FROM assistance_commands c WHERE request_id=$1", get.GetRequestId()).Scan(&durable, &digest); err != nil {
		t.Fatal(err)
	}
	if err := f.conn.QueryRow(f.ctx, "SELECT capability_projection FROM assistance_sessions WHERE id=$1", get.GetSessionId()).Scan(&projection); err != nil {
		t.Fatal(err)
	}
	if err := f.conn.QueryRow(f.ctx, "SELECT reason, target_device_id::text, actor_id::text, details, row_to_json(a)::text FROM audit_events a WHERE resource_id=$1 AND action='assistance.clipboard'", get.GetSessionId()).Scan(&reason, &target, &actor, &details, &audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(durable, text) || bytes.Contains(projection, []byte(text)) || strings.Contains(audit, text) || strings.Contains(audit, hex.EncodeToString(digest)) {
		t.Fatal("clipboard or content digest escaped ephemeral custody")
	}
	if reason != "" || target != f.deviceID || actor != f.creator.ID.String() || details["request"] != get.GetRequestId() || details["direction"] != "user_to_operator" || details["bytes"] != strconv.Itoa(len(text)) || details["result"] != "succeeded" || details["status"] != "succeeded" || details["clipboard"] != "on" {
		t.Fatalf("incomplete content-free completion metadata: %s", audit)
	}
	var denied string
	if err := f.conn.QueryRow(f.ctx, "SELECT reason, target_device_id::text, actor_id::text, details, row_to_json(a)::text FROM audit_events a WHERE resource_id=$1 AND action='assistance.command_denied'", get.GetSessionId()).Scan(&reason, &target, &actor, &details, &denied); err != nil {
		t.Fatal(err)
	}
	other, _ := identity.PrincipalFromContext(f.otherCtx)
	if reason != "" || target != f.deviceID || actor != other.ID.String() || details["request"] != get.GetRequestId() || details["result"] != "denied" || details["reason"] != "not_creator" || strings.Contains(denied, text) || strings.Contains(denied, hex.EncodeToString(digest)) {
		t.Fatalf("invalid result access audit: %s", denied)
	}
	// Simulate process memory loss, without changing the durable completed row.
	id := uuid.MustParse(get.GetSessionId())
	f.svc.runtime.assistanceMu.Lock()
	memory := f.svc.runtime.assistanceCommands[id]
	f.svc.runtime.assistanceMu.Unlock()
	f.svc.runtime.forgetAssistanceCommand(id, memory)
	_, err = admin.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(get))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_content_expired")
}

func TestAssistanceCommandsEnforceGrantReplayAndFreshRevocation(t *testing.T) {
	t.Run("unsupported grant", func(t *testing.T) {
		grant := allAssistanceCapabilities()
		grant.Clipboard = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
		f, observation := activeAssistanceCapabilities(t, grant)
		if got := f.get(t, observation.GetSessionId()).GetGrantedCapabilities().GetClipboardReason(); got != "unsupported" {
			t.Fatal("unsupported reason lost in projection")
		}
		_, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, "")))
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_capability_not_granted")
		var details map[string]string
		var reason, target string
		if err := f.conn.QueryRow(f.ctx, "SELECT reason, target_device_id::text, details FROM audit_events WHERE resource_id=$1 AND action='assistance.clipboard'", observation.GetSessionId()).Scan(&reason, &target, &details); err != nil {
			t.Fatal(err)
		}
		if reason != "" || target != f.deviceID || details["result"] != "denied" || details["reason"] != "capability_not_granted" {
			t.Fatalf("unsupported capability denial was not audited: %v", details)
		}
	})
	t.Run("replay and one outstanding", func(t *testing.T) {
		f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
		request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "private-message-"+uuid.NewString())
		if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
			t.Fatal(err)
		}
		changed := proto.CloneOf(request)
		changed.Command.Text = "changed"
		if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Fatalf("changed payload replay: %v", err)
		}
		_, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "second")))
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_command_busy")
		id := uuid.MustParse(observation.GetSessionId())
		f.svc.runtime.assistanceMu.Lock()
		memory := f.svc.runtime.assistanceCommands[id]
		f.svc.runtime.assistanceMu.Unlock()
		f.svc.runtime.forgetAssistanceCommand(id, memory)
		replayed, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request))
		if err != nil || replayed.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED {
			t.Fatalf("restart replay executed missing payload: %v", err)
		}
		if got := f.sync(t, observation); len(got) != 1 || got[0].GetCommand() != nil {
			t.Fatal("lost command replayed to guest")
		}
	})
	t.Run("creator revocation", func(t *testing.T) {
		f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
		request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "do not deliver after revoke")
		if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.conn.Exec(f.ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", f.creator.ID); err != nil {
			t.Fatal(err)
		}
		directives := f.sync(t, observation)
		if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetCommand() != nil {
			t.Fatal("device polling retained revoked operator authority")
		}
		var status int16
		if err := f.conn.QueryRow(f.ctx, "SELECT status FROM assistance_commands WHERE request_id=$1", request.Command.GetRequestId()).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != int16(agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED) {
			t.Fatal("revocation left a queued side effect")
		}
		if _, err := f.svc.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceCommandRequest{SessionId: request.GetSessionId(), RequestId: request.Command.GetRequestId()})); err == nil {
			t.Fatal("cached browser principal bypassed fresh revocation")
		}
	})
}

func TestAssistanceCapabilityScopesNeverBorrowViewScope(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	principal := identity.Principal{ID: f.creator.ID, Bindings: []*authv1.RoleBinding{
		{Permissions: []string{string(identity.PermissionViewRemoteAssistance)}},
		{Permissions: []string{string(identity.PermissionAssistanceClipboard)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}},
	}}
	policy := &agentv1.AssistancePolicy{Clipboard: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON}
	q := devicedb.New(f.svc.Pool)
	if err := scopeAssistanceCapabilities(f.ctx, q, principal, uuid.MustParse(f.deviceID), agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, policy); err == nil {
		t.Fatal("unrestricted view widened scoped clipboard authority")
	}
	principal.Bindings[1].Scopes[0].DeviceIds = []string{f.deviceID}
	if err := scopeAssistanceCapabilities(f.ctx, q, principal, uuid.MustParse(f.deviceID), agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, policy); err != nil {
		t.Fatalf("matching clipboard scope denied: %v", err)
	}
}

func TestAssistancePolicyRevocationCancelsWithoutGuestCompletion(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "private")
	if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: assistancePolicy(nil)}))
	if err != nil {
		t.Fatal(err)
	}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: request.Command.GetRequestId(), Kind: request.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, CompletedAt: timestamppb.New(f.now)}
	f.sync(t, observation)
	var status int16
	if err := f.conn.QueryRow(f.ctx, "SELECT status FROM assistance_commands WHERE request_id=$1", request.Command.GetRequestId()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != int16(agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED) {
		t.Fatal("late guest report resurrected cancelled operation")
	}
}

func TestAssistanceFreshScopeLossHidesResultsAndStopsSession(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, "")
	if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: request.Command.GetRequestId(), Kind: request.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, Text: "private", CompletedAt: timestamppb.New(f.now)}
	f.sync(t, observation)
	// Local account scopes are authoritative, not the browser Principal.
	if _, err := f.conn.Exec(f.ctx, `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes', jsonb_build_array(jsonb_build_object('deviceIds', jsonb_build_array($2::text)))) WHERE id=$1`, f.creator.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceCommandRequest{SessionId: request.GetSessionId(), RequestId: request.Command.GetRequestId()})); err == nil {
		t.Fatal("scope loss exposed cached clipboard result")
	}
	directives := f.sync(t, observation)
	if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
		t.Fatal("fresh scope loss did not end media authority")
	}
}

func TestAssistanceCommandDeadlineAcrossServicesFencesLateCompletion(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	admin := separateAssistanceService(t, f, f.svc.runtime)
	request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "late")
	if _, err := admin.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	// Shorten only the command deadline. Session and identity authority remain live.
	if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_commands SET deadline=$2 WHERE request_id=$1", request.Command.GetRequestId(), f.now); err != nil {
		t.Fatal(err)
	}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: request.Command.GetRequestId(), Kind: request.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, CompletedAt: timestamppb.New(f.now)}
	f.sync(t, observation)
	result, err := admin.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceCommandRequest{SessionId: request.GetSessionId(), RequestId: request.Command.GetRequestId()}))
	if err != nil || result.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_EXPIRED {
		t.Fatalf("late completion was accepted: %v", err)
	}
}

func TestAssistanceSeparateRuntimesDoNotDeliverCommands(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	admin := separateAssistanceService(t, f, NewRuntime())
	request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "isolated payload")
	if _, err := admin.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(request.GetSessionId())
	t.Cleanup(func() {
		admin.runtime.assistanceMu.Lock()
		memory := admin.runtime.assistanceCommands[id]
		admin.runtime.assistanceMu.Unlock()
		admin.runtime.forgetAssistanceCommand(id, memory)
	})
	directives := f.sync(t, observation)
	if len(directives) != 1 || directives[0].GetCommand() != nil {
		t.Fatal("device service borrowed content from a separate runtime")
	}
	result, err := admin.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceCommandRequest{SessionId: request.GetSessionId(), RequestId: request.Command.GetRequestId()}))
	if err != nil || result.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_CANCELLED || result.Msg.GetResult().GetReason() != "command_state_lost" {
		t.Fatalf("lost runtime state did not fail closed: %v", err)
	}
}

func TestAssistanceNoCommandsBeforeConsentAndConnection(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	f.svc.AssistanceCeiling = allAssistanceCapabilities()
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: allAssistanceCapabilities()})); err != nil {
		t.Fatal(err)
	}
	session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, 0, "")
	_, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(commandRequest(session.GetId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, "not consented")))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_not_active")
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM assistance_commands WHERE session_id=$1", session.GetId()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rejected preconsent operation became durable work")
	}
}

func TestAssistanceEmptyClipboardIsDistinctFromMissingContent(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := commandRequest(observation.GetSessionId(), agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, "")
	if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: request.Command.GetRequestId(), Kind: request.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, Text: "", Reason: "clipboard_text_read", CompletedAt: timestamppb.New(f.now)}
	f.sync(t, observation)
	result, err := f.svc.GetAssistanceCommand(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceCommandRequest{SessionId: request.GetSessionId(), RequestId: request.Command.GetRequestId()}))
	if err != nil || result.Msg.GetResult().GetStatus() != agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED || result.Msg.GetResult().GetText() != "" {
		t.Fatalf("real empty clipboard treated as missing content: %v", err)
	}
}

func TestAssistanceUnknownCompletionFailsClosed(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: uuid.NewString(), Kind: agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_MESSAGE, Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, CompletedAt: timestamppb.New(f.now)}
	directives := f.sync(t, observation)
	if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetCommand() != nil {
		t.Fatal("unknown side effect completion retained authority")
	}
	if got := f.get(t, observation.GetSessionId()); got.GetEndDetail() != "command_result_invalid" {
		t.Fatal("unknown completion did not record content-free failure")
	}
}

func TestAssistanceFrameProjectionIsImmutableAndClearedAtEnd(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	id := observation.GetSessionId()
	frame := &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-1", Generation: 1, RtpTimestamp: 0}
	observation.DisplayFrame = proto.CloneOf(frame)
	f.sync(t, observation)
	if !proto.Equal(f.get(t, id).GetDisplayFrame(), frame) {
		t.Fatal("operator lost the zero-timestamp frame witness")
	}
	observation.DisplayFrame = nil
	f.sync(t, observation)
	if !proto.Equal(f.get(t, id).GetDisplayFrame(), frame) {
		t.Fatal("transient omission erased the frame identity")
	}
	observation.DisplayFrame = proto.CloneOf(frame)
	observation.DisplayFrame.RtpTimestamp = 1
	f.sync(t, observation)
	state := f.get(t, id)
	if state.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED || state.GetEndDetail() != "display_frame_changed" {
		t.Fatal("same-generation frame substitution was accepted")
	}
	if state.GetDisplayFrame() != nil {
		t.Fatal("ended session exposed a live frame witness")
	}
}

func TestAssistanceDisplayCompletionPublishesFrameIdentityTogether(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	id := observation.GetSessionId()
	observation.DisplayFrame = &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-1", Generation: 1, RtpTimestamp: ^uint32(0)}
	f.sync(t, observation)
	request := commandRequest(id, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY, "")
	request.Command.DisplayId = "monitor-2"
	if _, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	f.sync(t, observation)
	observation.SelectedDisplayId, observation.DisplayGeneration = "monitor-2", 2
	observation.DisplayFrame = &agentv1.AssistanceDisplayFrame{DisplayId: "monitor-2", Generation: 2, RtpTimestamp: 0}
	observation.CommandResult = &agentv1.AssistanceCommandResult{RequestId: request.Command.GetRequestId(), Kind: request.Command.GetKind(), Status: agentv1.AssistanceCommandStatus_ASSISTANCE_COMMAND_STATUS_SUCCEEDED, Reason: "display_selected", CompletedAt: timestamppb.New(f.now)}
	f.sync(t, observation)
	state := f.get(t, id)
	if state.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE || state.GetSelectedDisplayId() != "monitor-2" || state.GetDisplayGeneration() != 2 || !proto.Equal(state.GetDisplayFrame(), observation.GetDisplayFrame()) {
		t.Fatal("selection and emitted-frame identity were not published together")
	}
}
