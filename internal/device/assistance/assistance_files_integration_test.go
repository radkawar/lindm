// SPDX-License-Identifier: Apache-2.0

//go:build integration

package assistance

import (
	"bytes"
	"context"
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
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func startTestAssistanceFile(t *testing.T, f *assistanceFixture, request *adminv1.StartAssistanceFileTransferRequest) *agentv1.AssistanceFileReport {
	t.Helper()
	response, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetTransfer()
}

func getTestAssistanceFile(t *testing.T, f *assistanceFixture, request *adminv1.StartAssistanceFileTransferRequest) *agentv1.AssistanceFileReport {
	t.Helper()
	response, err := f.svc.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetTransfer()
}

func cancelTestAssistanceFile(t *testing.T, f *assistanceFixture, request *adminv1.StartAssistanceFileTransferRequest) *agentv1.AssistanceFileReport {
	t.Helper()
	response, err := f.svc.CancelAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.CancelAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetTransfer()
}

func completedTestAssistanceFile(f *assistanceFixture, request *adminv1.StartAssistanceFileTransferRequest) *agentv1.AssistanceFileReport {
	return &agentv1.AssistanceFileReport{RequestId: request.Transfer.RequestId, Direction: request.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, BytesTransferred: request.Transfer.File.Size, File: proto.CloneOf(request.Transfer.File), CompletedAt: timestamppb.New(f.now), Reason: "receiver_verified"}
}

func newAssistanceFilesFixture(t *testing.T, role string) *assistanceFixture {
	t.Helper()
	f := newAssistanceFixture(t, 0)
	policy := assistancePolicy(&agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, FileLimits: testAssistanceFilePolicy()})
	f.svc.AssistanceCeiling = policy
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: policy})); err != nil {
		t.Fatal(err)
	}
	authority, err := identity.New(t.Context(), f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{
		{Name: "view-only", Permissions: []string{string(identity.PermissionViewRemoteAssistance)}},
		{Name: "files-only", Permissions: []string{string(identity.PermissionAssistanceFiles)}},
		{Name: "view-files", Permissions: []string{string(identity.PermissionViewRemoteAssistance), string(identity.PermissionAssistanceFiles)}},
		{Name: "control-files", Permissions: []string{string(identity.PermissionControlRemoteAssistance), string(identity.PermissionAssistanceFiles)}},
		{Name: "view-control", Permissions: []string{string(identity.PermissionViewRemoteAssistance), string(identity.PermissionControlRemoteAssistance)}},
		{Name: "view-control-files", Permissions: []string{string(identity.PermissionViewRemoteAssistance), string(identity.PermissionControlRemoteAssistance), string(identity.PermissionAssistanceFiles)}},
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
	return f
}

func offeredAssistanceFiles(t *testing.T, mode agentv1.AssistanceMode) (*assistanceFixture, *agentv1.AssistanceReport) {
	t.Helper()
	role := "view-files"
	if mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
		role = "view-control-files"
	}
	f := newAssistanceFilesFixture(t, role)
	request := f.createRequest(mode, 0, "")
	request.RequestedCapabilities = proto.CloneOf(f.svc.AssistanceCeiling)
	response, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	observation := report(response.Msg.GetSession().GetId(), agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, localSession("3"), f.sdp(testFingerprint))
	observation.ControlGranted = mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL
	observation.RequestedCapabilities, observation.EffectiveCapabilities = proto.CloneOf(request.RequestedCapabilities), proto.CloneOf(request.RequestedCapabilities)
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: proto.CloneOf(request.RequestedCapabilities)}
	f.sync(t, observation)
	return f, observation
}

func activateAssistanceFiles(t *testing.T, f *assistanceFixture, observation *agentv1.AssistanceReport) {
	t.Helper()
	if _, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: observation.SessionId, AnswerSdp: f.sdp(strings.ReplaceAll(testFingerprint, "AB", "CD"))})); err != nil {
		t.Fatal(err)
	}
	observation.Phase = agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE
	f.sync(t, observation)
	if state := f.get(t, observation.SessionId); state.GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE {
		t.Fatalf("file session did not activate: %v", state.GetEndDetail())
	}
}

func TestAssistanceFilesCreateRequiresIndependentModeGrants(t *testing.T) {
	for _, test := range []struct {
		role string
		mode agentv1.AssistanceMode
		code connect.Code
	}{
		{"files-only", agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, connect.CodePermissionDenied},
		{"files-only", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodePermissionDenied},
		{"control-files", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodePermissionDenied},
		{"view-files", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodePermissionDenied},
		{"view-only", agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, connect.CodeNotFound},
		{"view-control", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodeNotFound},
	} {
		t.Run(test.role+"/"+test.mode.String(), func(t *testing.T) {
			f := newAssistanceFilesFixture(t, test.role)
			request := f.createRequest(test.mode, 0, "")
			request.RequestedCapabilities = proto.CloneOf(f.svc.AssistanceCeiling)
			if _, err := f.svc.CreateAssistanceSession(f.creatorCtx, connect.NewRequest(request)); connect.CodeOf(err) != test.code {
				t.Fatalf("missing independent grant admitted file session: %v", err)
			}
			var count int
			if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM assistance_sessions").Scan(&count); err != nil || count != 0 {
				t.Fatalf("unauthorized file session was persisted: count=%d err=%v", count, err)
			}
		})
	}
}

func TestAssistanceFilesViewWithoutControlCompletesAndCancels(t *testing.T) {
	f, observation := offeredAssistanceFiles(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW)
	joined, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: observation.SessionId}))
	if err != nil || joined.Msg.GetSession().GetControlGranted() {
		t.Fatalf("view and files required or granted input control: %v", err)
	}
	activateAssistanceFiles(t, f, observation)
	request := testAssistanceFileRequest(observation.SessionId, 17)
	startTestAssistanceFile(t, f, request)
	directives := f.sync(t, observation)
	if len(directives) != 1 || directives[0].GetInvitation().GetMode() != agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW || directives[0].GetFileTransfer().GetCancel() || directives[0].GetFileTransfer().GetRequest().GetRequestId() != request.Transfer.RequestId {
		t.Fatal("view-only file work was not delivered without mode escalation")
	}
	observation.FileTransfer = completedTestAssistanceFile(f, request)
	f.sync(t, observation)
	if got := getTestAssistanceFile(t, f, request); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED || !proto.Equal(got.File, request.Transfer.File) {
		t.Fatal("view-only creator could not read verified file completion")
	}
	next := testAssistanceFileRequest(observation.SessionId, 1)
	startTestAssistanceFile(t, f, next)
	if got := cancelTestAssistanceFile(t, f, next); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED {
		t.Fatal("view-only creator could not cancel file work")
	}
	if session := f.get(t, observation.SessionId); session.GetControlGranted() || session.GetMode() != agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW {
		t.Fatal("file work escalated immutable view mode")
	}
}

func TestAssistanceFilesFreshGrantLossFencesNegotiationRPCsAndSync(t *testing.T) {
	for _, test := range []struct {
		role string
		mode agentv1.AssistanceMode
		code connect.Code
	}{
		{"files-only", agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, connect.CodePermissionDenied},
		{"view-only", agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, connect.CodeNotFound},
		{"control-files", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodePermissionDenied},
		{"view-files", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodePermissionDenied},
		{"view-control", agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, connect.CodeNotFound},
	} {
		for _, phase := range []agentv1.AssistancePhase{agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED, agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE} {
			t.Run(test.mode.String()+"/"+test.role+"/"+phase.String(), func(t *testing.T) {
				f, observation := offeredAssistanceFiles(t, test.mode)
				request := testAssistanceFileRequest(observation.SessionId, 17)
				if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
					activateAssistanceFiles(t, f, observation)
					startTestAssistanceFile(t, f, request)
				}
				// Keep the cached administrator principal: fresh grants alone
				// must fence every path, using the immutable session row mode.
				setAssistanceRole(t, f, test.role)
				if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED {
					if _, err := f.svc.JoinAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.JoinAssistanceSessionRequest{SessionId: observation.SessionId})); connect.CodeOf(err) != test.code {
						t.Fatalf("lost grant joined file session: %v", err)
					}
					if _, err := f.svc.AnswerAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.AnswerAssistanceSessionRequest{SessionId: observation.SessionId, AnswerSdp: f.sdp(strings.ReplaceAll(testFingerprint, "AB", "CD"))})); connect.CodeOf(err) != test.code {
						t.Fatalf("lost grant answered file session: %v", err)
					}
				} else {
					for _, start := range []*adminv1.StartAssistanceFileTransferRequest{request, testAssistanceFileRequest(observation.SessionId, 1)} {
						if _, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(start)); connect.CodeOf(err) != test.code {
							t.Fatalf("lost grant admitted or replayed file work: %v", err)
						}
					}
					if _, err := f.svc.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); connect.CodeOf(err) != test.code {
						t.Fatalf("lost grant polled file metadata: %v", err)
					}
					if _, err := f.svc.CancelAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.CancelAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); connect.CodeOf(err) != test.code {
						t.Fatalf("lost grant cancelled file work: %v", err)
					}
					observation.FileTransfer = completedTestAssistanceFile(f, request)
				}
				directives := f.sync(t, observation)
				if len(directives) != 1 || !directives[0].GetTerminate() || directives[0].GetFileTransfer() != nil {
					t.Fatal("lost grant retained live file or session authority")
				}
				if session := f.get(t, observation.SessionId); session.GetMode() != test.mode || session.GetEndCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
					t.Fatal("grant loss changed immutable mode or failed to end authority")
				}
				if phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE {
					operation, err := devicedb.New(f.svc.Pool).GetAssistanceFileTransfer(f.ctx, uuid.MustParse(request.Transfer.RequestId))
					if err != nil || operation.State != int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED) || operation.ReservedBytes != 17 {
						t.Fatalf("late completion revived or refunded revoked work: %v", err)
					}
				}
			})
		}
	}
}

func TestAssistanceFilesModeScopesMustIntersect(t *testing.T) {
	f := newAssistanceFixture(t, 0)
	q := devicedb.New(f.svc.Pool)
	policy := &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, FileLimits: testAssistanceFilePolicy()}
	for _, permission := range []identity.Permission{identity.PermissionViewRemoteAssistance, identity.PermissionControlRemoteAssistance, identity.PermissionAssistanceFiles} {
		t.Run(string(permission), func(t *testing.T) {
			principal := identity.Principal{Bindings: []*authv1.RoleBinding{
				{Permissions: []string{string(identity.PermissionViewRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}},
				{Permissions: []string{string(identity.PermissionControlRemoteAssistance)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}},
				{Permissions: []string{string(identity.PermissionAssistanceFiles)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{f.deviceID}}}},
			}}
			for _, binding := range principal.Bindings {
				if binding.Permissions[0] == string(permission) {
					binding.Scopes[0].DeviceIds = []string{uuid.NewString()}
				}
			}
			if err := scopeAssistanceCapabilities(f.ctx, q, principal, uuid.MustParse(f.deviceID), agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, policy); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("control files borrowed another grant's scope: %v", err)
			}
			err := scopeAssistanceCapabilities(f.ctx, q, principal, uuid.MustParse(f.deviceID), agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, policy)
			if permission == identity.PermissionControlRemoteAssistance {
				if err != nil {
					t.Fatalf("view files unnecessarily required control scope: %v", err)
				}
			} else if connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("view files borrowed another grant's scope: %v", err)
			}
		})
	}
}

func TestAssistanceFilesDurableReplayCompletionAndAuditPrivacy(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := testAssistanceFileRequest(observation.SessionId, 17)
	if got := startTestAssistanceFile(t, f, request); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_REQUESTED || got.File != nil {
		t.Fatal("admission claimed receipt or exposed unverified metadata")
	}
	if got := startTestAssistanceFile(t, f, request); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_REQUESTED {
		t.Fatal("exact replay changed pending outcome")
	}
	changed := proto.CloneOf(request)
	changed.Transfer.File.Size++
	if _, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed exact identity accepted: %v", err)
	}
	if _, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(testAssistanceFileRequest(request.SessionId, 1))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("concurrent transfer admitted: %v", err)
	}
	directives := f.sync(t, observation)
	transfer := directives[0].GetFileTransfer().GetRequest()
	if transfer.GetRequestId() != request.Transfer.RequestId || transfer.GetDeadline() == nil || transfer.GetDeadline().AsTime().After(f.now.Add(5*time.Minute)) || transfer.GetPolicy() == nil {
		t.Fatal("missing server-stamped operation authority")
	}
	if !proto.Equal(transfer.GetFile(), request.Transfer.File) {
		t.Fatal("authorized file identity changed")
	}
	observation.FileTransfer = completedTestAssistanceFile(f, request)
	// Unknown wire fields must not become a covert persistent content channel.
	observation.FileTransfer.ProtoReflect().SetUnknown([]byte{0xa2, 0x06, 0x03, 'b', 'a', 'd'})
	directives = f.sync(t, observation)
	if !directives[0].GetFileTransfer().GetCancel() {
		t.Fatal("completed work was reissued")
	}
	got := getTestAssistanceFile(t, f, request)
	if got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED || !proto.Equal(got.File, request.Transfer.File) || len(got.ProtoReflect().GetUnknown()) != 0 {
		t.Fatal("verified metadata was not durably projected")
	}
	if replay := startTestAssistanceFile(t, f, request); !proto.Equal(replay, got) {
		t.Fatal("completion replay changed outcome")
	}
	f.sync(t, observation)
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.file.complete'", request.SessionId).Scan(&count); err != nil || count != 1 {
		t.Fatalf("completion audit not exact once: %d %v", count, err)
	}
	var actor, target, reason string
	var details map[string]string
	if err := f.conn.QueryRow(f.ctx, "SELECT actor_id::text, target_device_id::text, reason, details FROM audit_events WHERE resource_id=$1 AND action='assistance.file.complete'", request.SessionId).Scan(&actor, &target, &reason, &details); err != nil {
		t.Fatal(err)
	}
	if actor != f.creator.ID.String() || target != f.deviceID || reason != "" || details["request"] != request.Transfer.RequestId || details["bytes"] != "17" || details["reason"] != "receiver_verified" || details["sha256"] != strings.Repeat("00", 32) || details["direction"] != "operator_to_user" {
		t.Fatalf("typed file audit metadata missing: %v", details)
	}
	for _, value := range details {
		if strings.Contains(value, request.Transfer.File.Name) {
			t.Fatal("file basename entered audit")
		}
	}
	var projection []byte
	if err := f.conn.QueryRow(f.ctx, "SELECT capability_projection FROM assistance_sessions WHERE id=$1", request.SessionId).Scan(&projection); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(projection, []byte(request.Transfer.File.Name)) {
		t.Fatal("file metadata leaked through fleet-readable projection")
	}
}

func TestAssistanceFilesSharedRuntimeAcrossServices(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	admin := separateAssistanceService(t, f, f.svc.runtime)
	if admin.Service == f.svc.Service || admin.Pool == f.svc.Pool {
		t.Fatal("file admission and device sync share a SQL core or pool")
	}
	request := testAssistanceFileRequest(observation.GetSessionId(), 17)
	accepted, err := admin.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
	if err != nil || accepted.Msg.GetTransfer().GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_REQUESTED || accepted.Msg.GetTransfer().GetFile() != nil {
		t.Fatalf("admission claimed completion: %v", err)
	}
	get := &adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId}
	pending, err := admin.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(get))
	if err != nil || pending.Msg.GetTransfer().GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_REQUESTED {
		t.Fatalf("creator could not poll admission: %v", err)
	}
	directives := f.sync(t, observation)
	if len(directives) != 1 || directives[0].GetFileTransfer().GetCancel() || directives[0].GetFileTransfer().GetRequest().GetRequestId() != request.Transfer.RequestId {
		t.Fatal("admin file admission did not reach device service")
	}
	observation.FileTransfer = completedTestAssistanceFile(f, request)
	if got := f.sync(t, observation); len(got) != 1 || !got[0].GetFileTransfer().GetCancel() {
		t.Fatal("device completion retained live file work")
	}
	result, err := admin.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(get))
	if err != nil || result.Msg.GetTransfer().GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED || !proto.Equal(result.Msg.GetTransfer().GetFile(), request.Transfer.File) {
		t.Fatalf("device completion metadata did not return to creator: %v", err)
	}
	if _, err := admin.GetAssistanceFileTransfer(f.otherCtx, connect.NewRequest(get)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("completion metadata disclosed to another operator: %v", err)
	}
	replayed, err := admin.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(replayed.Msg.GetTransfer(), result.Msg.GetTransfer()) {
		t.Fatalf("cross-service completion replay changed outcome: %v", err)
	}
}

func TestAssistanceFilesSeparateRuntimeCancelsOldWork(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	admin := separateAssistanceService(t, f, NewRuntime())
	request := testAssistanceFileRequest(observation.GetSessionId(), 7)
	file := request.Transfer.File
	request.Transfer.Direction, request.Transfer.File = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil
	if _, err := admin.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	directives := f.sync(t, observation)
	if len(directives) != 1 || !directives[0].GetFileTransfer().GetCancel() || directives[0].GetFileTransfer().GetRequest().GetRequestId() != request.Transfer.RequestId {
		t.Fatal("device service executed work from another process incarnation")
	}
	observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.Transfer.RequestId, Direction: request.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, BytesTransferred: file.Size, File: file, CompletedAt: timestamppb.New(f.now)}
	f.sync(t, observation)
	get := &adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId}
	result, err := admin.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(get))
	if err != nil || result.Msg.GetTransfer().GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED || result.Msg.GetTransfer().GetReason() != "file_outcome_unknown" || result.Msg.GetTransfer().GetFile() != nil {
		t.Fatalf("separate runtime allowed late success: %v", err)
	}
	replayed, err := admin.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(replayed.Msg.GetTransfer(), result.Msg.GetTransfer()) {
		t.Fatalf("original runtime resurrected cancelled work: %v", err)
	}
	quota, err := devicedb.New(admin.Pool).AssistanceFileQuota(f.ctx, uuid.MustParse(request.SessionId))
	if err != nil || quota.Requests != 1 || quota.ReservedBytes != 16<<20 {
		t.Fatalf("separate runtime refunded uncertain work: %v", err)
	}
}

func TestAssistanceFilesCreatorRoleScopeAndFreshAuthority(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := testAssistanceFileRequest(observation.SessionId, 1)
	startTestAssistanceFile(t, f, request)
	helpdesk := identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, f.conn, identity.RoleHelpdesk))
	for _, actor := range []context.Context{f.otherCtx, helpdesk} {
		if _, err := f.svc.StartAssistanceFileTransfer(actor, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("noncreator/role start admitted: %v", err)
		}
		if _, err := f.svc.GetAssistanceFileTransfer(actor, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("noncreator/role disclosure admitted: %v", err)
		}
		if _, err := f.svc.CancelAssistanceFileTransfer(actor, connect.NewRequest(&adminv1.CancelAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("noncreator/role cancel admitted: %v", err)
		}
	}
	principal := identity.Principal{ID: f.creator.ID, Bindings: []*authv1.RoleBinding{
		{Permissions: []string{string(identity.PermissionViewRemoteAssistance)}},
		{Permissions: []string{string(identity.PermissionAssistanceFiles)}, Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}},
	}}
	q := devicedb.New(f.svc.Pool)
	if err := scopeAssistanceCapabilities(f.ctx, q, principal, uuid.MustParse(f.deviceID), agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, FileLimits: testAssistanceFilePolicy()}); err == nil {
		t.Fatal("view scope widened files scope")
	}
	principal.Bindings[1].Scopes[0].DeviceIds = []string{f.deviceID}
	if err := scopeAssistanceCapabilities(f.ctx, q, principal, uuid.MustParse(f.deviceID), agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, &agentv1.AssistancePolicy{Files: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, FileLimits: testAssistanceFilePolicy()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(f.ctx, `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes', jsonb_build_array(jsonb_build_object('deviceIds', jsonb_build_array($2::text)))) WHERE id=$1`, f.creator.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); err == nil {
		t.Fatal("cached principal disclosed after fresh scope loss")
	}
	if got := f.sync(t, observation); !got[0].GetTerminate() || got[0].GetFileTransfer() != nil {
		t.Fatal("scope loss retained file authority")
	}
	var state int16
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM assistance_file_transfers WHERE request_id=$1", request.Transfer.RequestId).Scan(&state); err != nil || state != int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED) {
		t.Fatalf("revocation retained pending transfer: %v", err)
	}
}

func TestAssistanceFilesCancellationCannotRefundQuota(t *testing.T) {
	for _, download := range []bool{false, true} {
		t.Run(map[bool]string{false: "request count", true: "reserved bytes"}[download], func(t *testing.T) {
			f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
			limit := 32
			if download {
				limit = 4
			}
			for range limit {
				request := testAssistanceFileRequest(observation.SessionId, 0)
				if download {
					request.Transfer.Direction, request.Transfer.File = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil
				}
				startTestAssistanceFile(t, f, request)
				if got := cancelTestAssistanceFile(t, f, request); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED {
					t.Fatal("cancel failed")
				}
				cancelTestAssistanceFile(t, f, request)
			}
			_, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(testAssistanceFileRequest(observation.SessionId, 0)))
			wantReason(t, err, connect.CodeResourceExhausted, "assistance_file_quota")
		})
	}
}

func TestAssistanceFilesRestartDeadlineAndCancellationFenceLateSuccess(t *testing.T) {
	for _, cause := range []string{"restart", "deadline", "cancel"} {
		t.Run(cause, func(t *testing.T) {
			f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
			request := testAssistanceFileRequest(observation.SessionId, 1)
			startTestAssistanceFile(t, f, request)
			switch cause {
			case "restart":
				f.svc.fixtureAssistance = separateAssistanceService(t, f, NewRuntime())
			case "deadline":
				f.advance(time.Second)
				if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_file_transfers SET deadline=$2 WHERE request_id=$1", request.Transfer.RequestId, f.now); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancelTestAssistanceFile(t, f, request)
			}
			observation.FileTransfer = completedTestAssistanceFile(f, request)
			if got := f.sync(t, observation); !got[0].GetFileTransfer().GetCancel() {
				t.Fatal("uncertain/expired operation reissued")
			}
			if got := getTestAssistanceFile(t, f, request); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED || got.File != nil {
				t.Fatal("late success resurrected operation")
			}
			if got := startTestAssistanceFile(t, f, request); got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED {
				t.Fatal("exact replay re-executed uncertain operation")
			}
		})
	}
}

func TestAssistanceFilesInvalidReportsEndAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*agentv1.AssistanceFileReport)
	}{
		{"wrong digest", func(r *agentv1.AssistanceFileReport) { r.File.Sha256[0]++ }},
		{"wrong size", func(r *agentv1.AssistanceFileReport) { r.File.Size++; r.BytesTransferred++ }},
		{"wrong identity", func(r *agentv1.AssistanceFileReport) { r.RequestId = uuid.NewString() }},
		{"wrong direction", func(r *agentv1.AssistanceFileReport) {
			r.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
		}},
		{"wrong type", func(r *agentv1.AssistanceFileReport) { r.File.MimeType = "image/png" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
			request := testAssistanceFileRequest(observation.SessionId, 1)
			startTestAssistanceFile(t, f, request)
			observation.FileTransfer = completedTestAssistanceFile(f, request)
			tc.change(observation.FileTransfer)
			if got := f.sync(t, observation); !got[0].GetTerminate() {
				t.Fatal("invalid file report preserved authority")
			}
			var count int
			if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.file.complete'", observation.SessionId).Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid receipt manufactured completion: %v", err)
			}
		})
	}
}

func TestAssistanceFilesPolicyGrantAndRevocation(t *testing.T) {
	for _, mode := range []agentv1.AssistancePolicyMode{agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED} {
		grant := allAssistanceCapabilities()
		grant.Files = mode
		if mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
			grant.FileLimits = nil
		}
		f, observation := activeAssistanceCapabilities(t, grant)
		request := testAssistanceFileRequest(observation.SessionId, 1)
		request.Transfer.Direction, request.Transfer.File = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil
		_, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
		wantReason(t, err, connect.CodeFailedPrecondition, "assistance_files_not_granted")
	}
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := testAssistanceFileRequest(observation.SessionId, 1)
	startTestAssistanceFile(t, f, request)
	policy := allAssistanceCapabilities()
	policy.FileLimits.MaxFileBytes = 1
	if _, err := f.svc.UpdateAssistancePolicy(f.creatorCtx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, Policy: policy})); err != nil {
		t.Fatal(err)
	}
	observation.FileTransfer = completedTestAssistanceFile(f, request)
	if got := f.sync(t, observation); !got[0].GetTerminate() || got[0].GetFileTransfer() != nil {
		t.Fatal("narrowed file policy retained authority")
	}
	if _, err := f.svc.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); err == nil {
		t.Fatal("revoked policy disclosed transfer metadata")
	}
}

func TestAssistanceFilesInputEpochProjectionAndTerminalPause(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 2, Paused: true}
	f.sync(t, observation)
	if got := f.get(t, observation.SessionId).GetInputState(); got.GetEpoch() != 2 || !got.GetPaused() {
		t.Fatal("modal input pause not projected")
	}
	_, err := f.svc.RunAssistanceCommand(f.creatorCtx, connect.NewRequest(commandRequest(observation.SessionId, agentv1.AssistanceCommandKind_ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ, "")))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_input_paused")
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 3}
	f.sync(t, observation)
	observation.InputState = &agentv1.AssistanceInputState{Epoch: 5}
	f.sync(t, observation)
	if got := f.get(t, observation.SessionId).GetInputState(); got.GetEpoch() != 5 || got.GetPaused() {
		t.Fatal("coalesced modal epoch not accepted")
	}
	observation.InputState.Epoch = 4
	if got := f.sync(t, observation); !got[0].GetTerminate() {
		t.Fatal("regressed input epoch retained authority")
	}
	if got := f.get(t, observation.SessionId).GetInputState(); !got.GetPaused() || got.GetEpoch() != 5 {
		t.Fatal("terminal cleanup resumed stale input")
	}
}

func TestAssistanceFilesDownloadReceiptAndRemainingQuota(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	for range 5 {
		request := testAssistanceFileRequest(observation.SessionId, 7)
		file := request.Transfer.File
		request.Transfer.Direction, request.Transfer.File = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil
		startTestAssistanceFile(t, f, request)
		observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.Transfer.RequestId, Direction: request.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, BytesTransferred: file.Size, File: file, CompletedAt: timestamppb.New(f.now)}
		f.sync(t, observation)
		if got := getTestAssistanceFile(t, f, request); !proto.Equal(got.File, file) || got.State != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED {
			t.Fatal("outgoing verified receipt not recorded")
		}
		operation, err := devicedb.New(f.svc.Pool).GetAssistanceFileTransfer(f.ctx, uuid.MustParse(request.Transfer.RequestId))
		if err != nil || operation.ReservedBytes != 7 {
			t.Fatalf("verified success did not settle actual bytes: %v", err)
		}
	}
	next := testAssistanceFileRequest(observation.SessionId, 1)
	startTestAssistanceFile(t, f, next)
	directives := f.sync(t, observation)
	if got := directives[0].GetFileTransfer().GetRequest(); got.GetRequestId() != next.Transfer.RequestId || got.GetPolicy().GetMaxSessionBytes() != 64<<20-35 {
		t.Fatal("multiple verified downloads did not consume only actual bytes")
	}
}

func TestAssistanceFilesAdmissionValidationAndSessionDeadline(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	base := testAssistanceFileRequest(observation.SessionId, 1)
	for _, change := range []func(*adminv1.StartAssistanceFileTransferRequest){
		func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Name = "../private.txt" },
		func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Sha256 = nil },
		func(r *adminv1.StartAssistanceFileTransferRequest) {
			r.Transfer.Deadline = timestamppb.New(f.now.Add(time.Hour))
		},
		func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.Policy = testAssistanceFilePolicy() },
	} {
		request := proto.CloneOf(base)
		change(request)
		_, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
		wantReason(t, err, connect.CodeInvalidArgument, "invalid_assistance_file")
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM assistance_file_transfers WHERE session_id=$1", observation.SessionId).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid metadata reached persistence: %v", err)
	}
	end := f.now.Add(time.Minute)
	if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_sessions SET ends_at=$2 WHERE id=$1", observation.SessionId, end); err != nil {
		t.Fatal(err)
	}
	startTestAssistanceFile(t, f, base)
	directives := f.sync(t, observation)
	if !directives[0].GetFileTransfer().GetRequest().GetDeadline().AsTime().Equal(end) {
		t.Fatal("file deadline outlived session")
	}
}

func TestAssistanceFilesReportsCannotManufactureGrantsOrResumeEpoch(t *testing.T) {
	for _, capability := range []bool{false, true} {
		f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
		if capability {
			observation.GrantedCapabilities.Policy.FileLimits.MaxFileBytes--
		} else {
			observation.InputState.Paused = true
		}
		if got := f.sync(t, observation); !got[0].GetTerminate() {
			t.Fatal("report changed established grant or pause within an epoch")
		}
	}
}

func TestAssistanceFilesDeviceRevocationFencesDisclosure(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	request := testAssistanceFileRequest(observation.SessionId, 1)
	startTestAssistanceFile(t, f, request)
	if _, err := f.conn.Exec(f.ctx, "UPDATE devices SET state=$2, revoked_at=clock_timestamp(), revoked_by=$3, revoke_reason='assistance file disclosure fence' WHERE id=$1", f.deviceID, core.StateRevoked, f.creator.ID); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId}))
	wantReason(t, err, connect.CodeFailedPrecondition, "assistance_device_authority_lost")
	var state int16
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM assistance_file_transfers WHERE request_id=$1", request.Transfer.RequestId).Scan(&state); err != nil || state != int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED) {
		t.Fatalf("device revocation retained active file operation: %v", err)
	}
}

func TestAssistanceFilesMalformedAdmissionAuditIsContentFree(t *testing.T) {
	f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
	for _, change := range []func(*adminv1.StartAssistanceFileTransferRequest){
		func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Name = "../private-source.txt" },
		func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.Size = 16<<20 + 1 },
		func(r *adminv1.StartAssistanceFileTransferRequest) { r.Transfer.File.MimeType = "invalid content type" },
	} {
		request := testAssistanceFileRequest(observation.SessionId, 1)
		change(request)
		_, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
		wantReason(t, err, connect.CodeInvalidArgument, "invalid_assistance_file")
		var actor, target, reason, resource string
		var details map[string]string
		if err := f.conn.QueryRow(f.ctx, "SELECT actor_id::text, target_device_id::text, resource_id, reason, details FROM audit_events WHERE action='assistance.file.deny' AND details->>'request'=$1", request.Transfer.RequestId).Scan(&actor, &target, &resource, &reason, &details); err != nil {
			t.Fatal(err)
		}
		if actor != f.creator.ID.String() || target != f.deviceID || resource != observation.SessionId || reason != "" || details["reason"] != "invalid_assistance_file" || details["result"] != "denied" || len(details) != 3 {
			t.Fatalf("malformed request audit lost typed identity or included payload: %v", details)
		}
		for _, value := range details {
			if strings.Contains(value, "private-source") || strings.Contains(value, "invalid content type") {
				t.Fatal("malformed content entered denial audit")
			}
		}
	}
	request := testAssistanceFileRequest(uuid.NewString(), 1)
	request.Transfer.File.Name = "../private-source.txt"
	_, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
	wantReason(t, err, connect.CodeInvalidArgument, "invalid_assistance_file")
	var target *uuid.UUID
	if err := f.conn.QueryRow(f.ctx, "SELECT target_device_id FROM audit_events WHERE action='assistance.file.deny' AND details->>'request'=$1", request.Transfer.RequestId).Scan(&target); err != nil || target != nil {
		t.Fatalf("unknown session fabricated a target: %v", err)
	}
	for _, invalidID := range []string{"not-a-uuid", uuid.Nil.String()} {
		request.Transfer.RequestId = invalidID
		if _, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatal("malformed identity admitted")
		}
	}
	request.Transfer.RequestId, request.SessionId = uuid.NewString(), "unparseable-session"
	if _, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("malformed session admitted")
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='assistance.file.deny'").Scan(&count); err != nil || count != 4 {
		t.Fatalf("unparseable identities generated denial rows: count=%d err=%v", count, err)
	}
}

func TestAssistanceFilesLatePublicationWarningSurvivesCancellationAndEnd(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
		request := testAssistanceFileRequest(observation.SessionId, 17)
		startTestAssistanceFile(t, f, request)
		cancelTestAssistanceFile(t, f, request)
		if stopped {
			if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: observation.SessionId})); err != nil {
				t.Fatal(err)
			}
		}
		observation.Phase, observation.EndCause = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED
		observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.Transfer.RequestId, Direction: request.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, BytesTransferred: 17, File: proto.CloneOf(request.Transfer.File), Reason: "file_published_unconfirmed", CompletedAt: timestamppb.New(f.now)}
		for range 2 {
			directives := f.sync(t, observation)
			if len(directives) != 0 && (!directives[0].GetTerminate() || directives[0].GetFileTransfer() != nil) {
				t.Fatal("late warning reopened transfer authority")
			}
		}
		operation, err := devicedb.New(f.svc.Pool).GetAssistanceFileTransfer(f.ctx, uuid.MustParse(request.Transfer.RequestId))
		if err != nil {
			t.Fatal(err)
		}
		warning, err := assistanceFileReport(operation)
		if err != nil || warning.GetState() != agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED || warning.GetReason() != "file_published_unconfirmed" || !proto.Equal(warning.GetFile(), request.Transfer.File) || operation.ReservedBytes != 17 {
			t.Fatalf("publication warning lost or reservation changed: %v %v", warning, err)
		}
		var count int
		if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.file.deny' AND details->>'reason'='file_published_unconfirmed'", observation.SessionId).Scan(&count); err != nil || count != 1 {
			t.Fatalf("late warning audit not exact once: %d %v", count, err)
		}
		var details map[string]string
		if err := f.conn.QueryRow(f.ctx, "SELECT details FROM audit_events WHERE resource_id=$1 AND action='assistance.file.deny' AND details->>'reason'='file_published_unconfirmed'", observation.SessionId).Scan(&details); err != nil {
			t.Fatal(err)
		}
		if details["sha256_origin"] != "receiver_verified" || details["sha256"] != strings.Repeat("00", 32) || details["authorized_sha256"] != details["sha256"] || details["result"] != "failed" {
			t.Fatalf("publication warning confused verified and authorized digests: %v", details)
		}
		for _, value := range details {
			if strings.Contains(value, request.Transfer.File.Name) {
				t.Fatal("publication warning audit disclosed basename")
			}
		}
		if _, err := f.svc.GetAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(&adminv1.GetAssistanceFileTransferRequest{SessionId: request.SessionId, RequestId: request.Transfer.RequestId})); err == nil {
			t.Fatal("late warning enabled historical file disclosure")
		}
	}
}

func TestAssistanceFilesLatePublicationWarningRequiresExactVerifiedMetadata(t *testing.T) {
	for _, change := range []func(*agentv1.AssistanceFileReport){
		func(r *agentv1.AssistanceFileReport) { r.File.Sha256[0]++ },
		func(r *agentv1.AssistanceFileReport) { r.File.Name = "other.txt" },
		func(r *agentv1.AssistanceFileReport) { r.File.Size++; r.BytesTransferred++ },
		func(r *agentv1.AssistanceFileReport) { r.File.MimeType = "image/png" },
		func(r *agentv1.AssistanceFileReport) { r.RequestId = uuid.NewString() },
	} {
		f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
		request := testAssistanceFileRequest(observation.SessionId, 1)
		startTestAssistanceFile(t, f, request)
		if _, err := f.svc.StopAssistanceSession(f.creatorCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: observation.SessionId})); err != nil {
			t.Fatal(err)
		}
		observation.Phase, observation.EndCause = agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED
		observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.Transfer.RequestId, Direction: request.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, BytesTransferred: 1, File: proto.CloneOf(request.Transfer.File), Reason: "file_published_unconfirmed", CompletedAt: timestamppb.New(f.now)}
		change(observation.FileTransfer)
		f.sync(t, observation)
		operation, err := devicedb.New(f.svc.Pool).GetAssistanceFileTransfer(f.ctx, uuid.MustParse(request.Transfer.RequestId))
		if err != nil || operation.State != int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED) {
			t.Fatalf("mismatched late publication report changed outcome: %v", err)
		}
		var count int
		if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND details->>'reason'='file_published_unconfirmed'", observation.SessionId).Scan(&count); err != nil || count != 0 {
			t.Fatalf("mismatched report manufactured publication audit: %v", err)
		}
	}
}

func TestAssistanceFilesUncertainDownloadsKeepFullReservation(t *testing.T) {
	for _, outcome := range []string{"failed", "restart", "cancel_then_late_success"} {
		t.Run(outcome, func(t *testing.T) {
			f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
			request := testAssistanceFileRequest(observation.SessionId, 7)
			file := request.Transfer.File
			request.Transfer.Direction, request.Transfer.File = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER, nil
			startTestAssistanceFile(t, f, request)
			observation.FileTransfer = &agentv1.AssistanceFileReport{RequestId: request.Transfer.RequestId, Direction: request.Transfer.Direction, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED, File: file, BytesTransferred: 7, CompletedAt: timestamppb.New(f.now)}
			switch outcome {
			case "failed":
				observation.FileTransfer.State, observation.FileTransfer.File, observation.FileTransfer.Reason = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, nil, "transport_lost"
			case "restart":
				f.svc.fixtureAssistance = separateAssistanceService(t, f, NewRuntime())
			case "cancel_then_late_success":
				cancelTestAssistanceFile(t, f, request)
			}
			f.sync(t, observation)
			operation, err := devicedb.New(f.svc.Pool).GetAssistanceFileTransfer(f.ctx, uuid.MustParse(request.Transfer.RequestId))
			if err != nil || operation.ReservedBytes != 16<<20 || operation.State == int16(agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED) {
				t.Fatalf("unverified outcome refunded reservation: %v", err)
			}
			next := testAssistanceFileRequest(observation.SessionId, 1)
			startTestAssistanceFile(t, f, next)
			if got := f.sync(t, observation)[0].GetFileTransfer().GetRequest().GetPolicy().GetMaxSessionBytes(); got != 48<<20 {
				t.Fatalf("uncertain reservation disappeared from next snapshot: %d", got)
			}
		})
	}
}

func TestAssistanceUnsafeFileNamesFailBeforeDurableAdmission(t *testing.T) {
	for _, name := range []string{".notes.txt", "\u00a0notes.txt", "notes\u202e.txt"} {
		t.Run(name, func(t *testing.T) {
			f, observation := activeAssistanceCapabilities(t, allAssistanceCapabilities())
			request := testAssistanceFileRequest(observation.GetSessionId(), 1)
			request.Transfer.File.Name = name
			_, err := f.svc.StartAssistanceFileTransfer(f.creatorCtx, connect.NewRequest(request))
			wantReason(t, err, connect.CodeFailedPrecondition, "assistance_file_policy")
			var count int
			if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM assistance_file_transfers WHERE session_id=$1", observation.GetSessionId()).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 || f.get(t, observation.GetSessionId()).GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE {
				t.Fatal("unsafe basename allocated authority or ended the live session")
			}
			for _, directive := range f.sync(t, observation) {
				if directive.GetFileTransfer() != nil || directive.GetTerminate() {
					t.Fatal("unsafe basename escaped to the root broker")
				}
			}
		})
	}
}
