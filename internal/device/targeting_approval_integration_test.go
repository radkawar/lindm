//go:build integration

package device

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestTargetPreviewActivationRequiresBoundApproval(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	authority, err := identity.New(ctx, pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{ApprovalRequiredPermissions: []string{string(identity.PermissionAssignResources)}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	ca, key := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: authority}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	deviceKey := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, deviceKey)
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, ctx, svc, principal, deviceKey, 0)
	if _, err := svc.ReportHostObservation(core.WithDevicePrincipal(ctx, principal), connect.NewRequest(hostObservation(enrolled.Msg.GetEnrollmentGeneration(), 1, "preview-device"))); err != nil {
		t.Fatal(err)
	}
	preview, err := svc.PreviewTargetAssignments(ownerCtx, connect.NewRequest(&adminv1.PreviewTargetAssignmentsRequest{DeviceId: enrolled.Msg.GetDeviceId()}))
	if err != nil {
		t.Fatal(err)
	}
	request := &adminv1.ActivateTargetPreviewRequest{
		RequestId: uuid.NewString(), DeviceId: enrolled.Msg.GetDeviceId(),
		PreviewId: preview.Msg.GetPreview().GetPreviewId(), PreviewSha256: preview.Msg.GetPreview().GetPreviewSha256(),
		Reason: "activate reviewed resource target preview",
	}
	if _, err := svc.ActivateTargetPreview(ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("preview activation bypassed configured resource approval: %v", err)
	}
	badRequest := proto.CloneOf(request)
	badRequest.RequestId = uuid.NewString()
	badRequest.PreviewSha256[0] ^= 1
	badApproval := &adminv1.CreateApprovalRequest{
		LifetimeSeconds: 600,
		Payload:         &adminv1.CreateApprovalRequest_ActivateTargetPreview{ActivateTargetPreview: badRequest},
	}
	if _, err := svc.CreateApproval(ownerCtx, connect.NewRequest(badApproval)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("wrong preview digest was not rejected before commit: %v", err)
	}
	listed, err := svc.ListApprovals(ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil || len(listed.Msg.GetApprovals()) != 0 {
		t.Fatalf("rejected preview binding left an approval record: %v %v", listed, err)
	}
	// Model a historical record created before preview-binding validation. It
	// must remain listable, but cannot acquire valid optional evidence.
	historical, err := authority.CreateApproval(ownerCtx, owner.ID, badApproval, svc.RecoveryReadinessApprovalScope(nil))
	if err != nil {
		t.Fatal(err)
	}
	listed, err = svc.ListApprovals(ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatalf("historical mismatched binding poisoned approval inbox: %v", err)
	}
	if len(listed.Msg.GetApprovals()) != 1 || listed.Msg.GetApprovals()[0].GetId() != historical.GetId() || listed.Msg.GetApprovals()[0].GetTargetPreview() != nil {
		t.Fatal("historical mismatched binding was presented as valid evidence")
	}
	created, err := svc.CreateApproval(ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{
		LifetimeSeconds: 600,
		Payload:         &adminv1.CreateApprovalRequest_ActivateTargetPreview{ActivateTargetPreview: request},
	}))
	if err != nil {
		t.Fatal(err)
	}
	approval := created.Msg.GetApproval()
	if approval.GetAction() != "resources.activate_preview" || approval.GetActivateTargetPreview() == nil || approval.GetDeviceId() != request.GetDeviceId() {
		t.Fatalf("approval lost activation action or device binding: %v", approval)
	}
	if !proto.Equal(approval.GetTargetPreview(), preview.Msg.GetPreview()) {
		t.Fatal("created approval omitted exact retained evidence")
	}
	listed, err = svc.ListApprovals(ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if listed.Msg.GetCurrentPrincipalId() != owner.ID.String() {
		t.Fatal("approval list omitted authenticated requester identity")
	}
	request.ApprovalId = proto.String(approval.GetId())
	if _, err := svc.ActivateTargetPreview(ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("pending approval authorized preview activation: %v", err)
	}
	if _, err := svc.ApproveApproval(approvalReviewer(t, svc, ctx), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "reviewed exact device preview"})); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*adminv1.ActivateTargetPreviewRequest)
	}{
		{"device", func(r *adminv1.ActivateTargetPreviewRequest) { r.DeviceId = uuid.NewString() }},
		{"preview", func(r *adminv1.ActivateTargetPreviewRequest) { r.PreviewId = uuid.NewString() }},
		{"digest", func(r *adminv1.ActivateTargetPreviewRequest) { r.PreviewSha256[0] ^= 1 }},
		{"request", func(r *adminv1.ActivateTargetPreviewRequest) { r.RequestId = uuid.NewString() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.CloneOf(request)
			test.change(changed)
			if _, err := svc.ActivateTargetPreview(ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("changed activation reused approval: %v", err)
			}
		})
	}
	var state string
	if err := conn.QueryRow(ctx, "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&state); err != nil || state != "approved" {
		t.Fatalf("rejected activation consumed approval: state=%s err=%v", state, err)
	}
	if _, err := svc.ActivateTargetPreview(ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	resourceState, err := svc.GetDeviceResourceState(ownerCtx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: request.GetDeviceId()}))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(resourceState.Msg.GetActiveTargetPreview(), preview.Msg.GetPreview()) {
		t.Fatal("resource state did not project the exact retained active target preview")
	}
	if err := conn.QueryRow(ctx, "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&state); err != nil || state != "consumed" {
		t.Fatalf("approved activation did not consume approval: state=%s err=%v", state, err)
	}
	if _, err := svc.ActivateTargetPreview(ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("exact approved activation retry: %v", err)
	}
}
