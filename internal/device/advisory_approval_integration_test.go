//go:build integration

package device

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

func TestAdvisoryExceptionRequiresExactIndependentApproval(t *testing.T) {
	f, request := advisoryAcceptanceFixture(t)
	authority, err := identity.New(f.ctx, f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{ApprovalRequiredPermissions: []string{string(identity.PermissionManageAdvisoryExceptions)}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	f.svc.Identity = authority
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("missing approval accepted: %v", err)
	}
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}))
	if err != nil {
		t.Fatal(err)
	}
	approval := created.Msg.GetApproval()
	if approval.GetAdvisoryFinding().GetId() != request.GetFindingId() || approval.GetAcceptAdvisoryFinding().GetReason() != request.GetReason() {
		t.Fatal("approval lost exact finding or reason")
	}
	request.ApprovalId = approval.GetId()
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("pending approval accepted: %v", err)
	}
	decision := &adminv1.ApproveApprovalRequest{ApprovalId: approval.GetId(), Reason: "Reviewed exact vulnerable package and expiry"}
	if _, err := f.svc.ApproveApproval(f.ownerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("self approval accepted: %v", err)
	}
	reviewer := approvalReviewer(t, f.svc, f.ctx)
	if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(decision)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*adminv1.AcceptAdvisoryFindingRequest)
	}{
		{"device", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.DeviceId = uuid.NewString() }},
		{"finding", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.FindingId = uuid.NewString() }},
		{"request", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.RequestId = uuid.NewString() }},
		{"reason", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.Reason = "Substituted acceptance reason" }},
		{"expiry", func(r *adminv1.AcceptAdvisoryFindingRequest) { r.ExpiresAt.Seconds++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := proto.CloneOf(request)
			test.change(changed)
			if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(changed)); err == nil {
				t.Fatal("changed payload reused approval")
			}
		})
	}
	accepted, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(accepted.Msg, replay.Msg) {
		t.Fatalf("exact retry changed result: %v", err)
	}
	var state string
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM approval_requests WHERE id=$1", approval.GetId()).Scan(&state); err != nil || state != "consumed" {
		t.Fatalf("approval not consumed: %s %v", state, err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM advisory_exceptions").Scan(&count); err != nil || count != 1 {
		t.Fatalf("exception count %d: %v", count, err)
	}
	if _, err := f.conn.Exec(f.ctx, "UPDATE approval_requests SET created_at=clock_timestamp()-interval '1 hour', expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", approval.GetId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expired approval replay accepted: %v", err)
	}
}

func TestAdvisoryApprovalConsumptionRollsBackWithInvalidExpiry(t *testing.T) {
	f, request := advisoryAcceptanceFixture(t)
	request.ExpiresAt.Seconds = time.Now().Add(-time.Hour).Unix()
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}))
	if err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	if _, err := f.svc.ApproveApproval(approvalReviewer(t, f.svc, f.ctx), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: request.ApprovalId, Reason: "Review exact request"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expired exception accepted: %v", err)
	}
	var state string
	if err := f.conn.QueryRow(f.ctx, "SELECT state FROM approval_requests WHERE id=$1", request.ApprovalId).Scan(&state); err != nil || state != "approved" {
		t.Fatalf("failed mutation consumed approval: %s %v", state, err)
	}
}
