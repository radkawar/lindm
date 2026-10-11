//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
)

func TestAdvisoryApprovalRejectsChangedHumanAuthority(t *testing.T) {
	for _, changed := range []string{"requester", "reviewer"} {
		t.Run(changed, func(t *testing.T) {
			f, request := advisoryAcceptanceFixture(t)
			reviewer := approvalReviewer(t, f.svc, f.ctx)
			created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_AcceptAdvisoryFinding{AcceptAdvisoryFinding: request}}))
			if err != nil {
				t.Fatal(err)
			}
			request.ApprovalId = created.Msg.GetApproval().GetId()
			if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: request.ApprovalId, Reason: "Review temporary risk acceptance"})); err != nil {
				t.Fatal(err)
			}
			actor, _ := identity.PrincipalFromContext(f.ownerCtx)
			if changed == "reviewer" {
				actor, _ = identity.PrincipalFromContext(reviewer)
			}
			if _, err := f.conn.Exec(f.ctx, "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", actor.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.AcceptAdvisoryFinding(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("changed %s authority accepted: %v", changed, err)
			}
			var count int
			if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM advisory_exceptions").Scan(&count); err != nil || count != 0 {
				t.Fatalf("denied mutation committed exception: %d %v", count, err)
			}
		})
	}
}
