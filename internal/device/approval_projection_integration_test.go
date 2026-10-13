//go:build integration

package device

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/identity"
)

func assertApprovalProjection(t *testing.T, approval *adminv1.Approval, requester, approver, hostname string) {
	t.Helper()
	if approval == nil {
		t.Fatal("missing approval projection")
	}
	if approval.GetRequesterDisplayName() != requester || approval.GetApproverDisplayName() != approver || approval.GetDeviceHostname() != hostname {
		t.Fatalf("approval %s labels = (%q, %q, %q), want (%q, %q, %q)", approval.GetId(), approval.GetRequesterDisplayName(), approval.GetApproverDisplayName(), approval.GetDeviceHostname(), requester, approver, hostname)
	}
}

// These tests exercise real PostgreSQL authorization and response projections.
// They never dispatch an action or claim a native device effect.
func TestApprovalProjectionLifecycle(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, test := range []struct {
		name           string
		requesterLabel string
		approverLabel  string
		approve        bool
	}{
		{"approve", "projection-requester", "projection-reviewer", true},
		{"reject", "projection-requester", "projection-reviewer", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			owner, _ := identity.PrincipalFromContext(f.ownerCtx)
			reviewerCtx := approvalReviewer(t, f.svc, t.Context())
			reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
			observerCtx := approvalReviewer(t, f.svc, t.Context())
			for _, actor := range []struct {
				id       uuid.UUID
				username string
			}{
				{owner.ID, test.requesterLabel},
				{reviewer.ID, test.approverLabel},
			} {
				if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET username=$2 WHERE id=$1", actor.id, actor.username); err != nil {
					t.Fatal(err)
				}
			}
			request := &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: f.request(restartActionSpec())}}
			created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			approval := created.Msg.GetApproval()
			assertApprovalProjection(t, approval, test.requesterLabel, "", "device-action-fixture")
			if approval.GetRequesterId() != owner.ID.String() || approval.GetApproverId() != "" || approval.GetDeviceId() != f.deviceID || approval.GetState() != adminv1.ApprovalState_APPROVAL_STATE_PENDING {
				t.Fatalf("create lost pending approval identity: %v", approval)
			}
			id := approval.GetId()
			assertList := func(ctx context.Context, requester, approver, hostname string) {
				t.Helper()
				page, err := f.svc.ListApprovals(ctx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 1}))
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Msg.GetApprovals()) != 1 || page.Msg.GetApprovals()[0].GetId() != id || page.Msg.GetNextPageToken() != "" {
					t.Fatalf("unexpected projected inbox: %v", page.Msg)
				}
				assertApprovalProjection(t, page.Msg.GetApprovals()[0], requester, approver, hostname)
			}
			assertList(f.ownerCtx, test.requesterLabel, "", "device-action-fixture")
			assertList(reviewerCtx, test.requesterLabel, "", "device-action-fixture")
			assertCreateRetry := func(requester, approver, hostname string) {
				t.Helper()
				retried, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(request))
				if err != nil {
					t.Fatal(err)
				}
				if retried.Msg.GetApproval().GetId() != id {
					t.Fatal("exact create retry replaced approval")
				}
				assertApprovalProjection(t, retried.Msg.GetApproval(), requester, approver, hostname)
			}
			assertCreateRetry(test.requesterLabel, "", "device-action-fixture")
			decide := func() *adminv1.Approval {
				t.Helper()
				if test.approve {
					response, err := f.svc.ApproveApproval(reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: id, Reason: "reviewed projection target"}))
					if err != nil {
						t.Fatal(err)
					}
					return response.Msg.GetApproval()
				}
				response, err := f.svc.RejectApproval(reviewerCtx, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: id, Reason: "reviewed projection target"}))
				if err != nil {
					t.Fatal(err)
				}
				return response.Msg.GetApproval()
			}
			decided := decide()
			assertApprovalProjection(t, decided, test.requesterLabel, test.approverLabel, "device-action-fixture")
			wantState := adminv1.ApprovalState_APPROVAL_STATE_REJECTED
			if test.approve {
				wantState = adminv1.ApprovalState_APPROVAL_STATE_APPROVED
			}
			if decided.GetId() != id || decided.GetApproverId() != reviewer.ID.String() || decided.GetState() != wantState {
				t.Fatalf("decision lost approval identity or state: %v", decided)
			}
			assertList(reviewerCtx, test.requesterLabel, test.approverLabel, "device-action-fixture")

			// Labels are current read projections, not immutable approval payloads.
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE principals SET display_name=$2 WHERE id=$1", owner.ID, "Renamed Requester"); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE principals SET display_name=$2 WHERE id=$1", reviewer.ID, "Renamed Reviewer"); err != nil {
				t.Fatal(err)
			}
			// Seed the changed hostname projection directly; a second immediate
			// host upload would legitimately hit the production inventory gate.
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE devices SET hostname=$2 WHERE id=$1", f.principal.DeviceID, "renamed-approval-host"); err != nil {
				t.Fatal(err)
			}
			// Read as a third eligible reviewer: refreshing a local actor replaces
			// its principal display name with its username.
			assertList(observerCtx, "Renamed Requester", "Renamed Reviewer", "renamed-approval-host")
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE principals SET display_name='' WHERE id IN ($1,$2)", owner.ID, reviewer.ID); err != nil {
				t.Fatal(err)
			}
			assertList(observerCtx, test.requesterLabel, test.approverLabel, "renamed-approval-host")
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET username=$2 WHERE id=$1", owner.ID, "renamed-requester"); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET username=$2 WHERE id=$1", reviewer.ID, "renamed-reviewer"); err != nil {
				t.Fatal(err)
			}
			// There is no GetApproval RPC: exact Create and decision retries exercise
			// the existing authorized single-row retrieval paths.
			assertCreateRetry("renamed-requester", "renamed-reviewer", "renamed-approval-host")
			assertApprovalProjection(t, decide(), "renamed-requester", "renamed-reviewer", "renamed-approval-host")

			// Retained principal IDs need not have either a display name or a
			// local-account fallback. Missing labels must not hide the approval
			// or invent a name from its UUID.
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE principals SET display_name='' WHERE id IN ($1,$2)", owner.ID, reviewer.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.Pool.Exec(t.Context(), "DELETE FROM local_accounts WHERE id IN ($1,$2)", owner.ID, reviewer.ID); err != nil {
				t.Fatal(err)
			}
			assertList(observerCtx, "", "", "renamed-approval-host")
		})
	}
}

func TestApprovalProjectionScopedVisibility(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	reviewerCtx := approvalReviewer(t, f.svc, t.Context())
	reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
	outsideCtx := approvalReviewer(t, f.svc, t.Context())
	outside, _ := identity.PrincipalFromContext(outsideCtx)
	_, _, _, other := enrollDevice(t, t.Context(), f.svc, f.ownerCtx, ed25519Key(t))
	otherID := other.Msg.GetDeviceId()
	for _, actor := range []struct {
		id     uuid.UUID
		target string
		name   string
	}{
		{owner.ID, "", "scoped-requester"},
		{reviewer.ID, f.deviceID, "scoped-reviewer"},
		{outside.ID, otherID, "outside-reviewer"},
	} {
		if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET username=$2 WHERE id=$1", actor.id, actor.name); err != nil {
			t.Fatal(err)
		}
		if actor.target == "" {
			continue
		}
		if _, err := f.svc.Pool.Exec(t.Context(), `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, actor.id, actor.target); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Identity.AuthorizeFresh(t.Context(), actor.id, identity.PermissionManageAccounts); !errors.Is(err, identity.ErrAuthorizationDenied) {
			t.Fatalf("reviewer unexpectedly has account management authority: %v", err)
		}
	}
	request := &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: f.request(restartActionSpec())}}
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetApproval().GetId()
	assertApprovalProjection(t, created.Msg.GetApproval(), "scoped-requester", "", "device-action-fixture")
	assertInbox := func(ctx context.Context, expectedID, requester, approver, hostname string, pending uint64) {
		t.Helper()
		page, err := f.svc.ListApprovals(ctx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 1}))
		if err != nil {
			t.Fatal(err)
		}
		if page.Msg.GetNextPageToken() != "" {
			t.Fatal("hidden approval leaked through page token")
		}
		if expectedID == "" {
			if len(page.Msg.GetApprovals()) != 0 {
				t.Fatalf("outside-scope inbox leaked row or labels: %v", page.Msg)
			}
		} else {
			if len(page.Msg.GetApprovals()) != 1 || page.Msg.GetApprovals()[0].GetId() != expectedID {
				t.Fatalf("scoped inbox returned wrong rows: %v", page.Msg)
			}
			assertApprovalProjection(t, page.Msg.GetApprovals()[0], requester, approver, hostname)
		}
		summary, err := f.svc.GetFleetSummary(ctx, connect.NewRequest(&adminv1.GetFleetSummaryRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if summary.Msg.GetApprovals() == nil || summary.Msg.GetApprovals().GetPendingApprovals() != pending {
			t.Fatalf("scoped pending count = %v, want %d", summary.Msg.GetApprovals(), pending)
		}
	}
	assertInbox(reviewerCtx, id, "scoped-requester", "", "device-action-fixture", 1)
	assertInbox(outsideCtx, "", "", "", "", 0)
	if response, err := f.svc.ApproveApproval(outsideCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: id, Reason: "outside scope approval"})); connect.CodeOf(err) != connect.CodeNotFound || response != nil {
		t.Fatalf("outside-scope approve returned response=%v err=%v", response, err)
	}
	if response, err := f.svc.RejectApproval(outsideCtx, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: id, Reason: "outside scope rejection"})); connect.CodeOf(err) != connect.CodeNotFound || response != nil {
		t.Fatalf("outside-scope reject returned response=%v err=%v", response, err)
	}
	if response, err := f.svc.CreateApproval(outsideCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound || response != nil {
		t.Fatalf("outside-scope create returned response=%v err=%v", response, err)
	}
	assertInbox(reviewerCtx, id, "scoped-requester", "", "device-action-fixture", 1)
	approved, err := f.svc.ApproveApproval(reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: id, Reason: "scoped independent review"}))
	if err != nil {
		t.Fatal(err)
	}
	assertApprovalProjection(t, approved.Msg.GetApproval(), "scoped-requester", "scoped-reviewer", "device-action-fixture")
	assertInbox(outsideCtx, "", "", "", "", 0)

	// A second enrolled device has no host observation; its hostname stays empty,
	// not its UUID, and its pending approval cannot affect the first scope's count.
	hidden, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: otherID, Reason: "unobserved scoped target"}}}))
	if err != nil {
		t.Fatal(err)
	}
	assertApprovalProjection(t, hidden.Msg.GetApproval(), "scoped-requester", "", "")
	assertInbox(reviewerCtx, id, "scoped-requester", "scoped-reviewer", "device-action-fixture", 0)
	assertInbox(outsideCtx, hidden.Msg.GetApproval().GetId(), "scoped-requester", "", "", 1)
}
