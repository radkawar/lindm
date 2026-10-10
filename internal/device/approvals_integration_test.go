//go:build integration

package device

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func approvalReviewer(t *testing.T, svc *Service, ctx context.Context) context.Context {
	t.Helper()
	conn, err := svc.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	reviewer := insertPrincipal(t, ctx, conn.Conn(), identity.RoleAdmin)
	return identity.WithPrincipal(ctx, reviewer)
}

// approvedRevocation follows the same durable two-human RPC lifecycle as clients.
func approvedRevocation(t *testing.T, svc *Service, ctx context.Context, request *adminv1.RevokeDeviceRequest) *connect.Request[adminv1.RevokeDeviceRequest] {
	t.Helper()
	created, err := svc.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: request}}))
	if err != nil {
		t.Fatal(err)
	}
	reviewer := approvalReviewer(t, svc, ctx)
	if _, err := svc.ApproveApproval(reviewer, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "independently reviewed retirement"})); err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	return connect.NewRequest(request)
}

func TestApprovalRevokeLifecycle(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	reviewerCtx := approvalReviewer(t, svc, ctx)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
	_, _, _, other := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
	request := &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: enrolled.Msg.GetDeviceId(), Reason: "retire selected device"}
	if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unapproved revoke: %v", err)
	}
	created, err := svc.CreateApproval(ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 3600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: request}}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetApproval().GetId()
	decision := &adminv1.ApproveApprovalRequest{ApprovalId: id, Reason: "reviewed exact target and payload"}
	if _, err := svc.ApproveApproval(ownerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("self approval: %v", err)
	}
	reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
	if _, err := conn.Exec(ctx, "UPDATE principals SET service_account=true WHERE id=$1", reviewer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveApproval(reviewerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("service approval: %v", err)
	}
	if _, err := conn.Exec(ctx, "UPDATE principals SET service_account=false WHERE id=$1", reviewer.ID); err != nil {
		t.Fatal(err)
	}
	approved, err := svc.ApproveApproval(reviewerCtx, connect.NewRequest(decision))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Msg.GetApproval().GetState() != adminv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Fatal("approval not durable")
	}
	request.ApprovalId = id
	for _, change := range []func(*adminv1.RevokeDeviceRequest){
		func(r *adminv1.RevokeDeviceRequest) { r.DeviceId = other.Msg.GetDeviceId() },
		func(r *adminv1.RevokeDeviceRequest) { r.Reason = "different payload" },
		func(r *adminv1.RevokeDeviceRequest) { r.RequestId = uuid.NewString() },
	} {
		altered := proto.CloneOf(request)
		change(altered)
		if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(altered)); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("altered approval binding: %v", err)
		}
	}
	if _, err := svc.RevokeDevice(reviewerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("different requester: %v", err)
	}
	if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	var count int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='approval.consumed' AND resource_id=$1", id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("one use audit=%d: %v", count, err)
	}
	page, err := svc.ListApprovals(ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Msg.GetApprovals()) != 1 || page.Msg.GetApprovals()[0].GetState() != adminv1.ApprovalState_APPROVAL_STATE_CONSUMED {
		t.Fatal("consumed inbox receipt missing")
	}
}

func TestApprovalRejectExpiryAndVersions(t *testing.T) {
	for _, scenario := range []string{"rejected", "expired", "requester_version", "approver_version", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			pool, conn := testdb.Open(t)
			ca, key := testCA(t, time.Now().Add(90*24*time.Hour))
			svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)})
			if err != nil {
				t.Fatal(err)
			}
			owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
			ownerCtx := identity.WithPrincipal(ctx, owner)
			reviewerCtx := approvalReviewer(t, svc, ctx)
			reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
			_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
			request := &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: enrolled.Msg.GetDeviceId(), Reason: "retire selected device"}
			created, err := svc.CreateApproval(ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: request}}))
			if err != nil {
				t.Fatal(err)
			}
			request.ApprovalId = created.Msg.GetApproval().GetId()
			if scenario == "rejected" {
				_, err = svc.RejectApproval(reviewerCtx, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: request.ApprovalId, Reason: "target must remain enrolled"}))
			} else {
				_, err = svc.ApproveApproval(reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: request.ApprovalId, Reason: "retirement reviewed"}))
			}
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "expired":
				_, err = conn.Exec(ctx, "UPDATE approval_requests SET created_at=statement_timestamp()-interval '2 hours',expires_at=statement_timestamp()-interval '1 hour' WHERE id=$1", request.ApprovalId)
			case "requester_version":
				_, err = conn.Exec(ctx, "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", owner.ID)
			case "approver_version":
				_, err = conn.Exec(ctx, "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", reviewer.ID)
			case "disabled":
				_, err = conn.Exec(ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", reviewer.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.RevokeDevice(ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("%s revoke: %v", scenario, err)
			}
			var state string
			if err := conn.QueryRow(ctx, "SELECT state FROM devices WHERE id=$1", request.DeviceId).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state == stateRevoked {
				t.Fatal("denied approval mutated device")
			}
		})
	}
}

func TestApprovalScopeInboxAndCreation(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(90*24*time.Hour))
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	reviewer := insertPrincipal(t, ctx, conn, identity.RoleAdmin)
	reviewerCtx := identity.WithPrincipal(ctx, reviewer)
	auditor := insertPrincipal(t, ctx, conn, identity.RoleAuditor)
	auditorCtx := identity.WithPrincipal(ctx, auditor)
	_, _, _, first := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
	_, _, _, second := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
	create := func(target string) *adminv1.CreateApprovalRequest {
		return &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_RevokeDevice{RevokeDevice: &adminv1.RevokeDeviceRequest{RequestId: uuid.NewString(), DeviceId: target, Reason: "scoped retirement"}}}
	}
	visibleRequest := create(first.Msg.GetDeviceId())
	visible, err := svc.CreateApproval(ownerCtx, connect.NewRequest(visibleRequest))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := svc.CreateApproval(ownerCtx, connect.NewRequest(visibleRequest))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(visible.Msg, retry.Msg) {
		t.Fatal("create retry changed immutable approval")
	}
	hidden, err := svc.CreateApproval(ownerCtx, connect.NewRequest(create(second.Msg.GetDeviceId())))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE local_accounts SET scope_binding=jsonb_build_object('scopes',jsonb_build_array(jsonb_build_object('deviceIds',jsonb_build_array($2::text)))) WHERE id=$1`, reviewer.ID, first.Msg.GetDeviceId()); err != nil {
		t.Fatal(err)
	}
	page, err := svc.ListApprovals(reviewerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Msg.GetApprovals()) != 1 || page.Msg.GetApprovals()[0].GetId() != visible.Msg.GetApproval().GetId() || page.Msg.GetNextPageToken() != "" {
		t.Fatal("hidden target leaked through inbox pagination")
	}
	if _, err := svc.ApproveApproval(reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: hidden.Msg.GetApproval().GetId(), Reason: "out of scope"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out of scope review: %v", err)
	}
	if _, err := svc.CreateApproval(reviewerCtx, connect.NewRequest(create(second.Msg.GetDeviceId()))); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out of scope create: %v", err)
	}
	if _, err := svc.CreateApproval(auditorCtx, connect.NewRequest(create(first.Msg.GetDeviceId()))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("no action grant create: %v", err)
	}
	if _, err := svc.ListApprovals(auditorCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("no action grant inbox: %v", err)
	}
}

func TestConfiguredAssignmentApproval(t *testing.T) {
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
	svc, err := New(pool, Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: authority})
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	_, _, _, enrolled := enrollDevice(t, ctx, svc, ownerCtx, ed25519Key(t))
	request := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: enrolled.Msg.GetDeviceId(), Clear: true, Reason: "stop managing this device"}
	if _, err := svc.SetResourceAssignment(ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("configured action bypass: %v", err)
	}
	created, err := svc.CreateApproval(ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: request}}))
	if err != nil {
		t.Fatal(err)
	}
	request.ApprovalId = created.Msg.GetApproval().GetId()
	if _, err := svc.ApproveApproval(approvalReviewer(t, svc, ctx), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: request.ApprovalId, Reason: "assignment removal reviewed"})); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(request)
	interval := uint32(600)
	changed.ReconcileIntervalSeconds = &interval
	if _, err := svc.SetResourceAssignment(ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("changed interval binding: %v", err)
	}
	if _, err := svc.SetResourceAssignment(ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetResourceAssignment(ownerCtx, connect.NewRequest(request)); err != nil {
		t.Fatalf("exact assignment retry: %v", err)
	}
	stale := proto.CloneOf(request)
	stale.RequestId = uuid.NewString()
	stale.ApprovalId = ""
	wrongHead := uuid.NewString()
	stale.ExpectedAssignmentId = &wrongHead
	pending, err := svc.CreateApproval(ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: stale}}))
	if err != nil {
		t.Fatal(err)
	}
	stale.ApprovalId = pending.Msg.GetApproval().GetId()
	if _, err := svc.ApproveApproval(approvalReviewer(t, svc, ctx), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: stale.ApprovalId, Reason: "reviewed immutable desired head"})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetResourceAssignment(ownerCtx, connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale assignment head: %v", err)
	}
	var state string
	if err := conn.QueryRow(ctx, "SELECT state FROM approval_requests WHERE id=$1", stale.ApprovalId).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "approved" {
		t.Fatalf("failed mutation consumed approval: %s", state)
	}
}
