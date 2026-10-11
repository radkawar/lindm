//go:build integration

package device

import (
	"encoding/json"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
	"lindm/internal/identity/identitydb"
)

func TestApprovalInboxEveryClosedDeviceAction(t *testing.T) {
	f := newDeviceActionFixture(t)
	owner, _ := identity.PrincipalFromContext(f.ownerCtx)
	reviewerCtx := approvalReviewer(t, f.svc, t.Context())
	reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
	specs := storageActionSpecs(f, fixtureStorageTarget(uuid.NewString()))
	specs["lock_sessions"] = lockActionSpec()
	specs["release_lock"] = releaseLockSpec(uuid.NewString())
	specs["quarantine"] = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"192.0.2.1"}}}}
	specs["release_quarantine"] = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{QuarantineActionId: uuid.NewString()}}}
	specs["restart"], specs["shutdown"], specs["refresh_inventory"] = restartActionSpec(), shutdownActionSpec(), refreshActionSpec()
	specs["local_admin_password_rotate"] = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{AccountName: "lapsadmin", EscrowKeyId: f.svc.escrow.KeyID(), EscrowPublicKey: f.svc.escrow.PublicKey()}}}
	specs["patch_now"] = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, RebootPolicy: &resourcev1.OSUpdateRebootPolicy{Mode: resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_NEVER}}}}
	fields := new(agentv1.DeviceActionSpec).ProtoReflect().Descriptor().Oneofs().ByName("action").Fields()
	if len(specs) != fields.Len() {
		t.Fatal("closed action schema needs an inbox fixture")
	}
	for i := range fields.Len() {
		field := fields.Get(i)
		t.Run(string(field.Name()), func(t *testing.T) {
			spec := specs[string(field.Name())]
			if spec == nil {
				t.Fatal("missing closed action fixture")
			}
			// Exercise real binding, authorization, scope, persistence and inbox SQL.
			// Native recovery-readiness preflight belongs to CreateDeviceAction, not
			// this identity inbox visibility regression.
			created, err := f.svc.identity.CreateApproval(t.Context(), owner.ID, &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: f.request(spec)}}, f.svc.approvalScope)
			if spec.GetLocalAdminPasswordRotate() != nil {
				// Only a local-admin policy mints this arm; nothing exists to approve.
				if !errors.Is(err, identity.ErrApprovalInvalid) {
					t.Fatalf("approval for a server-minted action: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, actor := range []identity.Principal{owner, reviewer} {
				page, err := f.svc.ListApprovals(identity.WithPrincipal(t.Context(), actor), connect.NewRequest(&adminv1.ListApprovalsRequest{}))
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Msg.GetApprovals()) != 1 || page.Msg.GetApprovals()[0].GetId() != created.GetId() {
					t.Fatalf("eligible %s cannot see %s approval", actor.ID, field.Name())
				}
				count, err := f.svc.identity.CountPendingApprovals(t.Context(), actor.ID)
				if err != nil || count != 1 {
					t.Fatalf("pending count=%d err=%v", count, err)
				}
			}
			if _, err := f.svc.RejectApproval(reviewerCtx, connect.NewRequest(&adminv1.RejectApprovalRequest{ApprovalId: created.GetId(), Reason: "closed-kind inbox review regression"})); err != nil {
				t.Fatal(err)
			}
			for _, actor := range []identity.Principal{owner, reviewer} {
				count, err := f.svc.identity.CountPendingApprovals(t.Context(), actor.ID)
				if err != nil || count != 0 {
					t.Fatalf("decided approval count=%d err=%v", count, err)
				}
			}
			// Retain decisions normally; isolate each arm's list/count assertion.
			if _, err := f.svc.pool.Exec(t.Context(), "DELETE FROM approval_requests WHERE id=$1", created.GetId()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestApprovalRefreshInboxRequiresIndependentFleetRead(t *testing.T) {
	f := newDeviceActionFixture(t)
	imperativePolicy(t, f, &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "refresh-reviewer", Permissions: []string{string(identity.PermissionManageInventory), string(identity.PermissionManageApprovals)}}}})
	reviewer := insertPrincipal(t, t.Context(), f.conn, "refresh-reviewer")
	reviewerCtx := identity.WithPrincipal(t.Context(), reviewer)
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: f.request(refreshActionSpec())}}))
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListApprovals(reviewerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
	if err != nil || len(page.Msg.GetApprovals()) != 0 {
		t.Fatalf("missing fleet-read leaked approval projections: %v %v", page, err)
	}
	count, err := f.svc.identity.CountPendingApprovals(t.Context(), reviewer.ID)
	if err != nil || count != 0 {
		t.Fatalf("missing fleet-read count=%d err=%v", count, err)
	}

	// Exercise the identical real SQL filters with independently scoped read
	// grants. Local accounts bind one common role scope; OIDC group grants can
	// bind these dimensions separately, as the identity unit regression proves.
	q := identitydb.New(f.svc.pool)
	for _, test := range []struct {
		target  string
		visible bool
	}{{uuid.NewString(), false}, {f.deviceID, true}} {
		required, err := json.Marshal(map[string]any{string(identity.PermissionManageInventory): []any{map[string]any{"unrestricted": false, "scopes": []any{map[string]any{"device_ids": []string{test.target}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		params := identitydb.ListVisibleApprovalsParams{ActorID: reviewer.ID, AfterID: uuid.Nil, RowLimit: 50, UnrestrictedPermissions: []string{string(identity.PermissionManageInventory)}, Scopes: []byte("{}"), RequiredScopes: required, ManageUnrestricted: true, ManageScopes: []byte("[]")}
		rows, err := q.ListVisibleApprovals(t.Context(), params)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if test.visible {
			want = 1
		}
		if len(rows) != want {
			t.Fatalf("independent read-scope rows=%d want=%d", len(rows), want)
		}
		if test.visible && (rows[0].ApprovalRequest.ID.String() != created.Msg.GetApproval().GetId() || rows[0].DeviceHostname == "") {
			t.Fatal("authorized projected target disappeared")
		}
		count, err := q.CountVisiblePendingApprovals(t.Context(), identitydb.CountVisiblePendingApprovalsParams{ActorID: params.ActorID, UnrestrictedPermissions: params.UnrestrictedPermissions, Scopes: params.Scopes, RequiredScopes: params.RequiredScopes, ManageUnrestricted: params.ManageUnrestricted, ManageScopes: params.ManageScopes})
		if err != nil || count != int64(want) {
			t.Fatalf("independent read-scope count=%d want=%d err=%v", count, want, err)
		}
	}
}
