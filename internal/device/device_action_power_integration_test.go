//go:build integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/internal/device/dispatch"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/identity"
)

func imperativePolicy(t *testing.T, f *deviceActionFixture, policy *authv1.AuthorizationPolicy) {
	t.Helper()
	authority, err := identity.New(t.Context(), f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	f.svc.Identity = authority
}

func setImperativeScope(t *testing.T, f *deviceActionFixture, actor identity.Principal, id string) {
	t.Helper()
	scope := []byte(`{"scopes":[{"deviceIds":["` + id + `"]}]}`)
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET scope_binding=$2::jsonb WHERE id=$1", actor.ID, scope); err != nil {
		t.Fatal(err)
	}
}

func TestImperativeActionsFreshScopeOfflineAndReplay(t *testing.T) {
	for name, spec := range map[string]*agentv1.DeviceActionSpec{"restart": restartActionSpec(), "shutdown": shutdownActionSpec(), "refresh": refreshActionSpec()} {
		t.Run(name, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			request := f.request(spec)
			helper := insertPrincipal(t, t.Context(), f.conn, identity.RoleHelpdesk)
			if _, err := f.svc.CreateDeviceAction(identity.WithPrincipal(t.Context(), helper), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("fleet reader admitted privileged action: %v", err)
			}
			actor := insertPrincipal(t, t.Context(), f.conn, identity.RoleAdmin)
			actorCtx := identity.WithPrincipal(t.Context(), actor)
			setImperativeScope(t, f, actor, uuid.NewString())
			if _, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("fresh create scope bypassed: %v", err)
			}
			setImperativeScope(t, f, actor, f.deviceID)
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", f.principal.DeviceID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("offline imperative queued: %v", err)
			}
			if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp() WHERE id=$1", f.principal.DeviceID); err != nil {
				t.Fatal(err)
			}
			created, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request))
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request))
			if err != nil || replayed.Msg.GetAction().GetActionId() != created.Msg.GetAction().GetActionId() {
				t.Fatalf("exact create replay changed action: %v", err)
			}
			changed := proto.CloneOf(request)
			changed.Reason = "different imperative mutation"
			if _, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
				t.Fatalf("changed create replay admitted: %v", err)
			}
			start, _ := f.startRequest(t, f.work(t))
			setImperativeScope(t, f, actor, uuid.NewString())
			if _, err := f.svc.CreateDeviceAction(actorCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("create replay bypassed current scope: %v", err)
			}
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); connect.CodeOf(err) != connect.CodeNotFound && connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("start used stale requester scope/version: %v", err)
			}
		})
	}
}

func TestRefreshRequiresFreshReadAndInventoryManagement(t *testing.T) {
	for _, permissions := range [][]string{{string(identity.PermissionReadFleet)}, {string(identity.PermissionManageInventory)}, {string(identity.PermissionRunRemoteExecution)}, {string(identity.PermissionReadFleet), string(identity.PermissionManageInventory)}} {
		t.Run(permissions[0]+"-"+permissions[len(permissions)-1], func(t *testing.T) {
			f := newDeviceActionFixture(t)
			imperativePolicy(t, f, &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "inventory-refresh", Permissions: permissions}}})
			actor := insertPrincipal(t, t.Context(), f.conn, "inventory-refresh")
			// A stale browser's owner label must never supply missing fresh permissions.
			actor.Role = identity.RoleOwner
			ctx := identity.WithPrincipal(t.Context(), actor)
			request := f.request(refreshActionSpec())
			if _, err := f.svc.Pool.Exec(t.Context(), "DELETE FROM host_observations WHERE generation_id=$1", f.principal.GenerationID); err != nil {
				t.Fatal(err)
			}
			_, err := f.svc.CreateDeviceAction(ctx, connect.NewRequest(request))
			if len(permissions) == 2 {
				if err != nil {
					t.Fatalf("refresh could not repair missing inventory: %v", err)
				}
				start, _ := f.startRequest(t, f.work(t))
				if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
					t.Fatalf("fresh dual-permission refresh could not start: %v", err)
				}
			} else {
				if code := connect.CodeOf(err); code != connect.CodePermissionDenied && code != connect.CodeNotFound {
					t.Fatalf("refresh admitted incomplete permission set: %v", err)
				}
				if _, err := f.svc.CreateApproval(ctx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}})); connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Fatalf("approval admitted incomplete permission set: %v", err)
				}
			}
		})
	}
}

func TestImperativeActionsConfiguredApprovalAndReviewerScope(t *testing.T) {
	for name, spec := range map[string]*agentv1.DeviceActionSpec{"restart": restartActionSpec(), "shutdown": shutdownActionSpec(), "refresh": refreshActionSpec()} {
		t.Run(name, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			imperativePolicy(t, f, &authv1.AuthorizationPolicy{ApprovalRequiredPermissions: []string{string(dispatch.DeviceActionPermission(spec))}})
			request := f.request(spec)
			if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("configured approval bypassed: %v", err)
			}
			created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
			if err != nil {
				t.Fatal(err)
			}
			request.ApprovalId = created.Msg.GetApproval().GetId()
			decision := &adminv1.ApproveApprovalRequest{ApprovalId: request.GetApprovalId(), Reason: "independent imperative review"}
			if _, err := f.svc.ApproveApproval(f.ownerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("self approval admitted: %v", err)
			}
			reviewer := insertPrincipal(t, t.Context(), f.conn, identity.RoleAdmin)
			reviewerCtx := identity.WithPrincipal(t.Context(), reviewer)
			setImperativeScope(t, f, reviewer, uuid.NewString())
			if _, err := f.svc.ApproveApproval(reviewerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("out-of-scope reviewer admitted: %v", err)
			}
			setImperativeScope(t, f, reviewer, f.deviceID)
			if _, err := f.svc.ApproveApproval(reviewerCtx, connect.NewRequest(decision)); err != nil {
				t.Fatal(err)
			}
			f.create(t, request)
			work := f.work(t)
			start, _ := f.startRequest(t, work)
			response, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start))
			if err != nil {
				t.Fatal(err)
			}
			grant := new(agentv1.DeviceActionStartGrant)
			if err := f.svc.Authority.Verify(t.Context(), response.Msg.GetStartGrantEnvelope(), grant, 1, ed25519.PublicKey(f.svc.Signing.StartKey[ed25519.SeedSize:])); err != nil {
				t.Fatal(err)
			}
			if len(grant.GetApprovals()) != 2 || grant.GetApprovals()[0].GetActorId() == grant.GetApprovals()[1].GetActorId() {
				t.Fatal("grant lost independent approval authorities")
			}
			var state string
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", request.GetApprovalId()).Scan(&state); err != nil || state != "consumed" {
				t.Fatalf("approval not consumed with grant: %s %v", state, err)
			}
			replay, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start))
			if err != nil || !bytes.Equal(replay.Msg.GetStartGrantEnvelope(), response.Msg.GetStartGrantEnvelope()) {
				t.Fatalf("grant replay changed authority: %v", err)
			}
		})
	}
}

func TestRestartSignedResultBootTransitionAndReplay(t *testing.T) {
	f := newDeviceActionFixture(t)
	action := f.create(t, f.request(restartActionSpec()))
	work := f.work(t)
	start, challenge := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	unknown := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil)
	if response, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(unknown)); err != nil || response.Msg.GetClosed() {
		t.Fatalf("interrupted restart prematurely closed: %v", err)
	}
	work = f.work(t)
	verification := &agentv1.DeviceActionVerification{Verified: true, BootId: challenge.GetBootId(), After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, BootId: challenge.GetBootId()}}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("same boot accepted as successful restart: %v", err)
	}
	verification.BootId = uuid.NewString()
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("mismatched after boot accepted: %v", err)
	}
	verification.After.BootId = verification.GetBootId()
	result := f.result(t, work, 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)
	for range 2 {
		if response, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil || !response.Msg.GetClosed() {
			t.Fatalf("fresh boot success/exact replay failed: %v", err)
		}
	}
	got, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: action.GetActionId()}))
	if err != nil || got.Msg.GetAction().GetStatus().GetVerification().GetBootId() != verification.GetBootId() || got.Msg.GetAction().GetActionRevision() != 2 {
		t.Fatalf("accepted boot evidence lost: %v", err)
	}
	var audits int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action IN ('device_action.create','device_action.start','device_action.result')", action.GetActionId()).Scan(&audits); err != nil || audits != 4 {
		t.Fatalf("action audit trail or replay deduplication incorrect: %d %v", audits, err)
	}
}

func TestShutdownSignedResultRemainsUnknown(t *testing.T) {
	f := newDeviceActionFixture(t)
	action := f.create(t, f.request(shutdownActionSpec()))
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	verification := &agentv1.DeviceActionVerification{Verified: true, PowerRequestAccepted: true, Evidence: "outcome_unknown_until_contact", After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, BootId: uuid.NewString()}}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("shutdown accepted false success: %v", err)
	}
	verification.Verified = false
	result := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, verification)
	if response, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil || response.Msg.GetClosed() {
		t.Fatalf("shutdown accepted request not retained unknown: %v", err)
	}
	got, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: action.GetActionId()}))
	if err != nil || got.Msg.GetAction().GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN || !proto.Equal(got.Msg.GetAction().GetStatus().GetVerification(), verification) {
		t.Fatalf("shutdown evidence was replaced by fabricated certainty: %v", err)
	}
}

func TestRefreshSignedResultRequiresPublishedFullInventory(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.publishPackages(t, 1, "old-package")
	f.create(t, f.request(refreshActionSpec()))
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 6, "ungranted-host"))); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("ungranted refresh bypassed host admission: %v", err)
	}
	if _, err := f.begin(t, snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil), 1); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("ungranted refresh bypassed package admission: %v", err)
	}
	work := f.work(t)
	start, challenge := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	queued := hostObservation(f.generation, 6, "previously-collected-host")
	queued.Observation.StartedAt = timestamppb.New(challenge.GetIssuedAt().AsTime().Add(-time.Second))
	queued.Observation.FinishedAt = queued.Observation.GetStartedAt()
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(queued)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("old queued host consumed refresh admission: %v", err)
	}
	oldManifest := snapshotManifest(t, f.generation, 2, challenge.GetIssuedAt().AsTime().Add(-time.Second), nil)
	if _, err := f.begin(t, oldManifest, 1); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("old queued snapshot consumed refresh admission: %v", err)
	}
	verification := &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true}}
	for _, seq := range []uint64{0, 1, 99} {
		verification.InventorySequence = seq
		_, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)))
		if code := connect.CodeOf(err); code != connect.CodePermissionDenied && code != connect.CodeFailedPrecondition {
			t.Fatalf("unpublished or old sequence %d accepted: %v", seq, err)
		}
	}
	// A host-only refresh is not a published full snapshot.
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 7, "refreshed-host"))); err != nil {
		t.Fatal(err)
	}
	verification.InventorySequence = 2
	manifest := snapshotManifest(t, f.generation, 2, time.Now().UTC(), nil)
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	confirmation := &devicev1.ConfirmRefreshInventoryPublicationRequest{SessionEpoch: 1, ActionId: work.GetActionId()}
	if _, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(confirmation)); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "inventory_refresh_not_published" {
		t.Fatalf("receipt signed for staging publication: %v", err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("staging full snapshot accepted: %v", err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("refresh bypassed root publication receipt handshake: %v", err)
	}
	stale := proto.CloneOf(confirmation)
	stale.SessionEpoch = 2
	if _, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("stale session signed publication receipt: %v", err)
	}
	otherKey := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, f.ctx, f.svc, f.ownerCtx, otherKey)
	other, err := f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, f.ctx, f.svc, other, otherKey, 0)
	if _, err := f.svc.ConfirmRefreshInventoryPublication(core.WithDevicePrincipal(f.ctx, other), connect.NewRequest(confirmation)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("other device obtained publication receipt: %v", err)
	}
	confirmed, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(confirmation))
	if err != nil {
		t.Fatal(err)
	}
	receipt := new(agentv1.DeviceActionInventoryReceipt)
	if err := f.svc.Authority.Verify(t.Context(), confirmed.Msg.GetReceiptEnvelope(), receipt, 1, ed25519.PublicKey(f.svc.Signing.StartKey[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(work.GetIntentEnvelope())
	if receipt.GetActionId() != work.GetActionId() || receipt.GetDeviceId() != f.deviceID || receipt.GetEnrollmentGeneration() != f.generation || receipt.GetPackageSequence() != 2 || receipt.GetHostSequence() != 7 || receipt.GetSnapshotId() != manifest.GetSnapshotId() || !bytes.Equal(receipt.GetIntentSha256(), intentDigest[:]) {
		t.Fatal("signed receipt lost exact publication binding")
	}
	replayed, err := f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(confirmation))
	if err != nil || !bytes.Equal(replayed.Msg.GetReceiptEnvelope(), confirmed.Msg.GetReceiptEnvelope()) {
		t.Fatalf("publication receipt replay changed authority: %v", err)
	}
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 8, "extra-host"))); connect.CodeOf(err) != connect.CodeResourceExhausted || rpcReason(err) != "rate_limited" {
		t.Fatalf("refresh admitted more than one early host report: %v", err)
	}
	later := snapshotManifest(t, f.generation, 3, time.Now().UTC(), nil)
	if _, err := f.begin(t, later, 1); connect.CodeOf(err) != connect.CodeResourceExhausted || rpcReason(err) != "rate_limited" {
		t.Fatalf("refresh admitted more than one early package snapshot: %v", err)
	}
	ageInventoryAdmissions(t, f)
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(hostObservation(f.generation, 8, "later-routine-host"))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.begin(t, later, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, later, 1); err != nil {
		t.Fatal(err)
	}
	replayed, err = f.svc.ConfirmRefreshInventoryPublication(f.deviceCtx(), connect.NewRequest(confirmation))
	if err != nil || !bytes.Equal(replayed.Msg.GetReceiptEnvelope(), confirmed.Msg.GetReceiptEnvelope()) {
		t.Fatalf("later routine inventory invalidated exact receipt replay: %v", err)
	}
	verification.InventorySequence = 3
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("later snapshot substituted for exact signed receipt: %v", err)
	}
	verification.InventorySequence = 2
	result := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)
	for range 2 {
		if response, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil || !response.Msg.GetClosed() {
			t.Fatalf("published full snapshot/exact replay rejected: %v", err)
		}
	}
}

func TestRefreshApprovalRequiresReviewerReadPermission(t *testing.T) {
	f := newDeviceActionFixture(t)
	imperativePolicy(t, f, &authv1.AuthorizationPolicy{Roles: []*authv1.RoleDefinition{{Name: "inventory-reviewer", Permissions: []string{string(identity.PermissionManageInventory), string(identity.PermissionManageApprovals)}}}})
	request := f.request(refreshActionSpec())
	created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
	if err != nil {
		t.Fatal(err)
	}
	reviewer := insertPrincipal(t, t.Context(), f.conn, "inventory-reviewer")
	reviewer.Role = identity.RoleOwner
	if _, err := f.svc.ApproveApproval(identity.WithPrincipal(t.Context(), reviewer), connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: created.Msg.GetApproval().GetId(), Reason: "review without fleet visibility"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("reviewer without fresh read permission approved refresh: %v", err)
	}
}

func TestImperativeApprovalReviewerRevocationBeforeStart(t *testing.T) {
	for name, spec := range map[string]*agentv1.DeviceActionSpec{"restart": restartActionSpec(), "shutdown": shutdownActionSpec(), "refresh": refreshActionSpec()} {
		t.Run(name, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			request := f.request(spec)
			reviewerCtx := f.approval(t, request)
			reviewer, _ := identity.PrincipalFromContext(reviewerCtx)
			f.create(t, request)
			start, _ := f.startRequest(t, f.work(t))
			setImperativeScope(t, f, reviewer, uuid.NewString())
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); connect.CodeOf(err) != connect.CodeNotFound && connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("start consumed stale approver authority: %v", err)
			}
			var state string
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", request.GetApprovalId()).Scan(&state); err != nil || state != "approved" {
				t.Fatalf("failed start consumed approval: %s %v", state, err)
			}
		})
	}
}

// Admission timestamps are fixture scheduling state, not publication evidence.
// Keep collection/commit clocks real for the signed receipt's freshness checks.
func ageInventoryAdmissions(t *testing.T, f *deviceActionFixture) {
	t.Helper()
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE enrollment_generations SET last_host_admission_at=clock_timestamp()-interval '5 minutes', last_package_admission_at=clock_timestamp()-interval '5 minutes' WHERE id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
}
