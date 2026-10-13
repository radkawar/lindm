//go:build integration

package device

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"lindm/internal/device/core"

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

func releaseLockSpec(id string) *agentv1.DeviceActionSpec {
	return &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: id}}}
}

func lockVerification() *agentv1.DeviceActionVerification {
	return &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true, SessionsLocked: true, DisabledAccounts: []string{"alice"}, PreservedAccounts: []string{"root"}}}
}

func assertLockRestriction(t *testing.T, f *deviceActionFixture, id string) {
	t.Helper()
	response, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.GetSessionsLocked() != (id != "") || response.Msg.GetLockActionId() != id {
		t.Fatalf("lock restriction = %v/%q; want %q", response.Msg.GetSessionsLocked(), response.Msg.GetLockActionId(), id)
	}
}

func startCompletedLock(t *testing.T, f *deviceActionFixture) string {
	t.Helper()
	request := f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{TerminateSessions: true, Usernames: []string{"alice"}}}})
	action := f.create(t, request)
	assertLockRestriction(t, f, "")
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, action.GetActionId())
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, lockVerification()))); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, action.GetActionId())
	return action.GetActionId()
}

func TestDeviceActionLockReleaseVerifiedOwnershipAndAudit(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	original := startCompletedLock(t, f)
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(lockActionSpec()))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("overlapping lock orphaned owned accounts: %v", err)
	}
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(releaseLockSpec(uuid.NewString())))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unrelated original lock accepted: %v", err)
	}
	release := f.create(t, f.request(releaseLockSpec(original)))
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, original)
	verification := lockVerification()
	verification.After.DisabledAccounts = nil
	verification.After.PreservedAccounts = []string{"root", "admin_changed"}
	// A validly signed "success" without native support must not clear ownership.
	unsupported := proto.CloneOf(verification)
	unsupported.After.Supported = false
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, unsupported))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unverified release cleared restriction: %v", err)
	}
	assertLockRestriction(t, f, original)
	result := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)
	tampered := proto.CloneOf(result)
	tampered.AttestationEnvelope[len(tampered.AttestationEnvelope)/2] ^= 1
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(tampered)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unsigned release cleared restriction: %v", err)
	}
	assertLockRestriction(t, f, original)
	running := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING, nil)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(running)); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, original)
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(releaseLockSpec(original)))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("running release was replaced: %v", err)
	}
	result = f.result(t, f.work(t), 2, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, "")
	// The screen may remain locked; a verified release restores only owned accounts.
	stored, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: release.GetActionId()}))
	if err != nil || !proto.Equal(stored.Msg.GetAction().GetStatus().GetVerification(), verification) {
		t.Fatalf("release public evidence changed: %v", err)
	}
	// Readers get the requesting account's current label beside its audited ID.
	if name := stored.Msg.GetAction().GetActorDisplayName(); !strings.HasPrefix(name, "test-") {
		t.Fatalf("release actor label = %q", name)
	}
	newer := startCompletedLock(t, f)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); err != nil {
		t.Fatalf("exact release replay failed: %v", err)
	}
	assertLockRestriction(t, f, newer)
	oldID, _ := uuid.Parse(original)
	if err := devicedb.New(f.svc.Pool).ReleaseDeviceActionLock(t.Context(), devicedb.ReleaseDeviceActionLockParams{DeviceID: f.principal.DeviceID, LockActionID: &oldID, UpdatedAt: core.Timestamptz(time.Now())}); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, newer)
	for _, event := range []string{"device_action.create", "device_action.start", "device_action.result"} {
		var count int
		if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action=$2", release.GetActionId(), event).Scan(&count); err != nil {
			t.Fatal(err)
		}
		want := 1
		if event == "device_action.result" {
			want = 2 // signed running and signed completion, never rejected/replayed proofs
		}
		if count != want {
			t.Fatalf("release audit %s = %d; want %d", event, count, want)
		}
	}
}

func TestDeviceActionLockRestrictionIndependentOfQuarantine(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	original := startCompletedLock(t, f)
	quarantine := f.create(t, f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"192.0.2.1"}}}}))
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, lockVerification()))); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, original)
	f.create(t, f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{QuarantineActionId: quarantine.GetActionId()}}}))
	work = f.work(t)
	start, _ = f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, lockVerification()))); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, original)
	f.create(t, f.request(releaseLockSpec(original)))
}

func TestDeviceActionLockConfiguredApprovalConsumedAtStart(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, permission := range []identity.Permission{identity.PermissionLockDevice, identity.PermissionReleaseLockDevice} {
		t.Run(string(permission), func(t *testing.T) {
			f := newDeviceActionFixture(t)
			spec := lockActionSpec()
			if permission == identity.PermissionReleaseLockDevice {
				spec = releaseLockSpec(startCompletedLock(t, f))
			}
			authority, err := identity.New(t.Context(), f.svc.Pool, identity.Config{Local: true, PublicURL: "https://admin.example", Policy: &authv1.AuthorizationPolicy{ApprovalRequiredPermissions: []string{string(permission)}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := authority.Close(); err != nil {
					t.Error(err)
				}
			})
			f.svc.Identity = authority
			request := f.request(spec)
			if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("configured independent approval bypassed: %v", err)
			}
			created, err := f.svc.CreateApproval(f.ownerCtx, connect.NewRequest(&adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_CreateDeviceAction{CreateDeviceAction: request}}))
			if err != nil {
				t.Fatal(err)
			}
			approvalID := created.Msg.GetApproval().GetId()
			decision := &adminv1.ApproveApprovalRequest{ApprovalId: approvalID, Reason: "review exact original and local account scope"}
			if _, err := f.svc.ApproveApproval(f.ownerCtx, connect.NewRequest(decision)); connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("self approval accepted: %v", err)
			}
			reviewer := approvalReviewer(t, f.svc, t.Context())
			if _, err := f.svc.ApproveApproval(reviewer, connect.NewRequest(decision)); err != nil {
				t.Fatal(err)
			}
			request.ApprovalId = approvalID
			f.create(t, request)
			var state string
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", approvalID).Scan(&state); err != nil || state != "approved" {
				t.Fatalf("approval consumed before native start: %s %v", state, err)
			}
			start, _ := f.startRequest(t, f.work(t))
			response, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start))
			if err != nil {
				t.Fatal(err)
			}
			grant := new(agentv1.DeviceActionStartGrant)
			if err := f.svc.Authority.Verify(t.Context(), response.Msg.GetStartGrantEnvelope(), grant, 1, ed25519.PublicKey(f.svc.Signing.StartKey[ed25519.SeedSize:])); err != nil {
				t.Fatal(err)
			}
			if len(grant.GetApprovals()) != 2 || grant.GetApprovals()[0].GetActorId() == grant.GetApprovals()[1].GetActorId() {
				t.Fatal("configured policy lost the two independent human authorities")
			}
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT state FROM approval_requests WHERE id=$1", approvalID).Scan(&state); err != nil || state != "consumed" {
				t.Fatalf("approval not consumed atomically: %s %v", state, err)
			}
		})
	}
}

func TestDeviceActionUnknownLockExplicitRelease(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	lock := f.create(t, f.request(lockActionSpec()))
	original := lock.GetActionId()
	for range 2 {
		work := f.work(t)
		start, _ := f.startRequest(t, work)
		if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
			t.Fatal(err)
		}
		// No signed interrupted result yet: start authority might still be running.
		if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(releaseLockSpec(original)))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("grant-only lock/release superseded: %v", err)
		}
		if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN, nil))); err != nil {
			t.Fatal(err)
		}
		assertLockRestriction(t, f, original)
		if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(lockActionSpec()))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("unknown lock repeated instead of explicitly released: %v", err)
		}
		next := f.create(t, f.request(releaseLockSpec(original)))
		prior, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: work.GetActionId()}))
		if err != nil {
			t.Fatal(err)
		}
		if prior.Msg.GetAction().GetClosedReason() != "outcome_unknown" || prior.Msg.GetAction().GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
			t.Fatal("explicit inverse rewrote unknown history as success")
		}
		if f.work(t).GetActionId() != next.GetActionId() || next.GetActionId() == work.GetActionId() {
			t.Fatal("explicit inverse reused original execution identity")
		}
	}
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, lockVerification()))); err != nil {
		t.Fatal(err)
	}
	assertLockRestriction(t, f, "")
}

func TestDeviceActionReleaseLockFreshOwnershipFence(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	original := startCompletedLock(t, f)
	action := f.create(t, f.request(releaseLockSpec(original)))
	work := f.work(t)
	start, _ := f.startRequest(t, work)
	id, _ := uuid.Parse(original)
	if err := devicedb.New(f.svc.Pool).ReleaseDeviceActionLock(t.Context(), devicedb.ReleaseDeviceActionLockParams{DeviceID: f.principal.DeviceID, LockActionID: &id, UpdatedAt: core.Timestamptz(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("release used stale create-time ownership: %v", err)
	}
	var grant []byte
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT start_grant_envelope FROM device_actions WHERE id=$1", action.GetActionId()).Scan(&grant); err != nil {
		t.Fatal(err)
	}
	if len(grant) != 0 {
		t.Fatal("stale ownership persisted release authority")
	}
}

func TestDeviceActionLockApprovalRejectsChangedSelectionAndRevocation(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, change := range []string{"termination", "usernames", "all_humans", "approver_revoked"} {
		t.Run(change, func(t *testing.T) {
			f := newDeviceActionFixture(t)
			request := f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{Usernames: []string{"alice"}}}})
			reviewer := f.approval(t, request)
			switch change {
			case "termination":
				request.Spec.GetLockSessions().TerminateSessions = true
			case "usernames":
				request.Spec.GetLockSessions().Usernames = []string{"bob"}
			case "all_humans":
				request.Spec.GetLockSessions().Usernames = nil
				request.Spec.GetLockSessions().AllHumanAccounts = true
			case "approver_revoked":
				principal, _ := identity.PrincipalFromContext(reviewer)
				if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE local_accounts SET enabled=false WHERE id=$1", principal.ID); err != nil {
					t.Fatal(err)
				}
			}
			action := f.create(t, request)
			start, _ := f.startRequest(t, f.work(t))
			if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err == nil {
				t.Fatal("changed lock selection or revoked approver authorized effects")
			}
			var grant []byte
			if err := f.svc.Pool.QueryRow(t.Context(), "SELECT start_grant_envelope FROM device_actions WHERE id=$1", action.GetActionId()).Scan(&grant); err != nil {
				t.Fatal(err)
			}
			if len(grant) != 0 {
				t.Fatal("rejected approval persisted native authority")
			}
			assertLockRestriction(t, f, "")
		})
	}
}
