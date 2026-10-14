// SPDX-License-Identifier: Apache-2.0

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
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity"
)

func (f *deviceActionFixture) preflight(t *testing.T, ctx context.Context, spec *agentv1.DeviceActionSpec) *adminv1.PreflightDeviceActionResponse {
	t.Helper()
	response, err := f.svc.PreflightDeviceAction(ctx, connect.NewRequest(&adminv1.PreflightDeviceActionRequest{DeviceId: f.deviceID, EnrollmentGeneration: f.generation, Spec: spec}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

// The review-time preflight must refuse exactly what create would refuse, name
// the inventory and check-in times separately, and never leave a trace.
func TestPreflightDeviceActionMatchesCreateRefusalWithoutSideEffects(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	restart := restartActionSpec()
	ready := f.preflight(t, f.ownerCtx, restart)
	if ready.GetBlockedReason() != "" || ready.GetCheckedAt() == nil || ready.GetLastSeenAt() == nil || ready.GetInventoryReceivedAt() == nil || ready.GetInventoryMaxAgeSeconds() != 300 {
		t.Fatalf("fresh device not ready or facts missing: %v", ready)
	}
	// A device that checked in seconds ago can still hold an inventory older
	// than the action window: heartbeats do not carry host inventory.
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '7 minutes' WHERE generation_id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp()-interval '20 seconds' WHERE id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	stale := f.preflight(t, f.ownerCtx, restart)
	if stale.GetBlockedReason() != "device_action_inventory_stale" {
		t.Fatalf("stale inventory not reported at review: %v", stale)
	}
	checked, seen, received := stale.GetCheckedAt().AsTime(), stale.GetLastSeenAt().AsTime(), stale.GetInventoryReceivedAt().AsTime()
	if checked.Sub(seen) > time.Minute || checked.Sub(received) < 6*time.Minute {
		t.Fatalf("check-in and inventory ages conflated: checked=%v seen=%v received=%v", checked, seen, received)
	}
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(restart))); rpcReason(err) != stale.GetBlockedReason() {
		t.Fatalf("create refusal differs from preflight: %v", err)
	}
	// Refresh repairs stale inventory, so it needs no inventory window itself.
	refresh := f.preflight(t, f.ownerCtx, refreshActionSpec())
	if refresh.GetBlockedReason() != "" || refresh.GetInventoryMaxAgeSeconds() != 0 {
		t.Fatalf("refresh blocked by the inventory it repairs: %v", refresh)
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	if got := f.preflight(t, f.ownerCtx, restart).GetBlockedReason(); got != "device_action_offline" {
		t.Fatalf("offline device not reported: %q", got)
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE devices SET last_seen_at=clock_timestamp() WHERE id=$1", f.principal.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp() WHERE generation_id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	if got := f.preflight(t, f.ownerCtx, restart).GetBlockedReason(); got != "" {
		t.Fatalf("fresh inventory still blocked: %q", got)
	}
	var actions, audits int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM device_actions WHERE device_id=$1", f.principal.DeviceID).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action LIKE 'device_action.%'").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if actions != 0 || audits != 0 {
		t.Fatalf("preflight persisted work: actions=%d audits=%d", actions, audits)
	}
}

// With two-person approval required for restarts, stale inventory refuses the
// approved request without spending its approval: after fresh inventory
// arrives, the same approved request is created once, carrying the approval.
func TestApprovedActionSurvivesStaleInventoryRefusal(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	imperativePolicy(t, f, &authv1.AuthorizationPolicy{ApprovalRequiredPermissions: []string{string(identity.PermissionRunRemoteExecution)}})
	request := f.request(restartActionSpec())
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("restart admitted without the required approval: %v", err)
	}
	f.approval(t, request)
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET received_at=clock_timestamp()-interval '7 minutes' WHERE generation_id=$1", f.principal.GenerationID); err != nil {
		t.Fatal(err)
	}
	if got := f.preflight(t, f.ownerCtx, request.GetSpec()).GetBlockedReason(); got != "device_action_inventory_stale" {
		t.Fatalf("stale inventory not reported for the approved request: %q", got)
	}
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(request)); rpcReason(err) != "device_action_inventory_stale" {
		t.Fatalf("approved request admitted with stale inventory: %v", err)
	}
	f.observeStorageDetails(t, nativeDetailsFixture())
	if got := f.preflight(t, f.ownerCtx, request.GetSpec()).GetBlockedReason(); got != "" {
		t.Fatalf("fresh inventory still blocks the approved request: %q", got)
	}
	created := f.create(t, request)
	replayed := f.create(t, request)
	if created.GetActionId() == "" || replayed.GetActionId() != created.GetActionId() {
		t.Fatalf("approved request not created exactly once: %v %v", created, replayed)
	}
	// The refusal left the approval usable: the created action carries it, and
	// only that action does (its start consumes it).
	var bound int
	if err := f.svc.Pool.QueryRow(t.Context(), "SELECT count(*) FROM device_actions WHERE approval_id=$1 AND id=$2", request.GetApprovalId(), created.GetActionId()).Scan(&bound); err != nil || bound != 1 {
		t.Fatalf("approved action does not carry its approval: count=%d err=%v", bound, err)
	}
}

// Preflight is authorized exactly like create: a fleet reader cannot probe
// remote-execution prerequisites, and out-of-scope devices stay invisible.
func TestPreflightDeviceActionAuthorization(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	request := &adminv1.PreflightDeviceActionRequest{DeviceId: f.deviceID, EnrollmentGeneration: f.generation, Spec: restartActionSpec()}
	helper := insertPrincipal(t, t.Context(), f.conn, identity.RoleHelpdesk)
	if _, err := f.svc.PreflightDeviceAction(identity.WithPrincipal(t.Context(), helper), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("fleet reader admitted: %v", err)
	}
	actor := insertPrincipal(t, t.Context(), f.conn, identity.RoleAdmin)
	setImperativeScope(t, f, actor, uuid.NewString())
	if _, err := f.svc.PreflightDeviceAction(identity.WithPrincipal(t.Context(), actor), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope device visible: %v", err)
	}
}

// The restart delay is bounded by the proto (0 to 3600 seconds, the logind
// schedule the agent accepts); out-of-range values never reach a check.
func TestPreflightDeviceActionRejectsOutOfRangeRestartDelay(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	for _, delay := range []uint32{0, 3600} {
		spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{DelaySeconds: proto.Uint32(delay)}}}
		if got := f.preflight(t, f.ownerCtx, spec).GetBlockedReason(); got != "" {
			t.Fatalf("delay %d blocked: %q", delay, got)
		}
	}
	for _, delay := range []uint32{3601, 99999999} {
		spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{DelaySeconds: proto.Uint32(delay)}}}
		if _, err := f.svc.PreflightDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.PreflightDeviceActionRequest{DeviceId: f.deviceID, EnrollmentGeneration: f.generation, Spec: spec})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("delay %d admitted by preflight: %v", delay, err)
		}
		if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(spec))); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("delay %d admitted by create: %v", delay, err)
		}
	}
}
