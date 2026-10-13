//go:build integration

package device

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// A refused new action names the open action blocking it, and an action the
// device never started reads as expired once its expiry passes, without
// waiting for another create or start attempt to record the closure.
func TestDeviceActionPendingDetailAndUnstartedExpiry(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDeviceActionFixture(t)
	open := f.create(t, f.request(lockActionSpec()))

	_, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(lockActionSpec())))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "device_action_pending" {
		t.Fatalf("second action while one is open: %v", err)
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatal("not a connect error")
	}
	var blocking *adminv1.DeviceAction
	for _, detail := range connectErr.Details() {
		value, err := detail.Value()
		if err != nil {
			t.Fatal(err)
		}
		if action, ok := value.(*adminv1.DeviceAction); ok {
			blocking = action
		}
	}
	if blocking.GetActionId() != open.GetActionId() || blocking.GetSpec().GetLockSessions() == nil || blocking.GetCreatedAt() == nil || blocking.GetActorDisplayName() == "" {
		t.Fatalf("pending refusal does not name the blocking action: %v", blocking)
	}
	if open.GetClosedReason() != "" {
		t.Fatalf("fresh action reads closed: %q", open.GetClosedReason())
	}
	preflight, err := f.svc.PreflightDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.PreflightDeviceActionRequest{DeviceId: f.deviceID, EnrollmentGeneration: f.generation, Spec: lockActionSpec()}))
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Msg.GetBlockedReason() != "device_action_pending" || preflight.Msg.GetBlockingAction().GetActionId() != open.GetActionId() {
		t.Fatalf("preflight does not name the blocking action: %v", preflight.Msg)
	}

	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE device_actions SET expires_at = clock_timestamp() - interval '1 second', issued_at = clock_timestamp() - interval '2 minutes' WHERE id=$1", uuid.MustParse(open.GetActionId())); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: open.GetActionId()}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetAction().GetClosedReason() != "expired_unstarted" || got.Msg.GetAction().GetStatus() != nil {
		t.Fatalf("unstarted expired action: closed %q status %v", got.Msg.GetAction().GetClosedReason(), got.Msg.GetAction().GetStatus())
	}
	list, err := f.svc.GetDeviceActions(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionsRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, action := range list.Msg.GetActions() {
		if seen[action.GetActionId()] {
			t.Fatalf("action %s listed twice", action.GetActionId())
		}
		seen[action.GetActionId()] = true
		if action.GetActionId() == open.GetActionId() && action.GetClosedReason() != "expired_unstarted" {
			t.Fatalf("history shows expired action as %q", action.GetClosedReason())
		}
	}
	// The expired action no longer blocks a new one.
	f.create(t, f.request(lockActionSpec()))
}
