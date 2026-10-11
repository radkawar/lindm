//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// On a device observed as Omarchy 4.0.4, whose Quickshell lock ignores logind
// LockSessions, creating a session-only lock is refused with a visible reason
// and nothing is queued; adding an account selection makes the action
// effective and it is created.
func TestDeviceActionSessionOnlyLockRefusedOnOmarchy(t *testing.T) {
	f := newDeviceActionFixture(t)
	// The fixture's single allowed host report observed Debian 12; the stored
	// observation is what admission reads.
	if _, err := f.svc.Pool.Exec(t.Context(), "UPDATE host_observations SET os_id_value='omarchy', os_version_value='4.0.4' WHERE generation_id=$1", f.generation); err != nil {
		t.Fatal(err)
	}
	sessionOnly := f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}})
	if _, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(sessionOnly)); rpcReason(err) != "device_action_session_lock_unsupported" {
		t.Fatalf("session-only lock on Omarchy: error %v (reason %q)", err, rpcReason(err))
	}
	withAccounts := f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{Usernames: []string{"alice"}}}})
	if action := f.create(t, withAccounts); action.GetActionId() == "" {
		t.Fatal("account lock on Omarchy was not created")
	}
}
