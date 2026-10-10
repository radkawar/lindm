//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// The console fixture previously delegated only systemd.service.v1. A fresh
// otherwise valid refresh reached the signer and returned an opaque HTTP 500.
func TestDeviceActionServiceOnlyDelegationIsTypedPrerequisite(t *testing.T) {
	for _, kind := range []string{"refresh", "restart", "shutdown", "lock"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeviceActionFixtureCapabilities(t, []string{"systemd.service.v1"})
			spec := lockActionSpec()
			switch kind {
			case "refresh":
				spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}
			case "restart":
				spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}
			case "shutdown":
				spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}}
			}
			_, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(spec)))
			if connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("missing action delegation must be a prerequisite, not internal: %v", err)
			}
			if failure, ok := err.(*connect.Error); !ok || failure.Meta().Get("Lindm-Reason") != "device_action_capability_not_delegated" || failure.Meta().Get("Lindm-Signer-Role") != "plan" || failure.Meta().Get("Lindm-Action-Capability") == "" {
				t.Fatalf("missing typed signer reason: %v", err)
			}
			var count int
			if err := f.svc.pool.QueryRow(t.Context(), "SELECT count(*) FROM device_actions").Scan(&count); err != nil || count != 0 {
				t.Fatalf("undelegated action committed: count=%d err=%v", count, err)
			}
		})
	}
}

func TestDeviceActionConfiguredStartKeyMustBeDelegatedBeforeCreate(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.svc.signing.StartKey = ed25519Key(t)
	_, err := f.svc.CreateDeviceAction(f.ownerCtx, connect.NewRequest(f.request(&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}})))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("undelegated start signer admitted doomed action: %v", err)
	}
	if failure, ok := err.(*connect.Error); !ok || failure.Meta().Get("Lindm-Reason") != "device_action_capability_not_delegated" || failure.Meta().Get("Lindm-Signer-Role") != "start" || failure.Meta().Get("Lindm-Action-Capability") != "device.refresh-inventory.v1" {
		t.Fatalf("missing typed start signer reason: %v", err)
	}
}

func TestDeviceActionStartSignerChangeIsTypedPrerequisite(t *testing.T) {
	f := newDeviceActionFixture(t)
	f.create(t, f.request(refreshActionSpec()))
	request, _ := f.startRequest(t, f.work(t))
	f.svc.signing.StartKey = ed25519Key(t)
	_, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(request))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("undelegated start key returned an unexpected error: %v", err)
	}
	if failure, ok := err.(*connect.Error); !ok || failure.Meta().Get("Lindm-Reason") != "device_action_capability_not_delegated" || failure.Meta().Get("Lindm-Action-Capability") != "device.refresh-inventory.v1" {
		t.Fatalf("start lacks typed capability reason: %v", err)
	}
}
