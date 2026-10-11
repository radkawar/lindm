//go:build linux

package vmlab

import (
	"testing"
	"time"
)

// debian12-arm64-dgx21-device-actions-wipe-live-erase-01: after the 61 s
// approval-expiry wait, fresh presence/inventory took ~58 s and the 110 s
// request had expired, so the server answered device_action_expiry instead of
// the expired-approval denial being qualified.
func TestDestructiveNegativeRequestOutlivesItsWaits(t *testing.T) {
	for _, scenario := range []string{"destructive_self_approval", "destructive_spec_digest_changed", "destructive_expired_approval", "destructive_revoked_approver"} {
		lifetime := destructiveNegativeLifetime(scenario)
		waits := nativeActionPresenceTimeout
		if scenario == "destructive_expired_approval" {
			waits += destructiveNegativeApprovalLifetime + time.Second
		}
		if lifetime <= waits {
			t.Errorf("%s request lifetime %v does not outlive its %v of waits", scenario, lifetime, waits)
		}
		// CreateDeviceAction admits at most ten minutes of intent validity.
		if lifetime > 10*time.Minute {
			t.Errorf("%s request lifetime %v exceeds the server's intent limit", scenario, lifetime)
		}
	}
}
