// SPDX-License-Identifier: Apache-2.0

package labhost

import "testing"

// Only device-action runs that build the owned-boot recovery UKI provision the
// private ukify; every other lane, including other wipe phases, leaves it.
func TestRecoveryUkifyLane(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"vm", "device-actions", "-scenario=wipe", "-wipe-phase=recovery-nvme"}, true},
		{[]string{"vm", "device-actions", "-scenario", "wipe", "-wipe-phase", "recovery-sata"}, true},
		{[]string{"vm", "device-actions", "-scenario=wipe"}, true},
		{[]string{"vm", "device-actions", "-scenario=wipe", "-wipe-phase=live-actions"}, false},
		{[]string{"vm", "device-actions", "-scenario=encryption"}, false},
		{[]string{"vm", "dispatch", "-scenario=wipe", "-wipe-phase=recovery-nvme"}, false},
		{[]string{"vm"}, false},
	} {
		if got := recoveryUkifyLane(tc.args); got != tc.want {
			t.Errorf("recoveryUkifyLane(%v) = %t, want %t", tc.args, got, tc.want)
		}
	}
}
