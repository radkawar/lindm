// SPDX-License-Identifier: Apache-2.0

package device

import (
	"testing"

	"lindm/internal/device/core"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

// Omarchy 4.0.4's Quickshell lock ignores logind LockSessions
// (omarchy404-lock-quarantine-01). A lock action that would only request that
// lock is refused before effect; one that also locks accounts or terminates
// sessions has an effect and proceeds. Unobserved identities are not refused.
func TestSessionOnlyLockRefusedWhereDesktopIgnoresLogind(t *testing.T) {
	success := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS)
	denied := int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED)
	omarchy := devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "omarchy", OsVersionStatus: success, OsVersionValue: "4.0.4"}
	mint := devicedb.GetHostObservationRow{OsIDStatus: success, OsIDValue: "linuxmint", OsVersionStatus: success, OsVersionValue: "22.3"}
	unobserved := omarchy
	unobserved.OsIDStatus = denied
	for name, test := range map[string]struct {
		host   devicedb.GetHostObservationRow
		action *agentv1.LockSessionsAction
		want   bool
	}{
		"omarchy session only":  {omarchy, &agentv1.LockSessionsAction{}, true},
		"omarchy with accounts": {omarchy, &agentv1.LockSessionsAction{Usernames: []string{"alice"}}, false},
		"omarchy all humans":    {omarchy, &agentv1.LockSessionsAction{AllHumanAccounts: true}, false},
		"omarchy terminate":     {omarchy, &agentv1.LockSessionsAction{TerminateSessions: true}, false},
		"mint session only":     {mint, &agentv1.LockSessionsAction{}, false},
		"omarchy unobserved":    {unobserved, &agentv1.LockSessionsAction{}, false},
		"not a session lock":    {omarchy, nil, false},
	} {
		if got := core.SessionLockOnlyUnsupported(test.host, test.action); got != test.want {
			t.Errorf("%s: refused = %t, want %t", name, got, test.want)
		}
	}
}
