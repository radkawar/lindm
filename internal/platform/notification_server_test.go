// SPDX-License-Identifier: Apache-2.0

package platform

import "testing"

func TestNotificationActionsHiddenFollowsObservedServers(t *testing.T) {
	for server, want := range map[string]bool{
		"cosmic-notifications": true,
		"gnome-shell":          false,
		"Notification Daemon":  false,
		"":                     false,
	} {
		if got := NotificationActionsHidden(server); got != want {
			t.Errorf("%q: hidden = %v, want %v", server, got, want)
		}
	}
}
