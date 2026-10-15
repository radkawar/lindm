// SPDX-License-Identifier: Apache-2.0

package platform

import "testing"

func TestNotificationActionsUnavailableUsesVerifiedVersions(t *testing.T) {
	for _, test := range []struct {
		server, version, want string
	}{
		{"cosmic-notifications", "0.1.0", "notification_actions_hidden"},
		{"cosmic-notifications", "1.10.0", "notification_actions_hidden"},
		{"cosmic-notifications", "1.10.0-lindm-actions.1", ""},
		{"cosmic-notifications", "1.10.0-lindm-actions.2", "notification_actions_unverified"},
		{"cosmic-notifications", "", "notification_actions_unverified"},
		{"cosmic-notifications", "1.11.0", "notification_actions_unverified"},
		{"cosmic-notifications", "1.10.0+unknown", "notification_actions_unverified"},
		{"gnome-shell", "", ""},
		{"Notification Daemon", "", ""},
	} {
		if got := NotificationActionsUnavailable(test.server, test.version); got != test.want {
			t.Errorf("%q %q: reason = %q, want %q", test.server, test.version, got, test.want)
		}
	}
}
