// SPDX-License-Identifier: Apache-2.0

package platform

// NotificationActionsUnavailable adds server-specific consent qualification
// to the ordinary "actions" capability check performed by the caller. COSMIC
// advertises that capability even when it renders no buttons, so its runtime
// version requires native visible-button evidence rather than capability trust.
func NotificationActionsUnavailable(server, version string) string {
	if server != "cosmic-notifications" {
		return ""
	}
	switch version {
	case "1.10.0-lindm-actions.1":
		// Explicit fork version: renders non-default action buttons and
		// never turns a card click into the first action. Stock 1.10.0 is
		// not this build; no inferred minimum-version rule admits it.
		return ""
	case "0.1.0", "1.10.0":
		// Pop!_OS ISO 7837e49 and archive 1e4c1f1: activating the card
		// invokes default, else the first action, without visible buttons.
		// Observed natively in pop2404-assistance-04.
		return "notification_actions_hidden"
	default:
		// Do not infer a fix from a newer version or the advertised actions
		// capability. A fixed version needs native visible-button evidence.
		return "notification_actions_unverified"
	}
}
