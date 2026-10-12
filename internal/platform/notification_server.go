package platform

// NotificationActionsHidden reports whether a notification server, named by
// its org.freedesktop.Notifications GetServerInformation name, advertises the
// "actions" capability but shows the user no action buttons, so a consent
// prompt's Allow and Decline are never visible.
//   - cosmic-notifications: 1.10 (Pop!_OS 24.04, commit 1e4c1f1) renders a
//     card with the summary, body and a close button only; activating the
//     card invokes the "default" action, else the first action (src/app.rs
//     activate_notification). Observed natively in pop2404-assistance-04: the
//     lindm prompt showed no Allow/Decline.
func NotificationActionsHidden(server string) bool {
	return server == "cosmic-notifications"
}
