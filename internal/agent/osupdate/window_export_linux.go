//go:build linux

package osupdate

import (
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// OpenWindow is the runner's maintenance-window gate in the window's own IANA
// zone. It is exported only so the provider can prove its rendered systemd
// calendar elapses exactly at the window starts this gate admits.
func OpenWindow(window *resourcev1.MaintenanceWindow, now time.Time) (time.Time, bool, error) {
	loc, err := time.LoadLocation(window.GetTimeZone())
	if err != nil {
		return time.Time{}, false, errWindowInvalid
	}
	return openWindow(window, loc, now)
}
