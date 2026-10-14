// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"errors"
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

var errWindowInvalid = errors.New("maintenance_window_invalid")

// openWindow returns the start of the maintenance window containing now, if
// any. A window starts at the local start minute of a listed weekday in loc
// and lasts duration_minutes of elapsed time; it may cross midnight, so the
// previous local day's window is checked too.
//
// The semantics follow the systemd calendar the provider's timer uses
// (verified with systemd 255 `systemd-analyze calendar`): a start inside a
// DST gap does not exist and that day's window does not open at all; a
// repeated (fall-back) local time opens at its first occurrence.
func openWindow(window *resourcev1.MaintenanceWindow, loc *time.Location, now time.Time) (time.Time, bool, error) {
	if window == nil || loc == nil || window.GetLocalStartMinute() > 1439 || window.GetDurationMinutes() == 0 || window.GetDurationMinutes() > 1440 {
		return time.Time{}, false, errWindowInvalid
	}
	days := make(map[time.Weekday]bool, 7)
	for _, day := range window.GetWeekdays() {
		weekday, ok := goWeekday(day)
		if !ok {
			return time.Time{}, false, errWindowInvalid
		}
		days[weekday] = true
	}
	if len(days) == 0 {
		return time.Time{}, false, errWindowInvalid
	}
	local := now.In(loc)
	duration := time.Duration(window.GetDurationMinutes()) * time.Minute
	for offset := 0; offset >= -1; offset-- {
		day := time.Date(local.Year(), local.Month(), local.Day()+offset, 12, 0, 0, 0, loc)
		if !days[day.Weekday()] {
			continue
		}
		start, ok := windowStart(day, int(window.GetLocalStartMinute()), loc)
		if ok && !now.Before(start) && now.Before(start.Add(duration)) {
			return start, true, nil
		}
	}
	return time.Time{}, false, nil
}

// windowStart returns the first instant whose local wall time in loc is the
// start minute on day, or false when that local time falls into a DST gap.
func windowStart(day time.Time, minute int, loc *time.Location) (time.Time, bool) {
	hour, min := minute/60, minute%60
	nominal := time.Date(day.Year(), day.Month(), day.Day(), hour, min, 0, 0, loc)
	if wall := nominal.In(loc); wall.Hour() != hour || wall.Minute() != min || wall.Day() != day.Day() {
		return time.Time{}, false
	}
	// Fall back: the same wall time may also exist under the earlier offset.
	if transition, _ := nominal.ZoneBounds(); !transition.IsZero() {
		_, before := transition.Add(-time.Second).Zone()
		_, after := nominal.Zone()
		if before > after {
			earlier := nominal.Add(-time.Duration(before-after) * time.Second)
			if wall := earlier.In(loc); wall.Hour() == hour && wall.Minute() == min && wall.Day() == nominal.Day() {
				return earlier, true
			}
		}
	}
	return nominal, true
}

func goWeekday(day resourcev1.Weekday) (time.Weekday, bool) {
	switch day {
	case resourcev1.Weekday_WEEKDAY_MONDAY:
		return time.Monday, true
	case resourcev1.Weekday_WEEKDAY_TUESDAY:
		return time.Tuesday, true
	case resourcev1.Weekday_WEEKDAY_WEDNESDAY:
		return time.Wednesday, true
	case resourcev1.Weekday_WEEKDAY_THURSDAY:
		return time.Thursday, true
	case resourcev1.Weekday_WEEKDAY_FRIDAY:
		return time.Friday, true
	case resourcev1.Weekday_WEEKDAY_SATURDAY:
		return time.Saturday, true
	case resourcev1.Weekday_WEEKDAY_SUNDAY:
		return time.Sunday, true
	default:
		return 0, false
	}
}
