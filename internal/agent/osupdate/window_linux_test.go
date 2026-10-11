//go:build linux

package osupdate

import (
	"testing"
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("time zone %s unavailable: %v", name, err)
	}
	return loc
}

func window(zone string, start, duration uint32, days ...resourcev1.Weekday) *resourcev1.MaintenanceWindow {
	return &resourcev1.MaintenanceWindow{TimeZone: zone, Weekdays: days, LocalStartMinute: start, DurationMinutes: duration}
}

func TestOpenWindow(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	newYork := mustZone(t, "America/New_York")
	at := func(loc *time.Location, y int, m time.Month, d, h, min int) time.Time {
		return time.Date(y, m, d, h, min, 0, 0, loc)
	}
	utc := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, time.UTC) }
	mon, tue, sat, sun := resourcev1.Weekday_WEEKDAY_MONDAY, resourcev1.Weekday_WEEKDAY_TUESDAY, resourcev1.Weekday_WEEKDAY_SATURDAY, resourcev1.Weekday_WEEKDAY_SUNDAY
	for _, tc := range []struct {
		name   string
		window *resourcev1.MaintenanceWindow
		loc    *time.Location
		now    time.Time
		start  time.Time // zero when closed
	}{
		// 2026-10-12 is a Monday.
		{"start inclusive", window("Europe/Berlin", 120, 60, mon), berlin, at(berlin, 2026, 10, 12, 2, 0), at(berlin, 2026, 10, 12, 2, 0)},
		{"inside", window("Europe/Berlin", 120, 60, mon), berlin, at(berlin, 2026, 10, 12, 2, 59), at(berlin, 2026, 10, 12, 2, 0)},
		{"before start", window("Europe/Berlin", 120, 60, mon), berlin, at(berlin, 2026, 10, 12, 1, 59), time.Time{}},
		{"end exclusive", window("Europe/Berlin", 120, 60, mon), berlin, at(berlin, 2026, 10, 12, 3, 0), time.Time{}},
		{"other weekday", window("Europe/Berlin", 120, 60, tue), berlin, at(berlin, 2026, 10, 12, 2, 30), time.Time{}},
		{"zone not host clock", window("Europe/Berlin", 120, 60, mon), berlin, utc(2026, 10, 12, 0, 30), at(berlin, 2026, 10, 12, 2, 0)},
		{"zone not host clock outside", window("Europe/Berlin", 120, 60, mon), berlin, utc(2026, 10, 12, 2, 30), time.Time{}},
		// Monday 23:00 for 2 h crosses into Tuesday.
		{"midnight crossing before", window("Europe/Berlin", 1380, 120, mon), berlin, at(berlin, 2026, 10, 12, 23, 30), at(berlin, 2026, 10, 12, 23, 0)},
		{"midnight crossing after", window("Europe/Berlin", 1380, 120, mon), berlin, at(berlin, 2026, 10, 13, 0, 59), at(berlin, 2026, 10, 12, 23, 0)},
		{"midnight crossing end", window("Europe/Berlin", 1380, 120, mon), berlin, at(berlin, 2026, 10, 13, 1, 0), time.Time{}},
		{"unlisted day before its own start", window("Europe/Berlin", 1380, 120, mon), berlin, at(berlin, 2026, 10, 13, 23, 30), time.Time{}},
		{"full day", window("Europe/Berlin", 0, 1440, mon), berlin, at(berlin, 2026, 10, 12, 23, 59), at(berlin, 2026, 10, 12, 0, 0)},
		// Berlin spring forward: 2026-03-29 (Sunday) 02:00 CET -> 03:00 CEST.
		// 02:30 does not exist; systemd skips that day's elapse entirely.
		{"gap day skipped at transition", window("Europe/Berlin", 150, 60, sun), berlin, utc(2026, 3, 29, 1, 0), time.Time{}},
		{"gap day skipped later", window("Europe/Berlin", 150, 60, sun), berlin, utc(2026, 3, 29, 1, 40), time.Time{}},
		{"week before gap opens", window("Europe/Berlin", 150, 60, sun), berlin, utc(2026, 3, 22, 1, 30), at(berlin, 2026, 3, 22, 2, 30)},
		{"week after gap opens", window("Europe/Berlin", 150, 60, sun), berlin, utc(2026, 4, 5, 0, 30), at(berlin, 2026, 4, 5, 2, 30)},
		{"spring day duration is elapsed time", window("Europe/Berlin", 60, 120, sun), berlin, at(berlin, 2026, 3, 29, 3, 30), at(berlin, 2026, 3, 29, 1, 0)},
		{"spring day elapsed end", window("Europe/Berlin", 60, 120, sun), berlin, at(berlin, 2026, 3, 29, 4, 0), time.Time{}},
		// Berlin fall back: 2026-10-25 (Sunday) 03:00 CEST -> 02:00 CET. 02:30
		// occurs twice; the window opens at the first occurrence.
		{"fold first occurrence", window("Europe/Berlin", 150, 30, sun), berlin, utc(2026, 10, 25, 0, 30), utc(2026, 10, 25, 0, 30)},
		{"fold first occurrence end", window("Europe/Berlin", 150, 30, sun), berlin, utc(2026, 10, 25, 1, 0), time.Time{}},
		{"fold second occurrence", window("Europe/Berlin", 150, 30, sun), berlin, utc(2026, 10, 25, 1, 30), time.Time{}},
		// New York: 2026-03-08 02:00 EST -> 03:00 EDT; 2026-11-01 02:00 EDT -> 01:00 EST.
		{"new york gap skipped", window("America/New_York", 135, 30, sun), newYork, utc(2026, 3, 8, 7, 0), time.Time{}},
		{"new york fold first", window("America/New_York", 90, 20, sun), newYork, utc(2026, 11, 1, 5, 40), utc(2026, 11, 1, 5, 30)},
		{"new york fold second", window("America/New_York", 90, 20, sun), newYork, utc(2026, 11, 1, 6, 40), time.Time{}},
		{"new york crossing midnight inside", window("America/New_York", 1380, 240, sat), newYork, at(newYork, 2026, 3, 8, 1, 30), at(newYork, 2026, 3, 7, 23, 0)},
		// Saturday 23:00 EST + 4 h elapsed ends at 04:00 EDT, not 03:00.
		{"new york crossing midnight into dst day", window("America/New_York", 1380, 240, sat), newYork, at(newYork, 2026, 3, 8, 3, 30), at(newYork, 2026, 3, 7, 23, 0)},
		{"new york crossing midnight into dst day end", window("America/New_York", 1380, 240, sat), newYork, at(newYork, 2026, 3, 8, 4, 0), time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, open, err := openWindow(tc.window, tc.loc, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if open != !tc.start.IsZero() || !start.Equal(tc.start) {
				t.Fatalf("openWindow(%s) = %v %s, want %s", tc.now.In(tc.loc), open, start.In(tc.loc), tc.start.In(tc.loc))
			}
		})
	}
}

func TestOpenWindowRejectsInvalidWindows(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	now := time.Date(2026, 10, 12, 2, 0, 0, 0, berlin)
	for _, w := range []*resourcev1.MaintenanceWindow{
		nil,
		window("Europe/Berlin", 120, 60),
		window("Europe/Berlin", 1440, 60, resourcev1.Weekday_WEEKDAY_MONDAY),
		window("Europe/Berlin", 120, 0, resourcev1.Weekday_WEEKDAY_MONDAY),
		window("Europe/Berlin", 120, 1441, resourcev1.Weekday_WEEKDAY_MONDAY),
		window("Europe/Berlin", 120, 60, resourcev1.Weekday_WEEKDAY_UNSPECIFIED),
	} {
		if _, _, err := openWindow(w, berlin, now); err == nil {
			t.Errorf("openWindow(%v) accepted an invalid window", w)
		}
	}
}
