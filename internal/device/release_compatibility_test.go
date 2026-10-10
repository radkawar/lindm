package device

import (
	"testing"
	"time"

	"lindm/internal/device/devicedb"
)

func TestReleaseWindowRetainsThreeSeriesAndNotice(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	rows := make([]devicedb.ReleasedAgentSeries, 4)
	for i := range rows {
		rows[i] = devicedb.ReleasedAgentSeries{Major: 1, Minor: int32(4 - i), ReleasedAt: timestamptz(now.Add(-180 * 24 * time.Hour)), SupportUntil: timestamptz(now.Add(-time.Hour)), MinimumProtocol: 1, MaximumProtocol: 1}
	}
	for _, version := range []string{"1.4.0", "1.3.9", "1.2.1"} {
		if !releaseSupported(rows, version, 1, "1.4.0", 1, now) {
			t.Fatalf("current/previous-two denied: %s", version)
		}
	}
	if releaseSupported(rows, "1.1.0", 1, "1.4.0", 1, now) {
		t.Fatal("fourth expired series admitted")
	}
	rows[3].SupportUntil = timestamptz(now.Add(time.Second))
	if !releaseSupported(rows, "1.1.0", 1, "1.4.0", 1, now) {
		t.Fatal("announced support window discarded")
	}
	if releaseSupported(rows, "1.1.0", 1, "1.4.0", 1, now.Add(time.Second)) {
		t.Fatal("support boundary inclusive")
	}
	for _, version := range []string{"", "(devel)", "1.04.0", "1.4", "2.0.0"} {
		if releaseSupported(rows, version, 1, "1.4.0", 1, now) {
			t.Fatalf("unreported/unreleased version admitted: %s", version)
		}
	}
	if releaseSupported(rows, "1.4.0", 2, "1.4.0", 1, now) {
		t.Fatal("incompatible protocol admitted")
	}
	if releaseSupported(rows, "1.4.0", 1, "(devel)", 1, now) {
		t.Fatal("unknown server stamp admitted")
	}
	rows[0].ReleasedAt = timestamptz(now.Add(time.Second))
	if releaseSupported(rows, "1.4.0", 1, "1.4.0", 1, now) {
		t.Fatal("future release admitted")
	}
}
