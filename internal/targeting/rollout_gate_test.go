// SPDX-License-Identifier: Apache-2.0

package targeting

import (
	"testing"
	"time"

	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

func TestRolloutGatesWithInjectedClock(t *testing.T) {
	started := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	now := started
	store, err := newStore(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ring := &policyv1.RolloutRing{SoakSeconds: 60, MinimumObserved: 2, FailureBasisPoints: 1000, UnknownBasisPoints: 2000, UnavailableBasisPoints: 1000}
	tests := []struct {
		name    string
		elapsed time.Duration
		counts  targetingdb.RolloutHealthCountsRow
		ready   bool
		reason  string
	}{
		{"before soak", 60*time.Second - time.Nanosecond, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 10, CurrentHealthy: 2}, false, ""},
		{"at soak", 60 * time.Second, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 10, CurrentHealthy: 2}, true, ""},
		{"current ring minimum", time.Minute, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 10, CurrentHealthy: 1}, false, ""},
		{"exact failure budget", time.Minute, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 9, CurrentHealthy: 2, Failed: 1}, true, ""},
		{"failure before soak", 0, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 8, CurrentHealthy: 2, Failed: 2}, false, "failure_threshold"},
		{"unavailable before soak", 0, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 8, CurrentHealthy: 2, Unavailable: 2}, false, "unavailable_threshold"},
		{"unknown before soak", time.Minute - time.Nanosecond, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 2, CurrentHealthy: 2}, false, ""},
		{"unknown at soak", time.Minute, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 2, CurrentHealthy: 2}, false, "unknown_threshold"},
		{"exact unknown budget", time.Minute, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 8, CurrentHealthy: 2}, true, ""},
		{"exact unavailable budget", time.Minute, targetingdb.RolloutHealthCountsRow{Targeted: 10, Healthy: 9, CurrentHealthy: 2, Unavailable: 1}, true, ""},
		{"empty cohort", time.Minute, targetingdb.RolloutHealthCountsRow{}, false, ""},
		{"failure takes precedence", time.Minute, targetingdb.RolloutHealthCountsRow{Targeted: 10, Failed: 2, Unavailable: 2}, false, "failure_threshold"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = started.Add(test.elapsed)
			assessedAt, err := store.rolloutClock(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			ready, reason := assessRolloutGate(ring, test.counts, started, assessedAt)
			if ready != test.ready || reason != test.reason {
				t.Fatalf("gate = (%t, %q), want (%t, %q)", ready, reason, test.ready, test.reason)
			}
		})
	}
}

func TestPromoterRequiresDependencies(t *testing.T) {
	if _, err := NewPromoter(nil, nil, nil, RolloutHooks{}); err == nil {
		t.Fatal("accepted missing dependencies")
	}
}
