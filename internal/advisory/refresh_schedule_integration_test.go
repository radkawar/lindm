//go:build integration

package advisory

import (
	"context"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/testdb"
)

// A replica that takes over advisory maintenance must not repeat a vendor fetch
// that another replica attempted within the refresh interval.
func TestRefreshScheduleIsSharedAcrossReplicas(t *testing.T) {
	pool, _ := testdb.Open(t)
	first, source, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	second, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if due, err := first.refreshDue(t.Context()); err != nil || !due {
		t.Fatalf("never-attempted feed not due: %t %v", due, err)
	}
	attempted := time.Now().UTC().Truncate(time.Microsecond)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	// The first replica's failed refresh records its durable attempt.
	if err := advisorydb.New(pool).FailAdvisoryFeed(t.Context(), advisorydb.FailAdvisoryFeedParams{ID: source.GetId(), AttemptedAt: timestamp(attempted), Error: "refresh_failed", ConfigBytes: encoded}); err != nil {
		t.Fatal(err)
	}
	second.clock = func() time.Time { return attempted.Add(time.Minute) }
	if due, err := second.refreshDue(t.Context()); err != nil || due {
		t.Fatalf("new leader repeated a recent attempt: %t %v", due, err)
	}
	second.clock = func() time.Time { return attempted.Add(second.refreshInterval) }
	if due, err := second.refreshDue(t.Context()); err != nil || !due {
		t.Fatalf("feed not due after its interval: %t %v", due, err)
	}
}

// A refresh cut short by shutdown or lost leadership is not an attempt: the
// next leader must still refresh instead of waiting a whole interval.
func TestCancelledRefreshIsNotRecordedAsAttempt(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, _, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Refresh(cancelled); err == nil {
		t.Fatal("cancelled refresh reported success")
	}
	if due, err := s.refreshDue(t.Context()); err != nil || !due {
		t.Fatalf("cancelled refresh deferred the schedule: due=%t err=%v", due, err)
	}
}
