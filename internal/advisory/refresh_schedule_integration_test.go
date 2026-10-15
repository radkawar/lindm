// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
	if due, err := first.dueSources(t.Context()); err != nil || len(due) != 1 {
		t.Fatalf("never-attempted feed not due: %v %v", due, err)
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
	if due, err := second.dueSources(t.Context()); err != nil || len(due) != 0 {
		t.Fatalf("new leader repeated a recent attempt: %v %v", due, err)
	}
	second.clock = func() time.Time { return attempted.Add(second.refreshInterval) }
	if due, err := second.dueSources(t.Context()); err != nil || len(due) != 1 {
		t.Fatalf("feed not due after its interval: %v %v", due, err)
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
	if due, err := s.dueSources(t.Context()); err != nil || len(due) != 1 {
		t.Fatalf("cancelled refresh deferred the schedule: due=%v err=%v", due, err)
	}
}

func TestRefreshWorkersJoinOnLeadershipCancellation(t *testing.T) {
	pool, _ := testdb.Open(t)
	started := make(chan struct{}, 5)
	var active, peak atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, current) {
				break
			}
		}
		started <- struct{}{}
		<-request.Context().Done()
	}))
	defer server.Close()
	config := &configv1.AdvisoryConfig{}
	for index, scope := range []struct{ distro, release string }{
		{"ubuntu", "22.04"}, {"ubuntu", "24.04"}, {"ubuntu", "26.04"},
		{"debian", "12"}, {"debian", "13"},
	} {
		source := &advisoryv1.FeedSource{
			Id: fmt.Sprintf("parallel-%d", index), Distro: scope.distro, Release: scope.release,
			Url: server.URL + "/fixture.json", Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON,
			MaxAgeSeconds: 86400,
		}
		config.Feeds = append(config.Feeds, source)
	}
	service, err := New(t.Context(), pool, config, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Refresh(ctx) }()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for range 2 {
		select {
		case <-started:
		case <-deadline.C:
			t.Fatal("independent source refreshes did not run concurrently")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("leadership cancellation returned success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("refresh workers did not join on cancellation")
	}
	if peak.Load() != 2 {
		t.Fatalf("source concurrency = %d, want 2", peak.Load())
	}
	for _, source := range config.Feeds {
		row, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
		if err != nil {
			t.Fatal(err)
		}
		if row.AttemptedAt.Valid {
			t.Fatalf("leadership cancellation deferred %s", source.Id)
		}
	}
}
