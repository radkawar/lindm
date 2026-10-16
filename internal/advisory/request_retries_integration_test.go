// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/testdb"
)

func TestRequestRetriesPersistLatestAttemptAndIsolateSources(t *testing.T) {
	pool, _ := testdb.Open(t)
	raw, err := os.ReadFile("feed/testdata/ubuntu-USN-6859-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var attemptsA, attemptsB atomic.Int64
	var phase atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter := &attemptsA
		if r.URL.Path == "/b" {
			counter = &attemptsB
		}
		attempt := counter.Add(1)
		// Both sources run concurrently: a succeeds after two retries while
		// b exhausts all five attempts. The next refresh uses no retries.
		if phase.Load() == 0 && (r.URL.Path == "/b" || attempt <= 2) {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	cfg := &configv1.AdvisoryConfig{}
	for index, arch := range []string{"amd64", "arm64"} {
		id := string(rune('a' + index))
		cfg.Feeds = append(cfg.Feeds, &advisoryv1.FeedSource{
			Id: id, Distro: "ubuntu", Release: "24.04", Architecture: arch,
			Url: server.URL + "/" + id, Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, MaxAgeSeconds: 86400,
		})
	}
	s, err := New(t.Context(), pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(t.Context()); err == nil {
		t.Fatal("exhausted source unexpectedly succeeded")
	}
	if attemptsA.Load() != 3 || attemptsB.Load() != 5 {
		t.Fatalf("actual HTTP attempts = %d/%d, want 3/5", attemptsA.Load(), attemptsB.Load())
	}
	// A replacement service reads durable SQL state rather than process counters.
	restarted, err := New(t.Context(), pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Feeds(t.Context())
	if err != nil || len(status.GetFeeds()) != 2 {
		t.Fatalf("feed status: %v %v", status, err)
	}
	for index, want := range []uint64{2, 4} {
		got := status.Feeds[index]
		if got.GetRequestRetryCount() != want || got.GetAttemptedAt() == nil || got.GetFresh() {
			t.Fatalf("latest attempt accounting/coverage: %v", got)
		}
		if (got.GetError() != "") != (index == 1) || (got.GetCheckedAt() != nil) != (index == 0) {
			t.Fatalf("success/failure publication evidence: %v", got)
		}
	}
	phase.Store(1)
	if err := restarted.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err = restarted.Feeds(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range status.Feeds {
		if got.GetRequestRetryCount() != 0 || got.GetError() != "" || got.GetCheckedAt() == nil || got.GetFresh() {
			t.Fatalf("no-retry refresh did not reset without inventing coverage: %v", got)
		}
	}
}

func TestRequestRetriesRetainedOnDocumentAuthenticationFailureAndCancellation(t *testing.T) {
	for _, outcome := range []string{"document", "authentication", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			cancelRefresh := outcome == "cancelled"
			pool, _ := testdb.Open(t)
			var attempts atomic.Int64
			entered := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if cancelRefresh {
					close(entered)
					<-r.Context().Done()
					return
				}
				if outcome == "authentication" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte("not an advisory document"))
			}))
			defer server.Close()
			source := &advisoryv1.FeedSource{Id: "failure", Distro: "ubuntu", Release: "24.04", Url: server.URL, Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, MaxAgeSeconds: 86400}
			s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Refresh(ctx) }()
			if cancelRefresh {
				select {
				case <-entered:
					cancel()
				case <-time.After(15 * time.Second):
					t.Fatal("retry request never began")
				}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("failed refresh reported success")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("refresh did not finish")
			}
			status, err := s.Feeds(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			got := status.Feeds[0]
			if attempts.Load() != 2 || got.GetRequestRetryCount() != 1 || got.GetAttemptedAt() == nil || got.GetCheckedAt() != nil || got.GetFresh() || got.GetRefreshing() || (got.GetError() == "") != cancelRefresh {
				t.Fatalf("failed/cancelled latest attempt: %v attempts=%d", got, attempts.Load())
			}
		})
	}
}

func TestRequestRetryAccountingRequiresExactConfigurationAndLiveLease(t *testing.T) {
	for _, fence := range []string{"configuration", "expired", "missing", "newer-attempt"} {
		t.Run(fence, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			s, source, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			q := advisorydb.New(pool)
			generation := uuid.New()
			started := time.Now().UTC().Truncate(time.Microsecond)
			if err := q.StartAdvisoryGeneration(t.Context(), advisorydb.StartAdvisoryGenerationParams{FeedID: source.Id, Generation: generation, ConfigBytes: encoded, StartedAt: timestamp(started)}); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), "UPDATE advisory_feeds SET request_retry_count=7 WHERE id=$1", source.Id); err != nil {
				t.Fatal(err)
			}
			switch fence {
			case "configuration":
				replacement := proto.CloneOf(source)
				replacement.Url += "?replacement"
				s.config.Feeds = []*advisoryv1.FeedSource{replacement}
				if err := s.reconcileFeeds(t.Context()); err != nil {
					t.Fatal(err)
				}
			case "expired":
				_, err = pool.Exec(t.Context(), "UPDATE advisory_generation_cleanup SET cleanup_after=clock_timestamp()-interval '1 second' WHERE generation=$1", generation)
			case "missing":
				_, err = pool.Exec(t.Context(), "DELETE FROM advisory_generation_cleanup WHERE generation=$1", generation)
			case "newer-attempt":
				_, err = pool.Exec(t.Context(), "UPDATE advisory_feeds SET attempted_at=$2 WHERE id=$1", source.Id, started.Add(time.Second))
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := q.GetAdvisoryFeed(t.Context(), source.Id)
			if err != nil {
				t.Fatal(err)
			}
			updated, err := q.BeginAdvisoryRefreshAttempt(t.Context(), advisorydb.BeginAdvisoryRefreshAttemptParams{ID: source.Id, AttemptedAt: timestamp(started), ConfigBytes: encoded, Generation: generation})
			if err != nil || updated != 0 {
				t.Fatalf("stale start crossed %s fence: %d %v", fence, updated, err)
			}
			if err := q.FailAdvisoryFeed(t.Context(), advisorydb.FailAdvisoryFeedParams{ID: source.Id, AttemptedAt: timestamp(started), ConfigBytes: encoded, Generation: generation, RequestRetryCount: 4, Error: "refresh_failed"}); err != nil {
				t.Fatal(err)
			}
			after, err := q.GetAdvisoryFeed(t.Context(), source.Id)
			if err != nil || before.RequestRetryCount != after.RequestRetryCount || before.Error != after.Error || before.AttemptedAt != after.AttemptedAt {
				t.Fatalf("stale completion crossed %s fence: before=%+v after=%+v err=%v", fence, before, after, err)
			}
		})
	}
}
