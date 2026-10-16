// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
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
			if _, err := pool.Exec(t.Context(), "UPDATE advisory_feeds SET request_retry_count=7,vendor_race_refetch_count=9 WHERE id=$1", source.Id); err != nil {
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
				_, err = pool.Exec(t.Context(), "UPDATE advisory_feeds SET attempted_at=$2,error='newer_failure' WHERE id=$1", source.Id, started.Add(time.Second))
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
			if err := q.FailAdvisoryFeed(t.Context(), advisorydb.FailAdvisoryFeedParams{ID: source.Id, AttemptedAt: timestamp(started), ConfigBytes: encoded, Generation: generation, RequestRetryCount: 4, VendorRaceRefetchCount: 2, Error: "refresh_failed"}); err != nil {
				t.Fatal(err)
			}
			if fence == "newer-attempt" {
				updated, err := q.PublishAdvisoryFeed(t.Context(), advisorydb.PublishAdvisoryFeedParams{
					ID: source.Id, Revision: before.Revision, SourceSha256: []byte{}, SourceManifest: []byte{},
					CheckedAt: timestamp(started), ConfigBytes: encoded, RefreshAttempt: true,
					RequestRetryCount: 4, VendorRaceRefetchCount: 2,
				})
				if err != nil || updated != 1 {
					t.Fatalf("older successful publication: updated=%d err=%v", updated, err)
				}
			}
			after, err := q.GetAdvisoryFeed(t.Context(), source.Id)
			if err != nil || before.RequestRetryCount != after.RequestRetryCount || before.VendorRaceRefetchCount != after.VendorRaceRefetchCount || before.Error != after.Error || before.AttemptedAt != after.AttemptedAt {
				t.Fatalf("stale completion crossed %s fence: before=%+v after=%+v err=%v", fence, before, after, err)
			}
		})
	}
}

func TestVendorRaceRefetchesPersistLatestAttemptAndIsolateSources(t *testing.T) {
	pool, _ := testdb.Open(t)
	fixtures := make(map[string][]byte, 3)
	for _, suffix := range []string{"", ".sha256", ".asc"} {
		raw, err := os.ReadFile("feed/testdata/redhat-rhsa-2024_6783.json" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[suffix] = raw
	}
	var requestsA, requestsB atomic.Int64
	var checksumsA atomic.Int64
	var phase atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter := &requestsA
		second := strings.HasPrefix(r.URL.Path, "/b/")
		if second {
			counter = &requestsB
		}
		suffix := strings.TrimPrefix(r.URL.Path, "/a/rhsa-2024_6783.json")
		if second {
			suffix = strings.TrimPrefix(r.URL.Path, "/b/rhsa-2024_6783.json")
		}
		if suffix == "" {
			attempt := counter.Add(1)
			// Source a has one transport retry and one vendor race. Source b
			// exhausts all three complete sets without an HTTP transport retry.
			if phase.Load() == 0 && !second && attempt == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		if suffix == ".sha256" && phase.Load() == 0 {
			if second || checksumsA.Add(1) == 1 {
				_, _ = w.Write([]byte(strings.Repeat("0", 64) + "  rhsa-2024_6783.json\n"))
				return
			}
		}
		raw, ok := fixtures[suffix]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	cfg := &configv1.AdvisoryConfig{}
	for index, arch := range []string{"x86_64", "aarch64"} {
		id := string(rune('a' + index))
		cfg.Feeds = append(cfg.Feeds, &advisoryv1.FeedSource{
			Id: id, Distro: "rhel", Release: "9", Architecture: arch, PlatformStream: "standard",
			Url:    server.URL + "/" + id + "/rhsa-2024_6783.json",
			Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, MaxAgeSeconds: 86400,
		})
	}
	s, err := New(t.Context(), pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	var inherited atomic.Int64
	inherited.Store(99)
	ctx := feed.WithVendorRaceRefetchCounter(t.Context(), &inherited)
	if err := s.Refresh(ctx); err == nil {
		t.Fatal("exhausted source unexpectedly succeeded")
	}
	if requestsA.Load() != 3 || requestsB.Load() != 3 || inherited.Load() != 99 {
		t.Fatalf("request/counter isolation: requests=%d/%d inherited=%d", requestsA.Load(), requestsB.Load(), inherited.Load())
	}
	restarted, err := New(t.Context(), pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Feeds(t.Context())
	if err != nil || len(status.GetFeeds()) != 2 {
		t.Fatalf("feed status after restart: %v %v", status, err)
	}
	for index, want := range []uint64{1, 2} {
		got := status.Feeds[index]
		if got.GetVendorRaceRefetchCount() != want || got.GetRequestRetryCount() != uint64(1-index) || got.GetAttemptedAt() == nil || got.GetFresh() || got.GetRefreshing() || len(got.GetRejectedRecords()) != 0 {
			t.Fatalf("distinct latest-attempt counters/coverage: %v", got)
		}
		if (got.GetError() != "") != (index == 1) || (got.GetCheckedAt() != nil) != (index == 0) {
			t.Fatalf("success/failure publication evidence: %v", got)
		}
	}
	phase.Store(1)
	if err := restarted.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	status, err = restarted.Feeds(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range status.Feeds {
		if got.GetVendorRaceRefetchCount() != 0 || got.GetRequestRetryCount() != 0 || got.GetError() != "" || got.GetCheckedAt() == nil || got.GetFresh() {
			t.Fatalf("new no-refetch attempt did not reset accounting: %v", got)
		}
	}
}

func TestVendorRaceRefetchesSurviveCancellationAndRestart(t *testing.T) {
	pool, _ := testdb.Open(t)
	raw, err := os.ReadFile("feed/testdata/redhat-rhsa-2024_6783.json")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile("feed/testdata/redhat-rhsa-2024_6783.json.asc")
	if err != nil {
		t.Fatal(err)
	}
	var payloads atomic.Int64
	entered := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			_, _ = w.Write([]byte(strings.Repeat("0", 64) + "  rhsa-2024_6783.json\n"))
		case strings.HasSuffix(r.URL.Path, ".asc"):
			_, _ = w.Write(signature)
		default:
			if payloads.Add(1) == 2 {
				close(entered)
				<-r.Context().Done()
				return
			}
			_, _ = w.Write(raw)
		}
	}))
	defer server.Close()
	source := &advisoryv1.FeedSource{
		Id: "cancelled", Distro: "rhel", Release: "9", Architecture: "x86_64", PlatformStream: "standard",
		Url: server.URL + "/rhsa-2024_6783.json", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, MaxAgeSeconds: 86400,
	}
	cfg := &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}
	s, err := New(t.Context(), pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Refresh(ctx) }()
	select {
	case <-entered:
		cancel()
	case <-time.After(15 * time.Second):
		t.Fatal("fresh consistent set never began")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled refresh reported success")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("cancelled refresh did not finish")
	}
	restarted, err := New(t.Context(), pool, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Feeds(t.Context())
	if err != nil || len(status.GetFeeds()) != 1 {
		t.Fatalf("cancelled feed status after restart: %v %v", status, err)
	}
	got := status.Feeds[0]
	if got.GetVendorRaceRefetchCount() != 1 || got.GetRequestRetryCount() != 0 || got.GetAttemptedAt() == nil || got.GetCheckedAt() != nil || got.GetFresh() || got.GetRefreshing() || got.GetError() != "" {
		t.Fatalf("cancelled refresh accounting changed status/coverage: %v", got)
	}
}

func TestLatestRefreshCountersRemainNonnegativeAndPreserveSQLPrecision(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, _ := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	row, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil || row.RequestRetryCount != 0 || row.VendorRaceRefetchCount != 0 {
		t.Fatalf("counter defaults: %+v %v", row, err)
	}
	for _, column := range []string{"request_retry_count", "vendor_race_refetch_count"} {
		if _, err := pool.Exec(t.Context(), "UPDATE advisory_feeds SET "+column+"=-1 WHERE id=$1", source.Id); err == nil {
			t.Fatalf("negative %s was accepted", column)
		}
	}
	const large = uint64(9223372036854775807)
	if _, err := pool.Exec(t.Context(), "UPDATE advisory_feeds SET request_retry_count=9223372036854775807,vendor_race_refetch_count=9223372036854775807 WHERE id=$1", source.Id); err != nil {
		t.Fatal(err)
	}
	status, err := s.Feeds(t.Context())
	if err != nil || len(status.GetFeeds()) != 1 {
		t.Fatalf("large counter status: %v %v", status, err)
	}
	if got := status.Feeds[0]; got.GetRequestRetryCount() != large || got.GetVendorRaceRefetchCount() != large || got.GetAttemptedAt() != nil || got.GetCheckedAt() != nil || got.GetFresh() {
		t.Fatalf("counter precision changed or invented publication evidence: %v", got)
	}
}
