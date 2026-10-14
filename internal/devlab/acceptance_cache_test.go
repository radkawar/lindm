// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

// A cached refresh inherits the lab duration as its idle bound only where the
// source sets none, and never mutates the caller's configuration.
func TestCachedRefreshConfigBoundsIdleWithoutMutatingSource(t *testing.T) {
	source := &configv1.AdvisoryConfig{RefreshEnabled: true, Feeds: []*advisoryv1.FeedSource{{Id: "unset"}, {Id: "explicit", ProgressTimeoutSeconds: proto.Uint32(120)}}}
	refresh := cachedRefreshConfig(source, 2*time.Hour)
	if !refresh.GetRefreshEnabled() || refresh.GetFeeds()[0].GetProgressTimeoutSeconds() != 3600 || refresh.GetFeeds()[1].GetProgressTimeoutSeconds() != 120 {
		t.Fatalf("refresh config = %v", refresh)
	}
	if source.GetFeeds()[0].ProgressTimeoutSeconds != nil {
		t.Fatal("caller's configuration was mutated")
	}
}

func TestAcceptanceFeedCacheRevalidatesAndChecksDigest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("If-None-Match") == `"version-one"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"version-one"`)
		_, _ = io.WriteString(w, "vendor bytes")
	}))
	defer server.Close()
	cache := &acceptanceFeedCache{base: http.DefaultTransport, directory: t.TempDir(), remaining: 1024}
	fetch := func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		if err != nil {
			return err
		}
		response, err := cache.RoundTrip(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(response.Body)
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err == nil && string(body) != "vendor bytes" {
			t.Fatalf("cache changed vendor content: %q", body)
		}
		return err
	}
	if err := fetch(); err != nil {
		t.Fatal(err)
	}
	if err := fetch(); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(cache.artifacts) != 2 || !cache.artifacts[1].Revalidated {
		t.Fatalf("cache bypassed current vendor validation: requests=%d artifacts=%v", requests, cache.artifacts)
	}
	if err := os.WriteFile(filepath.Join(cache.directory, cache.artifacts[0].SHA256), []byte("corrupt file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := fetch(); err == nil {
		t.Fatal("accepted corrupt digest-addressed cache entry")
	}
}

func TestAcceptanceFeedCacheEnforcesSizeBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "too large")
	}))
	defer server.Close()
	cache := &acceptanceFeedCache{base: http.DefaultTransport, directory: t.TempDir(), remaining: 3}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := cache.RoundTrip(req); err == nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatal("accepted over-budget vendor response")
	}
	entries, err := os.ReadDir(cache.directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != fmt.Sprintf("%x.json.lock", sha256.Sum256([]byte(server.URL))) {
		t.Fatal("failed fetch retained an incomplete cache entry")
	}
}

func TestAcceptanceFeedCacheWaitsForOtherRefreshAndHonorsCancellation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"vendor-version"`)
		_, _ = io.WriteString(w, "vendor bytes")
	}))
	defer server.Close()
	directory := t.TempDir()
	lockPath := filepath.Join(directory, fmt.Sprintf("%x.json.lock", sha256.Sum256([]byte(server.URL))))
	lock, err := lockAcceptanceFeedCache(t.Context(), lockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if lock != nil {
			if err := lock.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	cache := &acceptanceFeedCache{base: http.DefaultTransport, directory: directory, remaining: 1024}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := cache.RoundTrip(request)
	if response != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) || requests.Load() != 0 {
		t.Fatalf("concurrent refresh bypassed cache lock: requests=%d err=%v", requests.Load(), err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock = nil
	request = request.Clone(t.Context())
	response, err = cache.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("released refresh lock did not permit vendor revalidation")
	}
}

func TestAcceptanceFeedCacheSlowDownloadDoesNotBlockOtherURL(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared-client-%t", shared), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			resume, release := context.WithCancel(ctx)
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"vendor-version"`)
				if r.URL.Path == "/slow" {
					_, _ = io.WriteString(w, "slow ")
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error(err)
					}
					close(started)
					select {
					case <-resume.Done():
					case <-r.Context().Done():
						return
					}
				}
				_, _ = io.WriteString(w, "vendor bytes")
			}))
			defer server.Close()
			defer release()
			directory := t.TempDir()
			slow := &acceptanceFeedCache{base: http.DefaultTransport, directory: directory, remaining: 1024}
			fast := slow
			if !shared {
				fast = &acceptanceFeedCache{base: http.DefaultTransport, directory: directory, remaining: 1024}
			}
			fetch := func(ctx context.Context, cache *acceptanceFeedCache, path, want string) error {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+path, nil)
				if err != nil {
					return err
				}
				response, err := cache.RoundTrip(request)
				if err != nil {
					return err
				}
				body, err := io.ReadAll(response.Body)
				err = errors.Join(err, response.Body.Close())
				if err == nil && string(body) != want {
					return fmt.Errorf("vendor bytes changed: %q", body)
				}
				return err
			}
			done := make(chan error, 1)
			go func() { done <- fetch(ctx, slow, "/slow", "slow vendor bytes") }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			fastCtx, fastCancel := context.WithTimeout(ctx, time.Second)
			defer fastCancel()
			if err := fetch(fastCtx, fast, "/fast", "vendor bytes"); err != nil {
				t.Errorf("unrelated URL blocked by slow download: %v", err)
			}
			release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if shared && (slow.remaining != 1024-29 || len(slow.artifacts) != 2) {
				t.Fatalf("concurrent bookkeeping lost data: remaining=%d artifacts=%v", slow.remaining, slow.artifacts)
			}
		})
	}
}
