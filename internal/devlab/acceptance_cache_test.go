package devlab

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
	if len(entries) != 0 {
		t.Fatal("failed fetch retained an incomplete cache entry")
	}
}
