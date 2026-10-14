// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestConcurrentFetchOfflineVerificationAndCorruption(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("immutable image fixture\n")
	m := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED)
	checksums, signature := fixture.signed(t, m, checksumText(m))
	var imageRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/image.qcow2":
			imageRequests.Add(1)
			_, _ = w.Write(image)
		case "/checksums":
			_, _ = w.Write(checksums)
		case "/signature":
			_, _ = w.Write(signature)
		case "/key":
			_, _ = w.Write(fixture.key)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	setSources(m, server.URL)
	fetcher := Fetcher{transport: server.Client().Transport}
	cache := filepath.Join(t.TempDir(), "images")
	const clients = 6
	results := make(chan *VerifiedImage, clients)
	failures := make(chan error, clients)
	var group sync.WaitGroup
	for range clients {
		group.Go(func() {
			result, err := fetcher.Fetch(context.Background(), m, cache)
			results <- result
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var path string
	for result := range results {
		if path != "" && path != result.Path {
			t.Fatal("concurrent fetch published different images")
		}
		path = result.Path
	}
	if imageRequests.Load() != 1 {
		t.Fatalf("image downloaded %d times", imageRequests.Load())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0444 {
		t.Fatalf("cached base image is writable: %v", info.Mode())
	}
	server.Close()
	verified, err := VerifyCache(context.Background(), m, cache)
	if err != nil {
		t.Fatalf("offline verification: %v", err)
	}
	if verified.Path != path {
		t.Fatalf("offline path changed: %s", verified.Path)
	}
	cached, err := fetcher.Fetch(context.Background(), m, cache)
	if err != nil || cached.Path != path {
		t.Fatalf("offline cache reuse: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("cache reuse modified the base image")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(image)
	changed[0] ^= 1
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	for _, verify := range []func() (*VerifiedImage, error){
		func() (*VerifiedImage, error) { return VerifyCache(context.Background(), m, cache) },
		func() (*VerifiedImage, error) { return fetcher.Fetch(context.Background(), m, cache) },
	} {
		if _, err := verify(); err == nil || !strings.Contains(err.Error(), "image bytes do not match") {
			t.Fatalf("corrupt cached bytes were trusted or replaced: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, changed) {
		t.Fatalf("failed verification mutated cache: %v", err)
	}
}

func setSources(m *labv1.ImageManifest, origin string) {
	m.ImageUrl = origin + "/image.qcow2"
	m.ChecksumUrl = origin + "/checksums"
	m.KeyUrl = origin + "/key"
	if m.SignatureUrl != nil {
		m.SignatureUrl = proto.String(origin + "/signature")
	}
}

func TestInterruptedAndStaleDownloadsAreCleaned(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("complete image after interruption\n")
	m := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED)
	checksums, _ := fixture.signed(t, m, checksumText(m))
	started := make(chan struct{})
	var interrupted atomic.Bool
	interrupted.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums":
			_, _ = w.Write(checksums)
		case "/key":
			_, _ = w.Write(fixture.key)
		case "/image.qcow2":
			if interrupted.Load() {
				w.Header().Set("Content-Length", fmt.Sprint(len(image)))
				_, _ = w.Write(image[:3])
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
					return
				}
				close(started)
				<-r.Context().Done()
				return
			}
			_, _ = w.Write(image)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setSources(m, server.URL)
	fetcher := Fetcher{transport: server.Client().Transport}
	cache := filepath.Join(t.TempDir(), "images")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := fetcher.Fetch(ctx, m, cache); done <- err }()
	select {
	case <-started:
		cancel()
	case err := <-done:
		t.Fatalf("fetch failed before image interruption: %v", err)
	case <-ctx.Done():
		t.Fatal("image transfer did not start")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("interruption: %v", err)
	}
	entry := "sha256-" + m.Sha256
	partial := "." + entry + ".partial"
	for _, name := range []string{entry, partial} {
		if _, err := os.Stat(filepath.Join(cache, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("interrupted transfer left %s: %v", name, err)
		}
	}
	// This is the owned staging state a killed process would leave behind.
	if err := os.Mkdir(filepath.Join(cache, partial), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, partial, "image"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	interrupted.Store(false)
	if _, err := fetcher.Fetch(context.Background(), m, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache, partial)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale staging not cleaned: %v", err)
	}
}

func TestCacheOwnershipAndLockBoundaries(t *testing.T) {
	ctx := context.Background()
	t.Run("unmarked directory is never adopted", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "important")
		if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := openCache(ctx, dir, true); err == nil {
			t.Fatal("arbitrary nonempty directory adopted")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "preserve" {
			t.Fatalf("arbitrary file changed: %v", err)
		}
	})
	t.Run("symlink cache rejected", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatal(err)
		}
		if _, err := openCache(ctx, link, true); err == nil {
			t.Fatal("symlink cache accepted")
		}
	})
	t.Run("lock wait honors cancellation", func(t *testing.T) {
		root, err := openCache(ctx, filepath.Join(t.TempDir(), "images"), true)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		digest := strings.Repeat("a", 64)
		lock, err := lockImage(ctx, root, digest)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		deadline, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := lockImage(deadline, root, digest); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lock ignored deadline: %v", err)
		}
	})
	t.Run("lock symlink never written", func(t *testing.T) {
		root, err := openCache(ctx, filepath.Join(t.TempDir(), "images"), true)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		digest := strings.Repeat("b", 64)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(root.Name(), "."+digest+".lock")); err != nil {
			t.Fatal(err)
		}
		if _, err := lockImage(ctx, root, digest); err == nil {
			t.Fatal("symlink lock accepted")
		}
		data, err := os.ReadFile(victim)
		if err != nil || string(data) != "preserve" {
			t.Fatalf("lock touched arbitrary target: %v", err)
		}
	})
}

func TestFetchRejectsUnsignedMetadataBeforeImageDownload(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("must never be downloaded")
	m := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED)
	var imageRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums":
			_, _ = w.Write([]byte(checksumText(m)))
		case "/key":
			_, _ = w.Write(fixture.key)
		case "/image.qcow2":
			imageRequests.Add(1)
			_, _ = w.Write(image)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setSources(m, server.URL)
	cache := filepath.Join(t.TempDir(), "images")
	fetcher := Fetcher{transport: server.Client().Transport}
	if _, err := fetcher.Fetch(context.Background(), m, cache); err == nil {
		t.Fatal("unsigned vendor metadata was accepted")
	}
	if imageRequests.Load() != 0 {
		t.Fatal("image was downloaded before its metadata was authenticated")
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "sha256-") || strings.HasSuffix(entry.Name(), ".partial") {
			t.Fatalf("unauthenticated acquisition was retained: %s", entry.Name())
		}
	}
}
