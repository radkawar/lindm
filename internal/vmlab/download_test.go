package vmlab

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestDownloadBoundaries(t *testing.T) {
	var escaped atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		escaped.Add(1)
		_, _ = w.Write([]byte("escape"))
	}))
	defer other.Close()
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		escaped.Add(1)
		_, _ = w.Write([]byte("downgrade"))
	}))
	defer plaintext.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("verified transport bytes"))
		case "/same-origin":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/cross-origin":
			http.Redirect(w, r, other.URL, http.StatusFound)
		case "/downgrade":
			http.Redirect(w, r, plaintext.URL, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/too-large":
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
		case "/chunked-too-large":
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
		case "/truncated":
			w.Header().Set("Content-Length", "30")
			_, _ = w.Write([]byte("short"))
		case "/encoded":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("not identity"))
		case "/slow":
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	fetcher := Fetcher{transport: server.Client().Transport}
	client := fetcher.client()
	defer client.CloseIdleConnections()
	for _, path := range []string{"ok", "same-origin", "cross-origin", "downgrade", "loop", "too-large", "chunked-too-large", "truncated", "encoded", "slow", "missing"} {
		t.Run(path, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			timeout := 2 * time.Second
			if path == "slow" {
				timeout = 50 * time.Millisecond
			}
			err = download(context.Background(), client, root, "staging", server.URL+"/"+path, 64, timeout)
			if path == "ok" || path == "same-origin" {
				if err != nil {
					t.Fatal(err)
				}
				content, err := root.ReadFile("staging")
				if err != nil || string(content) != "verified transport bytes" {
					t.Fatalf("download changed payload: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe transfer succeeded")
			}
			if path == "slow" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline ignored: %v", err)
			}
		})
	}
	if escaped.Load() != 0 {
		t.Fatalf("redirect leaked %d requests to unauthorized origins", escaped.Load())
	}
	t.Run("existing staging is not overwritten", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := root.WriteFile("existing", []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := download(context.Background(), client, root, "existing", server.URL+"/ok", 64, time.Second); err == nil {
			t.Fatal("existing staging overwritten")
		}
		data, err := root.ReadFile("existing")
		if err != nil || string(data) != "preserve" {
			t.Fatalf("existing file changed: %v", err)
		}
	})
	t.Run("system roots reject untrusted TLS", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		client := (Fetcher{}).client()
		defer client.CloseIdleConnections()
		if err := download(context.Background(), client, root, "staging", server.URL+"/ok", 64, time.Second); err == nil {
			t.Fatal("untrusted server certificate accepted")
		}
	})
}

func TestStrictManifestBoundaries(t *testing.T) {
	base := testManifest([]byte("image"), strings.Repeat("A", 40), labv1.ChecksumMode_CHECKSUM_MODE_DETACHED)
	for _, test := range []struct {
		name   string
		change func(*labv1.ImageManifest)
	}{
		{"missing signature", func(m *labv1.ImageManifest) { m.SignatureUrl = nil }},
		{"clearsigned with signature", func(m *labv1.ImageManifest) { m.ChecksumMode = labv1.ChecksumMode_CHECKSUM_MODE_CLEARSIGNED }},
		{"no checksum mode", func(m *labv1.ImageManifest) { m.ChecksumMode = 0 }},
		{"unbounded size", func(m *labv1.ImageManifest) { m.ImageSizeBytes = 0 }},
		{"excessive size", func(m *labv1.ImageManifest) { m.ImageSizeBytes = 1 << 40 }},
		{"short fingerprint", func(m *labv1.ImageManifest) { m.SignerFingerprint = "DEADBEEF" }},
		{"plaintext source", func(m *labv1.ImageManifest) { m.ImageUrl = "http://example.invalid/image.qcow2" }},
		{"credential source", func(m *labv1.ImageManifest) { m.KeyUrl = "https://user:password@example.invalid/key" }},
		{"fragment source", func(m *labv1.ImageManifest) { m.KeyUrl += "#key" }},
		{"path traversal", func(m *labv1.ImageManifest) { m.ImageFilename = "../image.qcow2" }},
		{"wrong basename", func(m *labv1.ImageManifest) { m.ImageFilename = "other.qcow2" }},
		{"moving release", func(m *labv1.ImageManifest) { m.Release = "latest" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := proto.CloneOf(base)
			test.change(m)
			data, err := protojson.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "image.json")
			if err := os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadManifest(file); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	data, err := protojson.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		strings.TrimSuffix(string(data), "}") + `,"unexpected":true}`,
		strings.TrimSuffix(string(data), "}") + `,"id":"duplicate"}`,
		string(data) + ` {}`,
	} {
		file := filepath.Join(t.TempDir(), "image.json")
		if err := os.WriteFile(file, []byte(malformed), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadManifest(file); err == nil {
			t.Fatal("non-strict JSON accepted")
		}
	}
	base.KeyUrl = "https://example.invalid/pks/lookup?op=get&search=0x" + base.SignerFingerprint
	if err := validateManifest(base); err != nil {
		t.Fatalf("HTTPS vendor key lookup should be permitted: %v", err)
	}
}
