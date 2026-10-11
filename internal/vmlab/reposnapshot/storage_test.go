package reposnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestManifestContentAddress(t *testing.T) {
	original := &labv1.RepositorySnapshotManifest{Distribution: "distribution", Architecture: "architecture", SnapshotDate: "2026-10-07", RequestedPackages: []string{"a", "b"}, BasePackages: []string{"a\t0:1-1.aarch64"}, Files: []*labv1.RepositorySnapshotFile{{Path: "a.rpm", Sha256: strings.Repeat("a", 64), SizeBytes: 1}}, MaxBytes: 1024, MaxPackages: 2}
	first, err := identity(original)
	if err != nil {
		t.Fatal(err)
	}
	original.ManifestSha256 = first
	same, err := identity(original)
	if err != nil || same != first {
		t.Fatalf("self field changed identity: %q %v", same, err)
	}
	changed := proto.CloneOf(original)
	changed.BasePackages[0] = "a\t0:2-1.aarch64"
	second, err := identity(changed)
	if err != nil || second == first {
		t.Fatalf("base inventory not bound: %q %v", second, err)
	}
	changed = proto.CloneOf(original)
	changed.MaxPackages++
	second, err = identity(changed)
	if err != nil || second == first {
		t.Fatalf("bounds not bound: %q %v", second, err)
	}
}

func TestSnapshotPathAndDigestBoundaries(t *testing.T) {
	for _, p := range []string{"", ".", "/repodata/repomd.xml", "../rpm", "a/../../rpm", "a//rpm", "./rpm", "a\\rpm", "a\x00rpm", "a/$command.rpm", "a/quoted\".rpm", "a/query?x", "a/%2f.rpm"} {
		if safePath(p) {
			t.Errorf("unsafe path accepted: %q", p)
		}
	}
	for _, p := range []string{"repodata/repomd.xml", "aarch64/package-1.0.rpm"} {
		if !safePath(p) {
			t.Errorf("safe path rejected: %q", p)
		}
	}
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("z", 64), "../entry"} {
		if _, _, err := Load(t.TempDir(), digest); err == nil {
			t.Errorf("invalid digest accepted: %q", digest)
		}
	}
}

func TestCaptureBackendAndBoundsGateBeforeAcquisition(t *testing.T) {
	for _, o := range []CaptureOptions{
		{Distribution: "arch", Architecture: "x86_64"},
		{Distribution: "opensuse-tumbleweed", Architecture: "s390x"},
		{Distribution: "opensuse-tumbleweed", Architecture: "aarch64", RepomdSHA256: strings.Repeat("a", 64), BaseImageSHA256: strings.Repeat("b", 64), MaxBytes: HardMaxBytes + 1, MaxPackages: 1},
	} {
		if _, err := NewCapture(context.Background(), o); err == nil {
			t.Fatalf("unsupported or unbounded capture accepted: %+v", o)
		}
	}
}

func TestOfflineClosureNeverFetchesMissingRPM(t *testing.T) {
	c := &Capture{ctx: context.Background(), admitted: make(chan struct{}, 16), gate: make(chan struct{}, 1), offline: true, files: map[string]bool{}, allowed: map[string]rpmPackage{"aarch64/a.rpm": {}}, Manifest: &labv1.RepositorySnapshotManifest{MaxPackages: 1}}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/aarch64/a.rpm", nil)
	response := httptest.NewRecorder()
	c.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || c.failure == nil {
		t.Fatalf("incomplete closure not rejected: status %d", response.Code)
	}
}

func TestCaptureProxyRejectsUnlistedPathsAndWrites(t *testing.T) {
	c := &Capture{ctx: context.Background(), admitted: make(chan struct{}, 16), gate: make(chan struct{}, 1), files: map[string]bool{}, allowed: map[string]rpmPackage{}}
	for _, tc := range []struct {
		method, path string
		status       int
	}{{http.MethodGet, "/unlisted.rpm", 404}, {http.MethodGet, "/repodata/../escape", 404}, {http.MethodPost, "/a.rpm", 405}, {http.MethodGet, "/a.rpm?origin=other", 404}} {
		response := httptest.NewRecorder()
		c.ServeHTTP(response, httptest.NewRequest(tc.method, "http://127.0.0.1"+tc.path, nil))
		if response.Code != tc.status {
			t.Errorf("%s %s: %d", tc.method, tc.path, response.Code)
		}
	}
}

func TestCaptureProxyBindsSignedKeyQuery(t *testing.T) {
	root := t.TempDir()
	name, pin := "gpg-pubkey-example.asc", strings.Repeat("A", 40)
	if err := os.WriteFile(filepath.Join(root, name), []byte("retained-key-bytes"), 0400); err != nil {
		t.Fatal(err)
	}
	descriptor, err := openSnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = descriptor.Close() }()
	sum := sha256.Sum256([]byte("retained-key-bytes"))
	capture := &Capture{ctx: context.Background(), admitted: make(chan struct{}, 16), gate: make(chan struct{}, 1), payloadRoot: descriptor, spool: t.TempDir(), Root: root, files: map[string]bool{name: true}, keyPins: map[string]string{name: pin}, Manifest: &labv1.RepositorySnapshotManifest{Files: []*labv1.RepositorySnapshotFile{{Path: name, Sha256: hex.EncodeToString(sum[:]), SizeBytes: uint64(len("retained-key-bytes"))}}}}
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"", http.StatusOK},
		{"fpr=" + pin, http.StatusOK},
		{"fpr=" + strings.Repeat("B", 40), http.StatusNotFound},
		{"fpr=" + pin + "&other=1", http.StatusNotFound},
		{"fpr=" + pin + "&fpr=" + pin, http.StatusNotFound},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/"+name+"?"+tc.query, nil)
		response := httptest.NewRecorder()
		capture.ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Errorf("query %q: got %d, want %d", tc.query, response.Code, tc.status)
		}
	}
}

func TestCaptureLatchesChangedAuthenticatedPayload(t *testing.T) {
	root := t.TempDir()
	name := "repodata/repomd.xml"
	item := retainedFixture(t, root, name, []byte("trusted-content"))
	descriptor, err := openSnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = descriptor.Close() }()
	capture := &Capture{ctx: context.Background(), admitted: make(chan struct{}, 16), gate: make(chan struct{}, 1), payloadRoot: descriptor, spool: t.TempDir(), Root: root, files: map[string]bool{name: true}, Manifest: &labv1.RepositorySnapshotManifest{Files: []*labv1.RepositorySnapshotFile{item}}}
	if err := os.WriteFile(filepath.Join(root, name), []byte("altered-content"), 0600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	capture.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/"+name, nil))
	if response.Code != http.StatusServiceUnavailable || capture.failure == nil || strings.Contains(response.Body.String(), "altered-content") {
		t.Fatalf("changed metadata escaped authentication: %d %q", response.Code, response.Body.String())
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte("trusted-content"), 0600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	capture.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/"+name, nil))
	if response.Code != http.StatusServiceUnavailable || capture.Offline() == nil {
		t.Fatal("restoration cleared permanent capture failure")
	}
}

func TestCaptureCancellationDoesNotPoisonAuthenticatedPayload(t *testing.T) {
	root := t.TempDir()
	name := "repodata/repomd.xml"
	item := retainedFixture(t, root, name, []byte("trusted-content"))
	descriptor, err := openSnapshotRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = descriptor.Close() }()
	capture := &Capture{
		ctx: context.Background(), admitted: make(chan struct{}, 16),
		gate: make(chan struct{}), payloadRoot: descriptor, spool: t.TempDir(),
		Root: root, files: map[string]bool{name: true},
		Manifest: &labv1.RepositorySnapshotManifest{Files: []*labv1.RepositorySnapshotFile{item}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/"+name, nil).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	capture.mu.Lock()
	go func() {
		capture.ServeHTTP(response, request)
		close(done)
	}()
	// Hand off the gate while the mutex prevents payload verification. This
	// cancels after admission deterministically, not before its select.
	<-capture.gate
	cancel()
	capture.mu.Unlock()
	capture.gate <- struct{}{}
	<-done
	if capture.failure != nil || response.Body.Len() != 0 {
		t.Fatalf("cancellation poisoned capture or disclosed content: %v %q", capture.failure, response.Body.String())
	}
	capture.gate = make(chan struct{}, 1)
	response = httptest.NewRecorder()
	capture.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/"+name, nil))
	if response.Code != http.StatusOK || response.Body.String() != "trusted-content" || capture.failure != nil {
		t.Fatalf("valid request failed after cancellation: %d %q %v", response.Code, response.Body.String(), capture.failure)
	}
}

func TestPublishFailureRemovesSealedPrivateTree(t *testing.T) {
	for _, failure := range []string{"corrupt-winner", "partial-file-modes"} {
		t.Run(failure, func(t *testing.T) {
			cache := t.TempDir()
			stage, err := os.MkdirTemp(cache, ".repository-snapshot-")
			if err != nil {
				t.Fatal(err)
			}
			item := retainedFixture(t, filepath.Join(stage, "repository"), "aarch64/package.rpm", []byte("rpm"))
			manifest := &labv1.RepositorySnapshotManifest{Files: []*labv1.RepositorySnapshotFile{item}, MaxBytes: 1024, MaxPackages: 1, TotalBytes: 3, RequestedPackages: []string{"package"}, BasePackages: []string{"package\t0:1-1.aarch64"}, BaseImageSha256: strings.Repeat("a", 64), SolverVersion: "native"}
			digest, err := identity(manifest)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(cache, "repository-snapshots", "sha256", digest)
			if failure == "corrupt-winner" {
				if err := os.MkdirAll(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "sentinel"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filepath.Join(stage, "repository", item.Path)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := publish(cache, stage, manifest); err == nil {
				t.Fatal("invalid publication succeeded")
			}
			if _, err := os.Stat(stage); !os.IsNotExist(err) {
				t.Fatalf("private staging leaked: %v", err)
			}
			if failure == "corrupt-winner" {
				data, err := os.ReadFile(filepath.Join(target, "sentinel"))
				if err != nil || string(data) != "preserve" {
					t.Fatalf("existing target modified: %q %v", data, err)
				}
			}
		})
	}
}

func TestCaptureConsumesOnlySignedRetainedKeyNames(t *testing.T) {
	retained := t.TempDir()
	name := "gpg-pubkey-delegated.asc"
	if err := os.WriteFile(filepath.Join(retained, name), []byte("signed-key"), 0400); err != nil {
		t.Fatal(err)
	}
	capture := &Capture{Root: t.TempDir(), retained: retained, files: map[string]bool{}, keyPins: map[string]string{name: strings.Repeat("A", 40)}, Manifest: &labv1.RepositorySnapshotManifest{MaxBytes: 1024}}
	if err := capture.acquire(name, 1024, nil); err != nil {
		t.Fatal(err)
	}
	if len(capture.Manifest.Files) != 1 || capture.Manifest.Files[0].Path != name {
		t.Fatal("signed retained key omitted")
	}
	if err := ExportMetadata(context.Background(), CaptureOptions{}, nil); err == nil {
		t.Fatal("nil metadata consumer accepted")
	}
}
