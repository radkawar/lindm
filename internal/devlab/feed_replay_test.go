package devlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestFeedReplayChecksRecordedBytesWithoutVendorEgress(t *testing.T) {
	replay, artifact := replayTestFixture(t)
	client, closeClient, err := replay.openClient(artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, artifact.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read replay: %v %v", err, closeErr)
	}
	if response.StatusCode != http.StatusOK || string(raw) != "recorded vendor bytes" {
		t.Fatalf("replay response: %d %q", response.StatusCode, raw)
	}
	if response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("replay did not use genuinely verified loopback TLS")
	}
	if replay.Artifacts[0].Revalidated {
		t.Fatal("offline replay retained historical revalidation claim")
	}
	// The same bytes cannot silently exceed the aggregate budget on a repeat.
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("budget status=%d", response.StatusCode)
	}
}

func TestFeedReplayRejectsMissingCorruptAndUnrecordedArtifacts(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "unrecorded"} {
		t.Run(mode, func(t *testing.T) {
			replay, artifact := replayTestFixture(t)
			path := filepath.Join(replay.cacheDirectory, artifact.SHA256)
			url := artifact.URL
			want := http.StatusUnprocessableEntity
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, int(artifact.Bytes)), 0600); err != nil {
					t.Fatal(err)
				}
			case "unrecorded":
				url = "https://unrecorded.invalid/feed"
				want = http.StatusNotFound
			}
			client, closeClient, err := replay.openClient(1024)
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != want {
				t.Fatalf("status=%d want=%d", response.StatusCode, want)
			}
		})
	}
}

func TestFeedReplayManifestRejectsDuplicateURLs(t *testing.T) {
	replay, artifact := replayTestFixture(t)
	manifestPath := filepath.Join(replay.cacheDirectory, "manifest.json")
	encoded, err := json.Marshal([]AcceptanceFeedArtifact{artifact, artifact})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFeedReplay(replay.cacheDirectory, manifestPath, filepath.Join(replay.cacheDirectory, "sources.json")); err == nil {
		t.Fatal("accepted ambiguous duplicate URL recording")
	}
}

func TestFeedReplayHashFramesFields(t *testing.T) {
	a, b := sha256.New(), sha256.New()
	hashReplayField(a, []byte("ab"))
	hashReplayField(a, []byte("c"))
	hashReplayField(b, []byte("a"))
	hashReplayField(b, []byte("bc"))
	if bytes.Equal(a.Sum(nil), b.Sum(nil)) {
		t.Fatal("field boundaries omitted from digest")
	}
}

func TestFeedBenchmarkSourcesCoverSupportedFamilies(t *testing.T) {
	cfg, err := FeedBenchmarkSources([]string{"ubuntu", "fedora", "rhel", "debian", "suse", "arch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GetFeeds()) != 6 {
		t.Fatalf("sources=%d", len(cfg.GetFeeds()))
	}
	if _, err := FeedBenchmarkSources([]string{"ubuntu", "ubuntu"}); err == nil {
		t.Fatal("duplicate source accepted")
	}
	if _, err := FeedBenchmarkSources([]string{"unsupported"}); err == nil {
		t.Fatal("unsupported source accepted")
	}
}

func replayTestFixture(t *testing.T) (*FeedReplay, AcceptanceFeedArtifact) {
	t.Helper()
	directory := t.TempDir()
	raw := []byte("recorded vendor bytes")
	digest := sha256.Sum256(raw)
	artifact := AcceptanceFeedArtifact{URL: "https://security.archlinux.org/all.json", SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(raw)), Revalidated: true}
	manifest, err := json.Marshal([]AcceptanceFeedArtifact{artifact})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := FeedBenchmarkSources([]string{"arch"})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := protojson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{artifact.SHA256: raw, "manifest.json": manifest, "sources.json": sources} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	replay, err := LoadFeedReplay(directory, filepath.Join(directory, "manifest.json"), filepath.Join(directory, "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	return replay, artifact
}
