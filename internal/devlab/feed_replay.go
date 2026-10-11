package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
)

// FeedReplay is an immutable recording manifest and explicit source configuration.
// It is lab input, not vendor authentication or freshness evidence. Blob names
// are SHA-256 digests in the existing acceptance cache; mutable URL indexes are
// never consulted. The same files must be used for baseline and candidate runs.
type FeedReplay struct {
	Config         *configv1.AdvisoryConfig
	Artifacts      []AcceptanceFeedArtifact
	ManifestSHA256 string
	ConfigSHA256   string
	cacheDirectory string
}

// LoadFeedReplay reads a bounded JSON array of AcceptanceFeedArtifact and strict
// protobuf JSON AdvisoryConfig. Missing recordings fail closed, never go online.
func LoadFeedReplay(cacheDirectory, manifestPath, configPath string) (*FeedReplay, error) {
	if cacheDirectory == "" || manifestPath == "" || configPath == "" {
		return nil, errors.New("feed replay requires explicit cache, manifest and sources paths")
	}
	manifest, err := readFeedReplayFile(manifestPath)
	if err != nil {
		return nil, err
	}
	encoded, err := readFeedReplayFile(configPath)
	if err != nil {
		return nil, err
	}
	replay := &FeedReplay{Config: new(configv1.AdvisoryConfig), cacheDirectory: cacheDirectory}
	if err := json.Unmarshal(manifest, &replay.Artifacts); err != nil {
		return nil, fmt.Errorf("decode replay artifact array: %w", err)
	}
	if err := protojson.Unmarshal(encoded, replay.Config); err != nil {
		return nil, fmt.Errorf("decode replay AdvisoryConfig: %w", err)
	}
	if err := protovalidate.Validate(replay.Config); err != nil {
		return nil, fmt.Errorf("validate replay AdvisoryConfig: %w", err)
	}
	if len(replay.Artifacts) == 0 || len(replay.Config.GetFeeds()) == 0 {
		return nil, errors.New("feed replay requires artifacts and sources")
	}
	seen := make(map[string]bool, len(replay.Artifacts))
	for i := range replay.Artifacts {
		artifact := &replay.Artifacts[i]
		u, err := url.Parse(artifact.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("invalid replay artifact URL %q", artifact.URL)
		}
		digest, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(digest) != sha256.Size || artifact.SHA256 != hex.EncodeToString(digest) || artifact.Bytes < 0 {
			return nil, fmt.Errorf("invalid replay artifact digest or size for %s", artifact.URL)
		}
		if seen[artifact.URL] {
			return nil, fmt.Errorf("duplicate replay artifact URL %s", artifact.URL)
		}
		seen[artifact.URL] = true
		// A prior connected cache hit is not revalidation in this run.
		artifact.Revalidated = false
	}
	slices.SortFunc(replay.Artifacts, func(a, b AcceptanceFeedArtifact) int {
		if a.URL < b.URL {
			return -1
		}
		if a.URL > b.URL {
			return 1
		}
		return 0
	})
	manifestDigest, configDigest := sha256.Sum256(manifest), sha256.Sum256(encoded)
	replay.ManifestSHA256, replay.ConfigSHA256 = hex.EncodeToString(manifestDigest[:]), hex.EncodeToString(configDigest[:])
	return replay, nil
}

func readFeedReplayFile(path string) (_ []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("feed replay input exceeds 1 MiB")
	}
	return raw, nil
}

// openClient uses genuine verified loopback TLS, not invented vendor TLS state.
// Only this disposable lab fixture rewrites requests. Production signature,
// archive, checksum, parser and publication checks still run. TLS here proves
// only delivery from this local recording, never current vendor authority.
func (r *FeedReplay) openClient(byteBudget int64) (*http.Client, func(), error) {
	if byteBudget <= 0 {
		return nil, nil, errors.New("positive replay byte budget required")
	}
	artifacts := make(map[string]AcceptanceFeedArtifact, len(r.Artifacts))
	for _, artifact := range r.Artifacts {
		key := sha256.Sum256([]byte(artifact.URL))
		artifacts["/"+hex.EncodeToString(key[:])] = artifact
	}
	var mu sync.Mutex
	remaining := byteBudget
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		artifact, ok := artifacts[request.URL.Path]
		if request.Method != http.MethodGet || !ok {
			http.Error(w, "artifact absent from immutable replay manifest", http.StatusNotFound)
			return
		}
		mu.Lock()
		withinBudget := artifact.Bytes <= remaining
		if withinBudget {
			remaining -= artifact.Bytes
		}
		mu.Unlock()
		if !withinBudget {
			http.Error(w, "recorded artifact exceeds byte budget", http.StatusRequestEntityTooLarge)
			return
		}
		file, err := r.openArtifact(request.Context(), artifact)
		if err != nil {
			http.Error(w, "recorded artifact missing or corrupt", http.StatusUnprocessableEntity)
			return
		}
		defer func() { _ = file.Close() }()
		w.Header().Set("Content-Length", fmt.Sprint(artifact.Bytes))
		w.Header().Set("Content-Type", "application/octet-stream")
		// Client cancellation/early rejection ends the copy; the client owns
		// the corresponding read error, so no second HTTP response is possible.
		_, _ = io.Copy(w, file)
	}))
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		return nil, nil, err
	}
	client := server.Client()
	client.Transport = &feedReplayTransport{base: client.Transport, endpoint: endpoint}
	return client, server.Close, nil
}

type feedReplayTransport struct {
	base     http.RoundTripper
	endpoint *url.URL
}

func (t *feedReplayTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(request.URL.String()))
	local := request.Clone(request.Context())
	local.URL.Scheme, local.URL.Host = t.endpoint.Scheme, t.endpoint.Host
	local.URL.Path, local.URL.RawPath = "/"+hex.EncodeToString(key[:]), ""
	local.URL.RawQuery, local.URL.Fragment, local.Host = "", "", t.endpoint.Host
	return t.base.RoundTrip(local)
}

// replayContextReader bounds local hash reads by cancellation as well as bytes.
type replayContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r replayContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (r *FeedReplay) openArtifact(ctx context.Context, artifact AcceptanceFeedArtifact) (_ *os.File, resultErr error) {
	file, err := os.Open(filepath.Join(r.cacheDirectory, artifact.SHA256))
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != artifact.Bytes {
		return nil, errors.New("replay blob is not a regular file of recorded size")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, replayContextReader{ctx: ctx, reader: io.LimitReader(file, artifact.Bytes+1)})
	if err != nil {
		return nil, err
	}
	if count != artifact.Bytes || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return nil, errors.New("replay blob digest mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return file, nil
}
