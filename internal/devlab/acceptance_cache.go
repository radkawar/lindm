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
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

// cachedRefreshConfig returns a copy of cfg for refreshes behind
// acceptanceFeedCache. The cache materializes and hashes each complete vendor
// artifact before the production parser reads a byte, so a slow link would trip
// the production idle watchdog without any stalled stream. The lab duration
// already bounds the refresh; an unset idle bound inherits it (capped at the
// protocol maximum). Explicit bounds and cfg itself are left unchanged.
func cachedRefreshConfig(cfg *configv1.AdvisoryConfig, duration time.Duration) *configv1.AdvisoryConfig {
	cfg = proto.CloneOf(cfg)
	for _, feed := range cfg.GetFeeds() {
		if feed.ProgressTimeoutSeconds == nil {
			feed.ProgressTimeoutSeconds = proto.Uint32(uint32(min(max(duration.Seconds(), 1), 3600)))
		}
	}
	return cfg
}

// AcceptanceFeedArtifact records bytes actually delivered to the production feed
// parser. A cache hit requires current vendor HTTP revalidation and a digest check;
// a cached file alone never establishes current advisory coverage.
type AcceptanceFeedArtifact struct {
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	Bytes       int64  `json:"bytes"`
	Revalidated bool   `json:"revalidated"`
}

type acceptanceCacheEntry struct {
	SHA256 string      `json:"sha256"`
	Bytes  int64       `json:"bytes"`
	Header http.Header `json:"header"`
}

type acceptanceFeedCache struct {
	base      http.RoundTripper
	directory string
	mu        sync.Mutex // guards the shared byte budget and completed artifacts
	remaining int64
	artifacts []AcceptanceFeedArtifact
}

func (c *acceptanceFeedCache) RoundTrip(request *http.Request) (_ *http.Response, resultErr error) {
	if request.Method != http.MethodGet {
		return nil, errors.New("acceptance feed cache only permits GET")
	}
	key := sha256.Sum256([]byte(request.URL.String()))
	index := filepath.Join(c.directory, hex.EncodeToString(key[:])+".json")
	lock, err := lockAcceptanceFeedCache(request.Context(), index+".lock")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	var cached acceptanceCacheEntry
	indexFile, err := os.Open(index)
	var encoded []byte
	if err == nil {
		encoded, err = io.ReadAll(io.LimitReader(indexFile, (64<<10)+1))
		err = errors.Join(err, indexFile.Close())
		if err != nil {
			return nil, err
		}
		if len(encoded) > 64<<10 || json.Unmarshal(encoded, &cached) != nil {
			return nil, errors.New("invalid acceptance feed cache index")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	req := request.Clone(request.Context())
	if cached.Header.Get("ETag") != "" {
		req.Header.Set("If-None-Match", cached.Header.Get("ETag"))
	} else if cached.Header.Get("Last-Modified") != "" {
		req.Header.Set("If-Modified-Since", cached.Header.Get("Last-Modified"))
	}
	response, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusNotModified {
		if err := response.Body.Close(); err != nil {
			return nil, err
		}
		if cached.Header.Get("ETag") == "" && cached.Header.Get("Last-Modified") == "" {
			return nil, errors.New("unsolicited feed cache revalidation")
		}
		file, err := c.openCached(cached)
		if err != nil {
			return nil, err
		}
		response.StatusCode, response.Status, response.Header = http.StatusOK, "200 OK", cached.Header.Clone()
		response.Body, response.ContentLength = file, cached.Bytes
		c.recordArtifact(AcceptanceFeedArtifact{URL: request.URL.String(), SHA256: cached.SHA256, Bytes: cached.Bytes, Revalidated: true})
		return response, nil
	}
	if response.StatusCode != http.StatusOK {
		return response, nil
	}
	file, err := os.CreateTemp(c.directory, ".download-")
	if err != nil {
		return nil, errors.Join(err, response.Body.Close())
	}
	name := file.Name()
	defer func() {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	hash := sha256.New()
	count, copyErr := io.Copy(acceptanceCacheWriter{cache: c, writer: io.MultiWriter(file, hash)}, response.Body)
	err = errors.Join(copyErr, response.Body.Close(), file.Close())
	if err != nil {
		return nil, err
	}
	entry := acceptanceCacheEntry{SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: count, Header: response.Header.Clone()}
	if err := os.Rename(name, filepath.Join(c.directory, entry.SHA256)); err != nil {
		return nil, err
	}
	encoded, err = json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(index, encoded, 0600); err != nil {
		return nil, err
	}
	body, err := os.Open(filepath.Join(c.directory, entry.SHA256))
	if err != nil {
		return nil, err
	}
	response.Body = body
	c.recordArtifact(AcceptanceFeedArtifact{URL: request.URL.String(), SHA256: entry.SHA256, Bytes: count})
	return response, nil
}

func (c *acceptanceFeedCache) openCached(entry acceptanceCacheEntry) (_ *os.File, resultErr error) {
	digest, err := hex.DecodeString(entry.SHA256)
	if err != nil || len(digest) != sha256.Size || entry.Bytes < 0 {
		return nil, errors.New("invalid acceptance feed cache entry")
	}
	if err := c.consumeBytes(entry.Bytes); err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(c.directory, entry.SHA256))
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, entry.Bytes+1))
	if err != nil {
		return nil, err
	}
	if count != entry.Bytes || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return nil, fmt.Errorf("acceptance feed cache digest mismatch: %s", entry.SHA256)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return file, nil
}

// Budget accounting never holds the mutex during network or filesystem I/O.
func (c *acceptanceFeedCache) consumeBytes(count int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if count > c.remaining {
		return errors.New("acceptance vendor feed byte budget exceeded")
	}
	c.remaining -= count
	return nil
}

func (c *acceptanceFeedCache) recordArtifact(artifact AcceptanceFeedArtifact) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.artifacts = append(c.artifacts, artifact)
}

type acceptanceCacheWriter struct {
	cache  *acceptanceFeedCache
	writer io.Writer
}

func (w acceptanceCacheWriter) Write(data []byte) (int, error) {
	if err := w.cache.consumeBytes(int64(len(data))); err != nil {
		return 0, err
	}
	return w.writer.Write(data)
}

// lockAcceptanceFeedCache serializes one URL's revalidation and index publication
// across processes without delaying unrelated vendor URLs. Content-addressed
// bodies remain readable through open descriptors after the entry lock is released.
func lockAcceptanceFeedCache(ctx context.Context, path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, file.Close())
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, errors.Join(err, file.Close())
		}
		if ticker == nil {
			ticker = time.NewTicker(100 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-ticker.C:
		}
	}
}
