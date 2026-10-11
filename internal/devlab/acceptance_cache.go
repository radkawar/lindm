package devlab

import (
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
)

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
	// Serialize acquisition, index replacement and budget accounting. Response
	// bodies are independent files and may be parsed concurrently after return.
	mu        sync.Mutex
	base      http.RoundTripper
	directory string
	remaining int64
	artifacts []AcceptanceFeedArtifact
}

func (c *acceptanceFeedCache) RoundTrip(request *http.Request) (_ *http.Response, resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if request.Method != http.MethodGet {
		return nil, errors.New("acceptance feed cache only permits GET")
	}
	key := sha256.Sum256([]byte(request.URL.String()))
	index := filepath.Join(c.directory, hex.EncodeToString(key[:])+".json")
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
		c.artifacts = append(c.artifacts, AcceptanceFeedArtifact{URL: request.URL.String(), SHA256: cached.SHA256, Bytes: cached.Bytes, Revalidated: true})
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
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, c.remaining+1))
	err = errors.Join(copyErr, response.Body.Close(), file.Close())
	if err != nil {
		return nil, err
	}
	if count > c.remaining {
		return nil, errors.New("acceptance vendor feed byte budget exceeded")
	}
	c.remaining -= count
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
	c.artifacts = append(c.artifacts, AcceptanceFeedArtifact{URL: request.URL.String(), SHA256: entry.SHA256, Bytes: count})
	return response, nil
}

func (c *acceptanceFeedCache) openCached(entry acceptanceCacheEntry) (_ *os.File, resultErr error) {
	digest, err := hex.DecodeString(entry.SHA256)
	if err != nil || len(digest) != sha256.Size || entry.Bytes < 0 || entry.Bytes > c.remaining {
		return nil, errors.New("invalid or over-budget acceptance feed cache entry")
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
	c.remaining -= count
	return file, nil
}
