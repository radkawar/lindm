// SPDX-License-Identifier: Apache-2.0

package serverdeps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

// APTCapture retains only authenticated main indexes and exact native solver downloads.
// Host HTTP is loopback-only; the guest receives only this allowlist, not origin access.
type APTCapture struct {
	Manifest *serverdepsv1.Manifest
	Staging  string
	Cache    string
	client   *http.Client
	packages map[string]aptDigest
}

func NewAPTCapture(ctx context.Context, cache string, m *serverdepsv1.Manifest, archiveKey []byte) (_ *APTCapture, err error) {
	if _, err := snapshotTarget(m); err != nil {
		return nil, err
	}
	if m.Backend != serverdepsv1.Backend_BACKEND_DEB || m.MaxBytes == 0 || m.MaxBytes > HardMaxBytes || m.MaxPackages == 0 || m.MaxPackages > HardMaxPackages || len(archiveKey) == 0 || len(archiveKey) > int(maxTrustBytes) {
		return nil, errors.New("invalid Ubuntu capture inputs")
	}
	if err := os.MkdirAll(cache, 0700); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(cache, ".serverdeps-apt-")
	if err != nil {
		return nil, err
	}
	capture := &APTCapture{Manifest: m, Staging: stage, Cache: cache, client: &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("vendor snapshot redirects forbidden")
	}}}
	defer func() {
		if err != nil {
			err = errors.Join(err, capture.Close())
		}
	}()
	if err := capture.Add("keys/ubuntu-archive.gpg", archiveKey, serverdepsv1.FileKind_FILE_KIND_KEY); err != nil {
		return nil, err
	}
	m.Files[len(m.Files)-1].SignerFingerprint = UbuntuArchiveFingerprint
	for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
		prefix, origin := "archive", "https://archive.ubuntu.com/ubuntu/"
		if suite == "noble-security" {
			prefix, origin = "security", "https://security.ubuntu.com/ubuntu/"
		}
		metadata := prefix + "/dists/" + suite + "/InRelease"
		m.Repositories = append(m.Repositories, &serverdepsv1.Repository{Id: suite, SourceUrl: origin, Authentication: "apt-inrelease", MetadataPath: metadata, SigningKeyPath: "keys/ubuntu-archive.gpg", SignerFingerprint: UbuntuArchiveFingerprint})
		if err := capture.fetch(ctx, origin+"dists/"+suite+"/InRelease", metadata, serverdepsv1.FileKind_FILE_KIND_METADATA, "", 0); err != nil {
			return nil, err
		}
		m.Files[len(m.Files)-1].SignerFingerprint = UbuntuArchiveFingerprint
		root, err := openSnapshotRoot(filepath.Join(stage, "repository"))
		if err != nil {
			return nil, err
		}
		release, authErr := signedRelease(ctx, root, m, m.Repositories[len(m.Repositories)-1])
		closeErr := root.Close()
		if err := errors.Join(authErr, closeErr); err != nil {
			return nil, err
		}
		indexes, err := releaseDigests(release, path.Dir(metadata))
		if err != nil {
			return nil, err
		}
		index := prefix + "/dists/" + suite + "/main/binary-amd64/Packages.gz"
		value, ok := indexes[index]
		if !ok {
			return nil, errors.New("serverdeps: Ubuntu signed main amd64 index is missing")
		}
		if err := capture.fetch(ctx, origin+strings.TrimPrefix(index, prefix+"/"), index, serverdepsv1.FileKind_FILE_KIND_METADATA, value.hash, value.size); err != nil {
			return nil, err
		}
		entry := m.Files[len(m.Files)-1]
		entry.VendorSha256, entry.VendorMetadataPath, entry.SignerFingerprint = value.hash, metadata, UbuntuArchiveFingerprint
	}
	root, err := openSnapshotRoot(filepath.Join(stage, "repository"))
	if err != nil {
		return nil, err
	}
	capture.packages, err = APTProvenance(ctx, root, m)
	return capture, errors.Join(err, root.Close())
}

func (c *APTCapture) Close() error { return os.RemoveAll(c.Staging) }

func (c *APTCapture) Add(name string, data []byte, kind serverdepsv1.FileKind) error {
	if !safePath(name) || len(data) == 0 || uint64(len(data)) > c.Manifest.MaxBytes-c.Manifest.TotalBytes {
		return errors.New("APT retained file exceeds bounds")
	}
	file := filepath.Join(c.Staging, "repository", filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	n, writeErr := output.Write(data)
	if err := errors.Join(writeErr, output.Sync(), output.Close()); err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	sum := sha256.Sum256(data)
	c.Manifest.Files = append(c.Manifest.Files, &serverdepsv1.File{Path: name, Sha256: hex.EncodeToString(sum[:]), SizeBytes: uint64(len(data)), Kind: kind})
	c.Manifest.TotalBytes += uint64(len(data))
	return nil
}

func (c *APTCapture) fetch(ctx context.Context, url, name string, kind serverdepsv1.FileKind, digest string, size uint64) (err error) {
	if !safePath(name) {
		return errors.New("unsafe APT origin path")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("serverdeps: Ubuntu origin status %d for %s", response.StatusCode, name)
	}
	limit := c.Manifest.MaxBytes - c.Manifest.TotalBytes
	if kind == serverdepsv1.FileKind_FILE_KIND_METADATA && limit > maxPrimaryBytes {
		limit = maxPrimaryBytes
	}
	if size > 0 {
		if size > limit {
			return errors.New("APT closure byte ceiling")
		}
		limit = size
	}
	file := filepath.Join(c.Staging, "repository", filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(response.Body, int64(limit)+1))
	if err := errors.Join(copyErr, output.Sync(), output.Close()); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if n <= 0 || uint64(n) > limit || size > 0 && uint64(n) != size || digest != "" && digest != actual {
		return errors.New("APT download differs from authenticated vendor digest or bound")
	}
	c.Manifest.Files = append(c.Manifest.Files, &serverdepsv1.File{Path: name, Sha256: actual, SizeBytes: uint64(n), Kind: kind})
	c.Manifest.TotalBytes += uint64(n)
	return nil
}

// ResolveURIs admits only URLs and SHA256s emitted by the real empty-status APT solver.
func (c *APTCapture) ResolveURIs(ctx context.Context, output, repositoryURL string) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "'") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return errors.New("malformed native APT URI output")
		}
		name, err := aptSolverPath(strings.Trim(fields[0], "'"), repositoryURL)
		if err != nil {
			return err
		}
		digest := strings.TrimPrefix(fields[3], "SHA256:")
		signed, ok := c.packages[name+"#"+digest]
		size, err := strconv.ParseUint(fields[2], 10, 64)
		if !ok || err != nil || signed.size != size {
			return errors.New("APT solver package is not authenticated by retained index")
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if c.Manifest.PackageCount >= c.Manifest.MaxPackages {
			return errors.New("APT closure package ceiling")
		}
		prefix, relative, ok := strings.Cut(name, "/")
		if !ok {
			return errors.New("APT package has no repository prefix")
		}
		origin := "https://archive.ubuntu.com/ubuntu/"
		if prefix == "security" {
			origin = "https://security.ubuntu.com/ubuntu/"
		} else if prefix != "archive" {
			return errors.New("unknown Ubuntu repository prefix")
		}
		if err := c.fetch(ctx, origin+relative, name, serverdepsv1.FileKind_FILE_KIND_PACKAGE, digest, size); err != nil {
			return err
		}
		entry := c.Manifest.Files[len(c.Manifest.Files)-1]
		entry.VendorSha256, entry.VendorMetadataPath, entry.PackageIdentity, entry.SignerFingerprint = digest, signed.metadata, signed.identity, UbuntuArchiveFingerprint
		c.Manifest.PackageCount++
	}
	if c.Manifest.PackageCount == 0 {
		return errors.New("APT solver returned no complete dependency closure")
	}
	return nil
}

// APT prints URI-escaped acquisition paths, not literal signed-index filenames.
// Decode exactly once inside the admitted origin, then bind to the signed index.
func aptSolverPath(uri, repositoryURL string) (string, error) {
	prefix := repositoryURL + "/"
	if !strings.HasPrefix(uri, prefix) {
		return "", fmt.Errorf("APT solver URL escapes captured repository: %q", uri)
	}
	name, err := url.PathUnescape(strings.TrimPrefix(uri, prefix))
	if err != nil || !safePath(name) || !strings.HasSuffix(name, ".deb") {
		return "", fmt.Errorf("APT solver URL has an invalid package path: %q", uri)
	}
	return name, nil
}

func (c *APTCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method refused", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if !safePath(name) {
		http.NotFound(w, r)
		return
	}
	entry, err := retainedFile(c.Manifest, name)
	if err != nil || entry.Kind != serverdepsv1.FileKind_FILE_KIND_METADATA {
		http.NotFound(w, r)
		return
	}
	root, err := openSnapshotRoot(filepath.Join(c.Staging, "repository"))
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = root.Close() }()
	if err := CheckRetained(root, entry); err != nil {
		http.Error(w, "snapshot changed", http.StatusServiceUnavailable)
		return
	}
	file, err := OpenRetained(root, entry)
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = file.Close() }()
	w.Header().Set("Content-Length", strconv.FormatUint(entry.SizeBytes, 10))
	if r.Method == http.MethodGet {
		_, _ = io.CopyN(w, file, int64(entry.SizeBytes))
	}
}

func (c *APTCapture) Publish(ctx context.Context) (*serverdepsv1.Manifest, string, error) {
	slices.SortFunc(c.Manifest.Files, func(a, b *serverdepsv1.File) int { return strings.Compare(a.Path, b.Path) })
	return Publish(ctx, c.Cache, c.Staging, c.Manifest)
}
