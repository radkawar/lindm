package reposnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// CaptureOptions are mandatory immutable pins plus explicit resource bounds.
type CaptureOptions struct {
	Cache, RetainedMetadata                                         string
	Distribution, Architecture, Date, RepomdSHA256, BaseImageSHA256 string
	MaxBytes                                                        uint64
	MaxPackages                                                     uint32
	// SeedManifestSHA256 reuses only authenticated bytes from this cache. It
	// never substitutes for either native solve or the complete offline replay.
	SeedManifestSHA256 string
	SeedCache          string
}

// Capture owns a private staging directory and a signed, allowlisted acquisition
// proxy. Only native solver GETs can add RPMs, never arbitrary repository paths.
type Capture struct {
	Manifest                 *labv1.RepositorySnapshotManifest
	Root                     string
	staging, cache, retained string
	ctx                      context.Context
	client                   *http.Client
	mu                       sync.Mutex
	allowed                  map[string]rpmPackage
	keyPins                  map[string]string
	files                    map[string]bool
	total                    uint64
	packages                 uint32
	offline                  bool
	failure                  error
	seedRoot                 *os.File
	payloadRoot              *os.File
	spool                    string
	admitted                 chan struct{}
	gate                     chan struct{}
	seedFiles                map[string]*labv1.RepositorySnapshotFile
}

func NewCapture(ctx context.Context, o CaptureOptions) (_ *Capture, err error) {
	recipe, ok := platform.RepositorySnapshotRecipes[o.Distribution]
	if !ok {
		return nil, errors.New("repository snapshot backend not maintained; Arch requires a genuine signed pacman database backend")
	}
	source, ok := recipe.Sources[o.Architecture]
	if !ok {
		return nil, errors.New("unsupported snapshot architecture")
	}
	if strings.Contains(source, "%s") {
		source = fmt.Sprintf(source, strings.ReplaceAll(o.Date, "-", ""))
	}
	if !validDigest(o.RepomdSHA256) || !validDigest(o.BaseImageSHA256) || o.MaxBytes == 0 || o.MaxBytes > HardMaxBytes || o.MaxPackages == 0 || o.MaxPackages > HardMaxPackages {
		return nil, errors.New("exact digest pins and bounded package/byte limits required")
	}
	inputs, err := platform.RepositorySnapshotInputs(o.Distribution, strings.ReplaceAll(o.Date, "-", ""), o.Architecture)
	if err != nil {
		return nil, err
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("repository capture requires the maintained HTTP transport")
	}
	transport = transport.Clone()
	if err := os.MkdirAll(o.Cache, 0700); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(o.Cache, ".repository-snapshot-")
	if err != nil {
		return nil, err
	}
	transport.MaxConnsPerHost = 4
	c := &Capture{ctx: ctx, staging: staging, Root: filepath.Join(staging, "repository"), cache: o.Cache, retained: o.RetainedMetadata, allowed: map[string]rpmPackage{}, files: map[string]bool{}, client: &http.Client{Transport: transport, Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 8 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("unsafe snapshot download redirect")
		}
		return nil
	}}}
	c.Manifest = &labv1.RepositorySnapshotManifest{Distribution: o.Distribution, Architecture: o.Architecture, SnapshotDate: o.Date, SourceRootUrl: source, SignerFingerprint: recipe.Signer, RepomdSha256: o.RepomdSHA256, MaxBytes: o.MaxBytes, MaxPackages: o.MaxPackages, BaseImageSha256: o.BaseImageSHA256, RequestedPackages: inputs}
	failed := true
	defer func() {
		if failed {
			err = errors.Join(err, c.Close())
		}
	}()
	if o.SeedManifestSHA256 != "" {
		seedCache := o.SeedCache
		if seedCache == "" {
			seedCache = o.Cache
		}
		seed, root, err := Load(seedCache, o.SeedManifestSHA256)
		if err != nil {
			return nil, err
		}
		if seed.Distribution != c.Manifest.Distribution || seed.Architecture != c.Manifest.Architecture || seed.SnapshotDate != c.Manifest.SnapshotDate || seed.RepomdSha256 != c.Manifest.RepomdSha256 || seed.SourceRootUrl != c.Manifest.SourceRootUrl || seed.SignerFingerprint != c.Manifest.SignerFingerprint {
			return nil, errors.New("retained closure does not match the exact capture target")
		}
		c.seedRoot, err = openSnapshotRoot(root)
		if err != nil {
			return nil, err
		}
		c.seedFiles = make(map[string]*labv1.RepositorySnapshotFile, len(seed.Files))
		for _, item := range seed.Files {
			c.seedFiles[item.Path] = item
		}
	}
	for _, p := range []string{"repodata/repomd.xml", "repodata/repomd.xml.asc", "repodata/repomd.xml.key"} {
		if err := c.acquire(p, 4<<20, nil); err != nil {
			return nil, err
		}
	}
	md, err := readMetadata(ctx, c.Root, c.Manifest)
	if err != nil {
		return nil, err
	}
	for _, d := range md.Data {
		if err := c.acquire(d.Location.Href, d.Size, &d.Checksum); err != nil {
			return nil, err
		}
	}
	keys, err := repositoryKeys(md)
	if err != nil {
		return nil, err
	}
	c.keyPins = keys
	for p, pin := range keys {
		if err := c.acquire(p, 4<<20, nil); err != nil {
			return nil, err
		}
		if err := verifyRPMKey(ctx, c.Root, c.Manifest, p, pin); err != nil {
			return nil, err
		}
	}
	if err := primaryPackages(c.Root, c.Manifest, md, func(p rpmPackage) error {
		if p.Arch != o.Architecture && p.Arch != "noarch" {
			return nil
		}
		if !safePath(p.Location.Href) || !strings.HasSuffix(p.Location.Href, ".rpm") || p.Size.Package == 0 {
			return errors.New("invalid primary package path/size")
		}
		if _, ok := c.allowed[p.Location.Href]; ok {
			return errors.New("duplicate primary package path")
		}
		c.allowed[p.Location.Href] = p
		return nil
	}); err != nil {
		return nil, err
	}
	c.payloadRoot, err = openSnapshotRoot(c.Root)
	if err != nil {
		return nil, err
	}
	c.spool, err = os.MkdirTemp(o.Cache, ".repository-response-")
	if err != nil {
		return nil, err
	}
	c.admitted = make(chan struct{}, 16)
	c.gate = make(chan struct{}, 1)
	failed = false
	return c, nil
}

func (c *Capture) Close() error {
	c.client.CloseIdleConnections()
	var closeErr error
	if c.seedRoot != nil {
		closeErr = c.seedRoot.Close()
		c.seedRoot = nil
	}
	if c.payloadRoot != nil {
		closeErr = errors.Join(closeErr, c.payloadRoot.Close())
		c.payloadRoot = nil
	}
	if c.spool != "" {
		closeErr = errors.Join(closeErr, os.RemoveAll(c.spool))
		c.spool = ""
	}
	if c.staging == "" {
		return closeErr
	}
	return errors.Join(closeErr, os.RemoveAll(c.staging))
}

func (c *Capture) acquire(relative string, bound uint64, sum *checksum) (err error) {
	if !safePath(relative) || bound == 0 {
		return errors.New("repository acquisition path or byte bound")
	}
	if c.files[relative] {
		return nil
	}
	if bound > c.Manifest.MaxBytes-c.total {
		return errors.New("repository acquisition aggregate byte bound")
	}
	var input io.ReadCloser
	seed := c.seedFiles[relative]
	if seed != nil {
		file, err := openRetained(c.seedRoot, seed)
		if err != nil {
			return err
		}
		input = file
	}
	if input == nil && c.retained != "" && (strings.HasPrefix(relative, "repodata/") || c.keyPins[relative] != "") {
		root, err := openSnapshotRoot(c.retained)
		if err != nil {
			return err
		}
		f, err := openRelative(root, relative, false)
		closeErr := root.Close()
		if closeErr != nil {
			if f != nil {
				closeErr = errors.Join(closeErr, f.Close())
			}
			return closeErr
		}
		if err == nil {
			input = f
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if input == nil {
		req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.Manifest.SourceRootUrl+relative, nil)
		if err != nil {
			return err
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return errors.Join(fmt.Errorf("snapshot source unavailable (%s): %s", relative, resp.Status), resp.Body.Close())
		}
		input = resp.Body
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	var signedHash hash.Hash
	if sum != nil && sum.Type != "sha256" {
		var err error
		signedHash, err = checksumHash(sum.Type)
		if err != nil {
			return err
		}
	}
	filename := filepath.Join(c.Root, relative)
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	writer := io.MultiWriter(f, h)
	if signedHash != nil {
		writer = io.MultiWriter(f, h, signedHash)
	}
	n, copyErr := io.Copy(writer, io.LimitReader(input, int64(bound)+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if n <= 0 || uint64(n) > bound {
		return errors.New("snapshot download exceeds bound")
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if seed != nil && (uint64(n) != seed.SizeBytes || digest != seed.Sha256) {
		return errors.New("authenticated retained closure bytes changed")
	}
	if sum != nil {
		actual := digest
		if signedHash != nil {
			actual = hex.EncodeToString(signedHash.Sum(nil))
		}
		if uint64(n) != bound || actual != sum.Value {
			return errors.New("signed repository checksum or size mismatch")
		}
	}
	c.files[relative] = true
	c.total += uint64(n)
	c.Manifest.Files = append(c.Manifest.Files, &labv1.RepositorySnapshotFile{Path: relative, Sha256: digest, SizeBytes: uint64(n)})
	return nil
}

func (c *Capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	relative := strings.TrimPrefix(r.URL.Path, "/")
	if !safePath(relative) {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawQuery != "" {
		pin := c.keyPins[relative]
		if pin == "" || r.URL.RawQuery != "fpr="+pin {
			http.NotFound(w, r)
			return
		}
	}
	select {
	case c.admitted <- struct{}{}:
		defer func() { <-c.admitted }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "snapshot request capacity exhausted", http.StatusServiceUnavailable)
		return
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-c.ctx.Done():
		return
	case <-r.Context().Done():
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		http.Error(w, "capture authentication failed", http.StatusServiceUnavailable)
		return
	}
	if !c.files[relative] {
		p, ok := c.allowed[relative]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if c.offline {
			c.failure = errors.New("offline closure requested uncaptured RPM")
			http.Error(w, "incomplete closure", http.StatusServiceUnavailable)
			return
		}
		if c.packages >= c.Manifest.MaxPackages {
			c.failure = errors.New("native closure exceeds package count bound")
			http.Error(w, "package bound", http.StatusServiceUnavailable)
			return
		}
		if err := c.acquire(relative, p.Size.Package, &p.Checksum); err != nil {
			c.failure = err
			http.Error(w, "authenticated acquisition failed", http.StatusBadGateway)
			return
		}
		c.packages++
	}
	item, err := retainedFile(c.Manifest, relative)
	if err != nil {
		c.failure = err
		http.Error(w, "capture manifest changed", http.StatusServiceUnavailable)
		return
	}
	payload, err := verifiedSnapshotPayload(r.Context(), c.payloadRoot, c.spool, item)
	if err != nil {
		// An abandoned request has not demonstrated an authentication failure.
		// Only the exact cancellation sentinel is exempt: joined cleanup errors
		// or observed content mismatches still poison the entire capture.
		if err == context.Canceled || err == context.DeadlineExceeded {
			return
		}
		c.failure = fmt.Errorf("verify captured %q: %w", relative, err)
		http.Error(w, "capture content changed", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = payload.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", "\"sha256:"+item.Sha256+"\"")
	http.ServeContent(w, r, relative, time.Time{}, payload)
}

// Offline disables every origin fetch before the independent empty-root replay.
func (c *Capture) Offline() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offline = true
	return c.failure
}

func (c *Capture) PackagePaths() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	paths := make([]string, 0, c.packages)
	for p := range c.files {
		if strings.HasSuffix(p, ".rpm") {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	return paths
}

func (c *Capture) Finish(base []string, version string, solver, signatures []byte) (*labv1.RepositorySnapshotManifest, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return nil, "", c.failure
	}
	if !c.offline || c.packages == 0 || len(base) == 0 || version == "" || len(solver) == 0 || len(signatures) == 0 {
		return nil, "", errors.New("native solver, offline replay and signature evidence required")
	}
	c.Manifest.BasePackages = slices.Clone(base)
	slices.Sort(c.Manifest.BasePackages)
	c.Manifest.SolverVersion = version
	for p, b := range map[string][]byte{"evidence/solver.txt": solver, "evidence/signatures.txt": signatures} {
		if len(b) > 8<<20 || uint64(len(b)) > c.Manifest.MaxBytes-c.total {
			return nil, "", errors.New("native evidence exceeds bound")
		}
		full := filepath.Join(c.Root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(full, b, 0400); err != nil {
			return nil, "", err
		}
		sum := sha256.Sum256(b)
		c.Manifest.Files = append(c.Manifest.Files, &labv1.RepositorySnapshotFile{Path: p, Sha256: hex.EncodeToString(sum[:]), SizeBytes: uint64(len(b))})
		c.total += uint64(len(b))
	}
	c.Manifest.TotalBytes = c.total
	if err := validateRepository(c.ctx, c.Root, c.Manifest); err != nil {
		return nil, "", err
	}
	m, root, err := publish(c.cache, c.staging, c.Manifest)
	if err == nil {
		c.staging = ""
	}
	return m, root, err
}

// RepositoryURL validates the loopback tunnel authority without shell syntax.
func RepositoryURL(address string) (string, error) {
	u, err := url.Parse("http://" + address + "/")
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		return "", errors.New("capture requires loopback SSH tunnel")
	}
	return u.String(), nil
}
