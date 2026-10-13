//go:build linux

package reposnapshot

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
)

// ServeOptions names only this disposable listener, never host trust settings.
// QEMU user networking uses loopback listening and AdvertiseHost 10.0.2.2.
type ServeOptions struct {
	ListenAddress string
	AdvertiseHost string
	keyPins       map[string]string
}

// Server owns a verified closure's lane-scoped HTTPS origin. CAPEM is public
// fixture trust for the disposable guest only; neither private key leaves memory.
type Server struct {
	URL      string
	CAPEM    []byte
	Manifest *labv1.RepositorySnapshotManifest
	// KeyPaths contains only the vendor key and keys delegated by signed repomd.
	KeyPaths []string

	server   *http.Server
	cancel   context.CancelFunc
	once     sync.Once
	closeErr error
	root     *os.File
	spool    string
	gate     chan struct{}
	admitted chan struct{}
	keyPins  map[string]string

	refusalMu sync.Mutex
	refusals  Refusals
}

// maxRefusedPaths bounds the distinct unlisted packages a Server remembers.
const maxRefusedPaths = 16

// Refusals counts requests the closure could not serve. Signed metadata names
// every package of the dated repository, so a client solver may select an RPM
// the retained closure lacks; that 404 otherwise surfaces only as an opaque
// client-side media error (AutoYaST: "Cannot access installation media").
type Refusals struct {
	// UnlistedPackages holds the first distinct closure-relative RPM paths
	// requested under the snapshot prefix but absent from the manifest.
	UnlistedPackages []string
	UnlistedTotal    int
	// Capacity counts 503 responses for the bounded request queue.
	Capacity int
}

// Refused returns a copy of the refusals observed so far.
func (s *Server) Refused() Refusals {
	s.refusalMu.Lock()
	defer s.refusalMu.Unlock()
	r := s.refusals
	r.UnlistedPackages = slices.Clone(r.UnlistedPackages)
	return r
}

// Err describes the refusals, or returns nil when every request was served.
func (r Refusals) Err() error {
	if r.UnlistedTotal == 0 && r.Capacity == 0 {
		return nil
	}
	return fmt.Errorf("snapshot closure refused %d request(s) for packages it does not retain %v and %d over-capacity request(s)", r.UnlistedTotal, r.UnlistedPackages, r.Capacity)
}

func (s *Server) refuse(name string, capacity bool) {
	s.refusalMu.Lock()
	defer s.refusalMu.Unlock()
	if capacity {
		s.refusals.Capacity++
		return
	}
	s.refusals.UnlistedTotal++
	if len(s.refusals.UnlistedPackages) < maxRefusedPaths && !slices.Contains(s.refusals.UnlistedPackages, name) {
		s.refusals.UnlistedPackages = append(s.refusals.UnlistedPackages, name)
	}
}

// Start verifies the signed, bounded closure before opening a listener. Each
// response is rehashed into a private unlinked spool and its writable descriptor
// closed before any bytes are sent: cache mutation cannot race verification.
func Start(ctx context.Context, cache, digest string, options ServeOptions) (*Server, error) {
	manifest, root, err := Load(cache, digest)
	if err != nil {
		return nil, err
	}
	metadata, err := readMetadata(ctx, root, manifest)
	if err != nil {
		return nil, err
	}
	options.keyPins, err = repositoryKeys(metadata)
	if err != nil {
		return nil, err
	}
	return startVerified(ctx, manifest, root, options)
}

func startVerified(ctx context.Context, manifest *labv1.RepositorySnapshotManifest, root string, options ServeOptions) (_ *Server, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.ListenAddress == "" {
		options.ListenAddress = "127.0.0.1:0"
	}
	if options.AdvertiseHost == "" {
		options.AdvertiseHost = "127.0.0.1"
	}
	if strings.ContainsAny(options.AdvertiseHost, "/\\:@?#%\x00") {
		return nil, errors.New("snapshot advertise host must be a hostname or IPv4 address")
	}
	files := make(map[string]*labv1.RepositorySnapshotFile, len(manifest.GetFiles()))
	for _, file := range manifest.GetFiles() {
		name := file.GetPath()
		if name == "." || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00") || file.GetSizeBytes() == 0 || file.GetSizeBytes() > 1<<40 {
			return nil, errors.New("invalid snapshot serving file")
		}
		if _, exists := files[name]; exists {
			return nil, errors.New("duplicate snapshot serving file")
		}
		// Copy the serving bounds: callers cannot mutate the public manifest to
		// expand the set of authorized bytes while the listener is running.
		files[name] = &labv1.RepositorySnapshotFile{Path: name, Sha256: file.GetSha256(), SizeBytes: file.GetSizeBytes()}
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{Manifest: manifest, root: os.NewFile(uintptr(rootFD), root), cancel: cancel, gate: make(chan struct{}, 1), admitted: make(chan struct{}, 16)}
	s.keyPins = make(map[string]string, len(options.keyPins))
	s.KeyPaths = []string{"repodata/repomd.xml.key"}
	for name, pin := range options.keyPins {
		if files[name] == nil {
			return nil, errors.Join(errors.New("signed RPM key is absent from closure"), s.Close())
		}
		s.keyPins[name] = pin
		s.KeyPaths = append(s.KeyPaths, name)
	}
	sort.Strings(s.KeyPaths)
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	s.spool, err = os.MkdirTemp("", "lindm-snapshot-https-")
	if err != nil {
		return nil, err
	}
	certificate, ca, err := snapshotCertificate(options.AdvertiseHost)
	if err != nil {
		return nil, err
	}
	s.CAPEM = ca
	listener, err := new(net.ListenConfig).Listen(ctx, "tcp4", options.ListenAddress)
	if err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	prefix := "/snapshots/" + manifest.GetManifestSha256() + "/"
	s.URL = "https://" + net.JoinHostPort(options.AdvertiseHost, port) + prefix
	s.server = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveFile(ctx, files, prefix, w, r) }),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		_ = s.server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}))
		cancel()
	}()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s, nil
}

// Close cancels requests, closes the listener and removes the private spool.
// Context cancellation has the same effect; callers may still defer Close.
func (s *Server) Close() error {
	s.once.Do(func() {
		s.cancel()
		if s.server != nil {
			s.closeErr = s.server.Close()
		}
		s.gate <- struct{}{}
		defer func() { <-s.gate }()
		s.closeErr = errors.Join(s.closeErr, s.root.Close())
		if s.spool != "" {
			s.closeErr = errors.Join(s.closeErr, os.RemoveAll(s.spool))
		}
	})
	return s.closeErr
}

func (s *Server) serveFile(ctx context.Context, files map[string]*labv1.RepositorySnapshotFile, prefix string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "read-only snapshot", http.StatusMethodNotAllowed)
		return
	}
	// Do not clean or redirect paths: only the exact manifest spelling is an
	// endpoint. In particular, percent-encoded separators and traversal fail.
	if r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	file, ok := files[name]
	// Signed repomd key locations include this exact fingerprint query. It
	// selects no alternate bytes and authorizes no other query or path.
	validQuery := r.URL.RawQuery == "" && !r.URL.ForceQuery
	if pin := s.keyPins[name]; pin != "" && r.URL.RawQuery == "fpr="+pin {
		validQuery = true
	}
	if !ok || !validQuery {
		// Repository-type probes (media.1/media, content) are expected 404s.
		if strings.HasSuffix(name, ".rpm") {
			s.refuse(name, false)
		}
		http.NotFound(w, r)
		return
	}
	// Keep a small, bounded queue for native package managers' parallel fetches.
	// Waiting for the spool must not retain an unbounded number of handlers.
	select {
	case s.admitted <- struct{}{}:
		defer func() { <-s.admitted }()
	default:
		s.refuse(name, true)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "snapshot request capacity exhausted", http.StatusServiceUnavailable)
		return
	}
	// One bounded spool at a time, including transmission; concurrent clients
	// cannot multiply closure-sized disk use or open package descriptors.
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return
	case <-r.Context().Done():
		return
	}
	if ctx.Err() != nil || r.Context().Err() != nil {
		return
	}
	payload, err := s.verifiedPayload(r.Context(), file)
	if err != nil {
		http.Error(w, "snapshot content changed or unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = payload.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", "\"sha256:"+file.GetSha256()+"\"")
	http.ServeContent(w, r, file.GetPath(), time.Time{}, payload)
}

func (s *Server) verifiedPayload(ctx context.Context, file *labv1.RepositorySnapshotFile) (_ *os.File, err error) {
	return verifiedSnapshotPayload(ctx, s.root, s.spool, file)
}

func verifiedSnapshotPayload(ctx context.Context, root *os.File, spoolDirectory string, file *labv1.RepositorySnapshotFile) (_ *os.File, err error) {
	fd, err := unix.Openat2(int(root.Fd()), file.GetPath(), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	source := os.NewFile(uintptr(fd), file.GetPath())
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(file.GetSizeBytes()) {
		return nil, errors.New("snapshot file size or type changed")
	}
	spool, err := os.CreateTemp(spoolDirectory, "payload-")
	if err != nil {
		return nil, err
	}
	spoolOpen := true
	defer func() {
		if spoolOpen {
			if closeErr := spool.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
	}()
	if err := os.Remove(spool.Name()); err != nil {
		return nil, err
	}
	digest := sha256.New()
	copied, err := io.Copy(io.MultiWriter(spool, digest), io.LimitReader(snapshotContextReader{ctx, source}, int64(file.GetSizeBytes())+1))
	if err != nil {
		return nil, err
	}
	if copied != int64(file.GetSizeBytes()) || hex.EncodeToString(digest.Sum(nil)) != file.GetSha256() {
		return nil, errors.New("snapshot file digest changed")
	}
	// Opening this process-owned unlinked inode read-only, then closing the
	// sole writable descriptor, makes the verified response bytes immutable.
	readonly, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(spool.Fd())))
	if err != nil {
		return nil, err
	}
	closeErr := spool.Close()
	spoolOpen = false
	if closeErr != nil {
		return nil, errors.Join(closeErr, readonly.Close())
	}
	return readonly, nil
}

type snapshotContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r snapshotContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Match the lab's disposable P-256 CA/leaf pattern, without touching any host
// certificate store or borrowing the long-lived dev/control-plane authority.
// Each authority has its own CA name and random serials: a Tumbleweed golden
// keeps its installer's snapshot CA (the same name and serial 1 before, valid
// for 24 hours) as a trust anchor, and with both anchors installed zypper's
// system store failed the lane leaf ("certificate signature failure", exit 4
// on the x86_64 resources and os-update lanes) while curl --cacert passed.
func snapshotCertificate(host string) (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serials := make([]byte, 32)
	if _, err := rand.Read(serials); err != nil {
		return tls.Certificate{}, nil, err
	}
	caSerial, leafSerial := new(big.Int).SetBytes(serials[:16]), new(big.Int).SetBytes(serials[16:])
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "lindm disposable snapshot CA " + hex.EncodeToString(serials[:8])}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: host}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("issue snapshot HTTPS leaf: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
