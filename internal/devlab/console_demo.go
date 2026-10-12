package devlab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/platform"
)

// ConsoleDemo describes the fixture-owned loopback HTTPS origin. It holds no
// credentials; the origin's private key never leaves this process.
type ConsoleDemo struct {
	// WebhookURL accepts and discards webhook deliveries.
	WebhookURL string
	// CAPEM is the origin's ephemeral certificate authority, for pinning.
	CAPEM string
}

type consoleDemoOrigin struct {
	server *http.Server
	done   chan error
}

func (o *consoleDemoOrigin) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := o.server.Shutdown(ctx)
	if serveErr := <-o.done; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}

// consoleDemoFeed is one checked-in vendor fixture served as
// /feeds/<release>/<name>, for the platform registry row release. Signed
// documents also serve their vendor .sha256 and .asc proofs. A repository feed
// is the complete updateinfo of the fixture-owned controlled repository: the
// recorded vendor node and the labelled synthetic updates of
// console_demo_scale.go inside an <updates> root.
type consoleDemoFeed struct {
	release, name, fixture string
	format                 advisoryv1.FeedFormat
	stream                 string
	signed, repository     bool
}

// Single notices are partial vendor snapshots, so their devices' evaluations,
// and with them every finding, stay UNKNOWN (feed_partial_coverage). The
// Fedora controlled repository is the one complete source: only Fedora
// devices can report AFFECTED. Provenance is recorded in
// internal/advisory/feed/testdata/provenance.txt.
func consoleDemoFeeds() []consoleDemoFeed {
	return []consoleDemoFeed{
		{release: "ubuntu-24.04", name: "USN-6859-1.json", fixture: "ubuntu-USN-6859-1.json", format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON},
		{release: "debian-12", name: "DSA-5724-1.json", fixture: "debian-DSA-5724-1.json", format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON},
		{release: "fedora-44", name: "updateinfo.xml", fixture: "fedora44-sudo.xml", format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, repository: true},
		{release: "rhel-9", name: "rhsa-2024_6783.json", fixture: "redhat-rhsa-2024_6783.json", format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, stream: "standard", signed: true},
	}
}

// consoleDemoAdvisories reads the served documents, keyed by origin-relative
// path, and their feed sources, whose URLs are still origin-relative.
func consoleDemoAdvisories(repository string) (map[string][]byte, []*advisoryv1.FeedSource, error) {
	files := make(map[string][]byte)
	var sources []*advisoryv1.FeedSource
	for _, feed := range consoleDemoFeeds() {
		release, ok := platform.Lookup(feed.release)
		if !ok {
			return nil, nil, fmt.Errorf("console demo release %s is not registered", feed.release)
		}
		path := "/feeds/" + feed.release + "/" + feed.name
		suffixes := []string{""}
		if feed.signed {
			suffixes = append(suffixes, ".sha256", ".asc")
		}
		for _, suffix := range suffixes {
			data, err := os.ReadFile(filepath.Join(repository, "internal", "advisory", "feed", "testdata", feed.fixture+suffix))
			if err != nil {
				return nil, nil, fmt.Errorf("read demo advisory fixture: %w", err)
			}
			files[path+suffix] = data
		}
		if feed.repository {
			synthetic, err := consoleDemoUpdateinfo()
			if err != nil {
				return nil, nil, fmt.Errorf("render synthetic demo updates: %w", err)
			}
			files[path] = slices.Concat([]byte("<updates>"), files[path], synthetic, []byte("</updates>"))
		}
		sources = append(sources, &advisoryv1.FeedSource{Id: "demo-" + feed.release, Distro: release.ID, Release: release.Version.Value, PlatformStream: feed.stream, Architecture: "x86_64", Format: feed.format, Url: path, MaxAgeSeconds: 604800})
	}
	return files, sources, nil
}

// ConfigureConsoleDemo serves the repository's checked-in vendor advisory
// fixtures and a webhook sink from an owned loopback HTTPS origin, then
// restarts the console server with its real advisory refresh pointed at that
// origin and the assistance relay enabled. Only this fixture trusts the
// origin's ephemeral CA; the database, accounts and keys are preserved and the
// origin stops at Close. Call at most once, before devices enroll.
func (f *AuthorityFixture) ConfigureConsoleDemo(ctx context.Context) (*ConsoleDemo, error) {
	if f.closed || f.local == nil || f.ConsoleOrigin == consoleOrigin || f.demo != nil {
		return nil, errors.New("console demo requires one live dynamic local console fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	if document.Proto.GetAdvisories() != nil || document.Proto.GetAssistance() != nil {
		return nil, errors.New("console demo advisories or assistance are already configured")
	}
	files, sources, err := consoleDemoAdvisories(f.repository)
	if err != nil {
		return nil, err
	}
	authority, certificate, err := consoleDemoCertificate()
	if err != nil {
		return nil, err
	}
	shared, err := os.ReadFile(filepath.Join(FixturePath(f.repository), "transport-ca.crt"))
	if err != nil {
		return nil, err
	}
	const trusted = "console-demo-trusted-ca.pem"
	if err := os.WriteFile(filepath.Join(f.directory, trusted), append(shared, authority...), 0600); err != nil {
		return nil, err
	}
	assistance, err := ReserveAssistanceRelay("127.0.0.1", "127.0.0.1")
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, errors.Join(errors.New("console demo origin is not TCP"), listener.Close())
	}
	origin := fmt.Sprintf("https://localhost:%d", address.Port)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /feeds/", func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, r.URL.Path, time.Time{}, bytes.NewReader(data))
	})
	mux.HandleFunc("POST /webhook", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20)); err != nil {
			http.Error(w, "unreadable delivery", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	f.demo = &consoleDemoOrigin{server: server, done: make(chan error, 1)}
	go func() { f.demo.done <- server.ServeTLS(listener, "", "") }()
	for _, source := range sources {
		source.Url = origin + source.GetUrl()
	}
	advisories := &configv1.AdvisoryConfig{Feeds: sources, RefreshEnabled: true, InventoryMaxAgeSeconds: proto.Uint32(604800)}
	document.Proto.Advisories, document.Proto.Assistance, document.Proto.TrustedCaFile = advisories, assistance, trusted
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return nil, err
	}
	if err := f.writeConfig(encoded); err != nil {
		return nil, err
	}
	if err := f.Restart(ctx); err != nil {
		return nil, err
	}
	return &ConsoleDemo{WebhookURL: origin + "/webhook", CAPEM: string(authority)}, nil
}

// consoleDemoCertificate returns a fresh CA PEM and a localhost leaf signed by
// it. Both private keys exist only in this process.
func consoleDemoCertificate() ([]byte, tls.Certificate, error) {
	var leaf tls.Certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, leaf, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, leaf, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lindm console demo origin CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, leaf, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, leaf, err
	}
	leaf = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf, nil
}
