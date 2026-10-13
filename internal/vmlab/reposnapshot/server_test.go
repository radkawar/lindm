//go:build linux

package reposnapshot

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

func servingFixture(t *testing.T) (*Server, *http.Client, string, context.CancelFunc) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "repodata"), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("signed metadata bytes")
	if err := os.WriteFile(filepath.Join(root, "repodata", "repomd.xml"), body, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	manifest := &labv1.RepositorySnapshotManifest{ManifestSha256: strings.Repeat("a", 64), Files: []*labv1.RepositorySnapshotFile{{Path: "repodata/repomd.xml", Sha256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(body))}}}
	if err := os.WriteFile(filepath.Join(root, "gpg-pubkey-fixture.asc"), body, 0600); err != nil {
		t.Fatal(err)
	}
	manifest.Files = append(manifest.Files, &labv1.RepositorySnapshotFile{Path: "gpg-pubkey-fixture.asc", Sha256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(body))})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server, err := startVerified(ctx, manifest, root, ServeOptions{keyPins: map[string]string{"gpg-pubkey-fixture.asc": strings.Repeat("A", 40)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(server.CAPEM) {
		t.Fatal("invalid fixture CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}
	t.Cleanup(transport.CloseIdleConnections)
	return server, &http.Client{Transport: transport, Timeout: 5 * time.Second}, root, cancel
}

func TestSnapshotHTTPSExactPathsAndMethods(t *testing.T) {
	server, client, root, _ := servingFixture(t)
	if err := os.WriteFile(filepath.Join(root, "unlisted"), []byte("must not be served"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "repodata/repomd.xml", http.StatusOK},
		{http.MethodHead, "repodata/repomd.xml", http.StatusOK},
		{http.MethodPost, "repodata/repomd.xml", http.StatusMethodNotAllowed},
		{http.MethodPut, "repodata/repomd.xml", http.StatusMethodNotAllowed},
		{http.MethodGet, "unlisted", http.StatusNotFound},
		{http.MethodGet, "", http.StatusNotFound},
		{http.MethodGet, "repodata/", http.StatusNotFound},
		{http.MethodGet, "../unlisted", http.StatusNotFound},
		{http.MethodGet, "repodata/../repodata/repomd.xml", http.StatusNotFound},
		{http.MethodGet, "repodata%2frepomd.xml", http.StatusNotFound},
		{http.MethodGet, "repodata/%72epomd.xml", http.StatusNotFound},
		{http.MethodGet, "repodata/repomd.xml?download=1", http.StatusNotFound},
		{http.MethodGet, "gpg-pubkey-fixture.asc?fpr=" + strings.Repeat("A", 40), http.StatusOK},
		{http.MethodHead, "gpg-pubkey-fixture.asc?fpr=" + strings.Repeat("A", 40), http.StatusOK},
		{http.MethodGet, "gpg-pubkey-fixture.asc?fpr=" + strings.Repeat("B", 40), http.StatusNotFound},
		{http.MethodGet, "gpg-pubkey-fixture.asc?fpr=" + strings.Repeat("A", 40) + "&extra=1", http.StatusNotFound},
		{http.MethodGet, "gpg-pubkey-fixture.asc?fpr=" + strings.Repeat("A", 40) + "&fpr=" + strings.Repeat("A", 40), http.StatusNotFound},
		{http.MethodGet, "repodata/repomd.xml?fpr=" + strings.Repeat("A", 40), http.StatusNotFound},
		{http.MethodGet, "gpg-pubkey-fixture.asc?", http.StatusNotFound},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", response.StatusCode, tc.status)
			}
			if tc.status == http.StatusOK && tc.method == http.MethodGet && string(body) != "signed metadata bytes" {
				t.Fatalf("unexpected payload %q", body)
			}
			if tc.method == http.MethodHead && len(body) != 0 {
				t.Fatal("HEAD returned a body")
			}
		})
	}
}

func TestSnapshotHTTPSRejectsMutationAndSymlinks(t *testing.T) {
	for _, change := range []string{"same-size", "growth", "symlink", "parent-symlink"} {
		t.Run(change, func(t *testing.T) {
			server, client, root, _ := servingFixture(t)
			name := filepath.Join(root, "repodata", "repomd.xml")
			switch change {
			case "same-size":
				if err := os.WriteFile(name, []byte("altered metadata data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "growth":
				if err := os.WriteFile(name, []byte(strings.Repeat("x", 4096)), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(name, name+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(name+".real", name); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Rename(filepath.Join(root, "repodata"), filepath.Join(root, "real")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "repodata")); err != nil {
					t.Fatal(err)
				}
			}
			response, err := client.Get(server.URL + "repodata/repomd.xml")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("mutation accepted: %d", response.StatusCode)
			}
		})
	}
}

func TestSnapshotHTTPSBoundsWaitingRequests(t *testing.T) {
	server, client, _, _ := servingFixture(t)
	for range cap(server.admitted) {
		server.admitted <- struct{}{}
	}
	response, err := client.Get(server.URL + "repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") != "1" {
		t.Fatalf("full request queue returned %d, retry %q", response.StatusCode, response.Header.Get("Retry-After"))
	}
	for range cap(server.admitted) {
		<-server.admitted
	}
	response, err = client.Get(server.URL + "repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("released request capacity returned %d", response.StatusCode)
	}
}

// A solver may select an RPM the signed metadata names but the closure lacks;
// the server, not the client's opaque media error, must name it.
func TestSnapshotHTTPSReportsUnretainedPackages(t *testing.T) {
	server, client, _, _ := servingFixture(t)
	if err := server.Refused().Err(); err != nil {
		t.Fatalf("fresh server reported refusals: %v", err)
	}
	for _, path := range []string{"aarch64/missing-1.0-1.aarch64.rpm", "aarch64/missing-1.0-1.aarch64.rpm", "media.1/media", "repodata/repomd.xml"} {
		response, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	refused := server.Refused()
	if refused.UnlistedTotal != 2 || len(refused.UnlistedPackages) != 1 || refused.UnlistedPackages[0] != "aarch64/missing-1.0-1.aarch64.rpm" || refused.Capacity != 0 {
		t.Fatalf("refusals = %+v", refused)
	}
	if err := refused.Err(); err == nil || !strings.Contains(err.Error(), "missing-1.0-1.aarch64.rpm") {
		t.Fatalf("refusal description = %v", err)
	}
}

func TestSnapshotPayloadRemainsImmutableAfterVerification(t *testing.T) {
	server, _, root, _ := servingFixture(t)
	payload, err := server.verifiedPayload(context.Background(), server.Manifest.GetFiles()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = payload.Close() }()
	if err := os.WriteFile(filepath.Join(root, "repodata", "repomd.xml"), []byte("mutated after verification"), 0600); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "signed metadata bytes" {
		t.Fatalf("immutable spool changed: %q", body)
	}
	if _, err := payload.Write([]byte("x")); err == nil {
		t.Fatal("payload retained writable descriptor")
	}
}

func TestSnapshotHTTPSIsolatedTrustAndCancellation(t *testing.T) {
	server, client, _, cancel := servingFixture(t)
	untrusted := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}, Timeout: 5 * time.Second}
	response, err := untrusted.Get(server.URL + "repodata/repomd.xml")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("ephemeral authority was trusted by host defaults")
	}
	cancel()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	response, err = client.Get(server.URL + "repodata/repomd.xml")
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("listener remained available after context cancellation")
	}
	if _, err := os.Stat(server.spool); !os.IsNotExist(err) {
		t.Fatalf("spool survived close: %v", err)
	}
}

// Two authorities never share an issuer name or serial, so a stale anchor
// left in a golden cannot stand in for the lane CA, and a lane leaf verifies
// only against its own CA.
func TestSnapshotAuthoritiesAreDistinct(t *testing.T) {
	var cas []*x509.Certificate
	var leaves []*x509.Certificate
	for range 2 {
		certificate, _, err := snapshotCertificate("127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(certificate.Certificate[1])
		if err != nil {
			t.Fatal(err)
		}
		leaves, cas = append(leaves, leaf), append(cas, ca)
	}
	if cas[0].Subject.String() == cas[1].Subject.String() || cas[0].SerialNumber.Cmp(cas[1].SerialNumber) == 0 || leaves[0].SerialNumber.Cmp(leaves[1].SerialNumber) == 0 {
		t.Fatalf("authorities share an issuer name or serial: %s / %s", cas[0].Subject, cas[1].Subject)
	}
	for i, leaf := range leaves {
		for j, ca := range cas {
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots})
			if (err == nil) != (i == j) {
				t.Fatalf("leaf %d against CA %d: %v", i, j, err)
			}
		}
	}
}
