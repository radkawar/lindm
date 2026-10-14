// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const (
	redHatLargeFixtureBytes  = 46707671
	redHatLargeFixtureSHA256 = "18f042e9fe16fd0312fd79b71aa8f78e8baeb4c60e9cf2a11274a30475d41214"
	redHatLargeFixtureURL    = "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_9315.json"
)

// The gzip is local storage packaging, not a replacement vendor payload. Limit
// expansion to the exact pinned original plus one byte to detect fixture growth.
func redHatLargeFixture(t *testing.T) *io.LimitedReader {
	t.Helper()
	file, err := os.Open("testdata/redhat-rhsa-2024_9315.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	return &io.LimitedReader{R: reader, N: redHatLargeFixtureBytes + 1}
}

func redHatLargePin(t *testing.T) []byte {
	t.Helper()
	pin, err := hex.DecodeString(redHatLargeFixtureSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func TestRedHatLargeFixtureOriginalSignatureAndDigest(t *testing.T) {
	trust, err := newVendorTrust()
	if err != nil {
		t.Fatal(err)
	}
	proof := fixture(t, "redhat-rhsa-2024_9315.json.asc")
	checksum, err := vendorChecksum(fixture(t, "redhat-rhsa-2024_9315.json.sha256"), redHatLargeFixtureURL)
	if err != nil {
		t.Fatal(err)
	}
	reader := redHatLargeFixture(t)
	digest := sha256.New()
	signer, signedAt, err := trust.verify(t.Context(), redHatFingerprint, io.TeeReader(reader, digest), proof, time.Date(2026, 10, 10, 23, 59, 59, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if reader.N != 1 || !bytes.Equal(digest.Sum(nil), checksum) || !bytes.Equal(checksum, redHatLargePin(t)) {
		t.Fatalf("large fixture lost original byte identity: remaining=%d digest=%x", reader.N, digest.Sum(nil))
	}
	if signer != redHatFingerprint || !signedAt.Equal(time.Unix(1790952342, 0)) {
		t.Fatalf("large fixture provenance: signer=%s signed_at=%s", signer, signedAt)
	}
}

// Retain only the semantic assertion and the CVE set, not all normalized claims.
// The real vendor document is larger than the former 32 MiB parser/fetch limit.
func redHatLargeConsumer(t *testing.T, sourceURL string) (func(*advisoryv1.Advisory) error, func()) {
	t.Helper()
	cves := make(map[string]bool)
	kernelCVEs := make(map[string]bool)
	var known *advisoryv1.Advisory
	consume := func(record *advisoryv1.Advisory) error {
		if record.Id != "RHSA-2024:9315" || record.SourceUrl != sourceURL || record.PlatformRelease != "9.8" || record.PlatformStream != "standard" {
			t.Errorf("large fixture lost source/product identity: %v", record)
		}
		for _, cve := range record.Cves {
			cves[cve] = true
			if record.PackageName == "kernel-core" && !record.SourcePackage && record.Architecture == "x86_64" {
				kernelCVEs[cve] = true
				if cve == "CVE-2019-25162" {
					known = record
				}
			}
		}
		return nil
	}
	assert := func() {
		t.Helper()
		if len(cves) != 594 || len(kernelCVEs) != 594 {
			t.Fatalf("lost genuine CVEs: all=%d kernel-core=%d, want 594 each", len(cves), len(kernelCVEs))
		}
		if known == nil {
			t.Fatal("missing genuine kernel-core / CVE-2019-25162 claim")
		}
		if known.FixedVersion != "0:5.14.0-503.11.1.el9_5" || known.AssessmentUnknown || known.NotAffected || known.ModuleName != "" || known.ModuleStream != "" {
			t.Fatalf("large document lost native kernel fix: %v", known)
		}
	}
	return consume, assert
}

func TestRedHatStreamLargestOriginalDocument(t *testing.T) {
	config := redHatSource("9.8", "standard")
	config.Url = redHatLargeFixtureURL
	config.ExpectedSha256 = redHatLargePin(t)
	input := redHatLargeFixture(t)
	consume, assertClaims := redHatLargeConsumer(t, config.Url)
	doc, err := ParseStream(t.Context(), config, input, consume, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertClaims()
	if input.N != 1 || len(doc.Advisories) != 0 || doc.CompleteSnapshot || !bytes.Equal(doc.SourceSha256, config.ExpectedSha256) || doc.SnapshotAt != nil {
		t.Fatalf("large import metadata or byte bound: remaining=%d doc=%v", input.N, doc)
	}
	if len(doc.Artifacts) != 0 {
		t.Fatalf("offline import invented authenticated artifacts: %v", doc.Artifacts)
	}
}

func TestRedHatFetchStreamLargestAuthenticatedDocument(t *testing.T) {
	checksum := fixture(t, "redhat-rhsa-2024_9315.json.sha256")
	signature := fixture(t, "redhat-rhsa-2024_9315.json.asc")
	input := redHatLargeFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("signed original requested with content transformation")
		}
		var body io.Reader
		switch r.URL.Path {
		case "/rhsa-2024_9315.json":
			body = input
		case "/rhsa-2024_9315.json.sha256":
			body = bytes.NewReader(checksum)
		case "/rhsa-2024_9315.json.asc":
			body = bytes.NewReader(signature)
		default:
			http.NotFound(w, r)
			return
		}
		if _, err := io.Copy(w, body); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := New(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	config := redHatSource("9.8", "standard")
	config.Url = server.URL + "/rhsa-2024_9315.json"
	config.ExpectedSha256 = redHatLargePin(t)
	consume, assertClaims := redHatLargeConsumer(t, config.Url)
	doc, err := client.FetchStream(t.Context(), config, consume, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertClaims()
	if input.N != 1 || requests.Load() != 3 || len(doc.Advisories) != 0 || doc.CompleteSnapshot || !bytes.Equal(doc.SourceSha256, config.ExpectedSha256) || !doc.GetSnapshotAt().AsTime().Equal(time.Unix(1790952342, 0)) {
		t.Fatalf("large signed stream metadata: requests=%d doc=%v", requests.Load(), doc)
	}
	if len(doc.Artifacts) != 1 || doc.Artifacts[0].Url != config.Url || !bytes.Equal(doc.Artifacts[0].Sha256, config.ExpectedSha256) || doc.Artifacts[0].SignerFingerprint != redHatFingerprint {
		t.Fatalf("signed source provenance lost: %v", doc.Artifacts)
	}
}
