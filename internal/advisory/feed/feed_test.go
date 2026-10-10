package feed

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func source(distro, release string, format advisoryv1.FeedFormat) *advisoryv1.FeedSource {
	return &advisoryv1.FeedSource{Id: "test", Distro: distro, Release: release, Url: "https://vendor.example/advisory", Format: format, MaxAgeSeconds: 3600}
}

// Fixtures are actual fetched vendor records; only the installed predecessor and
// successor versions below are test inputs. Same-upstream revision changes prove
// that native backports, rather than a generic upstream fixed version, govern.
func TestVendorBackports(t *testing.T) {
	for _, test := range []struct {
		file, digest, distro, release, arch, name, before, fixed, after string
		format                                                          advisoryv1.FeedFormat
		sourcePackage                                                   bool
	}{
		{"ubuntu-USN-6859-1.json", "e179d515688434574c1835bbff757f0839e37e08fd8d3301168513cbcbdd2f4e", "ubuntu", "24.04", "", "openssh-server", "1:9.6p1-3ubuntu13.2", "1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.4", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, false},
		{"debian-DSA-5724-1.json", "26841e28408b0912ae777691790b8e966492d9b6fc92c42aa3eab648a92b7e58", "debian", "12", "", "openssh", "1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u4", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, true},
		{"fedora44-sudo.xml", "3ed801b9bccd9f65bbba7d04421fb0395549cd4f076699fedc5f1d7915476d0f", "fedora", "44", "x86_64", "sudo", "0:1.9.17-9.p2.fc44", "0:1.9.17-10.p2.fc44", "0:1.9.17-11.p2.fc44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, false},
		{"rocky-RLSA-2024-6783.json", "2be38769894ce8b419202930dd5fbdd1e2c64db48ae3f6de7e9d2c39f5e524db", "rocky", "9", "", "openssl", "1:3.0.7-27.el9_4", "1:3.0.7-28.el9_4", "1:3.0.7-29.el9_4", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, false},
		{"alma-ALSA-2024-6783.json", "23b2a57735fdb26997c6251c9d27c1f5d3c59b18102ee0d12ca7550dde52bd9c", "almalinux", "9", "", "openssl-libs", "1:3.0.7-27.el9_4", "1:3.0.7-28.el9_4", "1:3.0.7-29.el9_4", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, false},
	} {
		t.Run(test.distro, func(t *testing.T) {
			config := source(test.distro, test.release, test.format)
			config.Architecture = test.arch
			doc, err := Parse(config, bytes.NewReader(fixture(t, test.file)))
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(doc.GetSourceSha256()); got != test.digest {
				t.Fatalf("source digest %s; want %s", got, test.digest)
			}
			if doc.GetCompleteSnapshot() {
				t.Fatal("single advisory claimed complete coverage")
			}
			var found *advisoryv1.Advisory
			for _, record := range doc.GetAdvisories() {
				if test.distro == "ubuntu" && strings.Contains(record.GetFixedVersion(), "ubuntu0.10") {
					t.Fatal("jammy record leaked into noble")
				}
				if test.distro == "fedora" && record.GetArchitecture() != "x86_64" && record.GetArchitecture() != "noarch" {
					t.Fatal("foreign architecture leaked")
				}
				if record.GetPackageName() == test.name {
					found = record
				}
			}
			if found == nil {
				t.Fatalf("missing package %s", test.name)
			}
			if found.GetFixedVersion() != test.fixed || found.GetSourcePackage() != test.sourcePackage {
				t.Fatalf("wrong normalized package: %v", found)
			}
			if test.distro == "fedora" && (len(found.GetCves()) != 1 || found.GetCves()[0] != "CVE-2026-96512") {
				t.Fatalf("lost vendor-disclosed sudo CVE: %v", found.GetCves())
			}
			for _, comparison := range []struct {
				version string
				want    int
			}{{test.before, -1}, {test.fixed, 0}, {test.after, 1}} {
				got, err := Compare(managerFor(test.distro), comparison.version, found.GetFixedVersion())
				if err != nil || got != comparison.want {
					t.Errorf("backport %s: compare=%d err=%v; want %d", comparison.version, got, err, comparison.want)
				}
			}
		})
	}
}

func TestUnsupportedInputsFailClosed(t *testing.T) {
	ubuntu := fixture(t, "ubuntu-USN-6859-1.json")
	fedora := fixture(t, "fedora44-sudo.xml")
	for _, test := range []struct {
		name   string
		input  []byte
		config *advisoryv1.FeedSource
	}{
		{"unknown-json", []byte(`{"records":[]}`), source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"semver", bytes.ReplaceAll(ubuntu, []byte(`"ECOSYSTEM"`), []byte(`"SEMVER"`)), source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"limit", bytes.ReplaceAll(ubuntu, []byte(`"fixed":`), []byte(`"limit":`)), source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"missing-source-map", bytes.ReplaceAll(ubuntu, []byte("arch=source"), []byte("arch=amd64")), source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"conflicting-release", bytes.ReplaceAll(ubuntu, []byte("distro=noble"), []byte("distro=jammy")), source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"foreign-product", ubuntu, source("debian", "12", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"rhel-not-rocky", fixture(t, "rocky-RLSA-2024-6783.json"), source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)},
		{"xml-product", bytes.ReplaceAll(fedora, []byte("Fedora 44"), []byte("Fedora 43")), source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)},
		{"xml-module", bytes.Replace(fedora, []byte(`<name>Fedora 44</name>`), []byte(`<name>Fedora 44</name><module name="nodejs" stream="22"/>`), 1), source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)},
		{"xml-unknown-architecture", bytes.ReplaceAll(fedora, []byte(`arch="x86_64"`), []byte(`arch="unknown"`)), source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)},
		{"xml-trailing", append(append([]byte(nil), fedora...), []byte(`<update/>`)...), source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)},
		{"xml-empty", []byte(`<updates/>`), source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.config.GetDistro() == "fedora" {
				test.config.Architecture = "x86_64"
			}
			if _, err := Parse(test.config, bytes.NewReader(test.input)); err == nil {
				t.Fatal("unsupported input accepted as clean")
			}
		})
	}
	if _, err := boundedRead(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("byte bound not enforced")
	}
}

func TestCompressedRawImportsPreserveDigest(t *testing.T) {
	raw := fixture(t, "fedora44-sudo.xml")
	var gzipBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuffer)
	if _, err := gzipWriter.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	zstdWriter, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	zstdBytes := zstdWriter.EncodeAll(raw, nil)
	if err := zstdWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for _, compressed := range [][]byte{gzipBuffer.Bytes(), zstdBytes} {
		config := source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)
		config.Architecture = "x86_64"
		digest := sha256.Sum256(compressed)
		config.ExpectedSha256 = digest[:]
		doc, err := Parse(config, bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(doc.GetSourceSha256(), digest[:]) || len(doc.GetAdvisories()) == 0 {
			t.Fatal("compressed bytes lost their source identity")
		}
		config.ExpectedSha256 = make([]byte, 32)
		if _, err := Parse(config, bytes.NewReader(compressed)); err == nil {
			t.Fatal("mismatched source pin accepted")
		}
	}
}

func TestOSVArchiveCoverageAndRejection(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("USN-6859-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(fixture(t, "ubuntu-USN-6859-1.json")); err != nil {
		t.Fatal(err)
	}
	// OSV permits withdrawn records without affected products.
	withdrawn, err := writer.Create("withdrawn.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withdrawn.Write([]byte(`{"id":"WITHDRAWN-TEST","schema_version":"1.7.3","withdrawn":"2026-01-01T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	config := source("ubuntu", "noble", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
	config.Url = "https://vendor.example/selected.zip"
	doc, err := Parse(config, bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if doc.GetCompleteSnapshot() {
		t.Fatal("selected-record archive claimed complete coverage")
	}
	config.Url = "https://vendor.example/all.zip"
	doc, err = Parse(config, bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if doc.GetCompleteSnapshot() {
		t.Fatal("arbitrary all.zip filename manufactured full coverage")
	}
	if _, err := Parse(config, bytes.NewReader([]byte("not a zip"))); err == nil {
		t.Fatal("malformed archive accepted")
	}
}

func TestHTTPSFetchAndRepomdIntegrity(t *testing.T) {
	// The transport envelope is synthetic; the advisory payload is the original
	// Fedora node. This proves network/raw-import equivalence, not live-feed reachability.
	raw := fixture(t, "fedora44-sudo.xml")
	digest := sha256.Sum256(raw)
	var calls atomic.Int64
	var corrupt atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/repodata/repomd.xml":
			checksum := hex.EncodeToString(digest[:])
			if corrupt.Load() {
				checksum = strings.Repeat("0", 64)
			}
			_, err := fmt.Fprintf(w, `<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo"><checksum type="sha256">%s</checksum><location href="repodata/advisories.xml"/></data></repomd>`, checksum)
			if err != nil {
				t.Error(err)
			}
		case "/repodata/advisories.xml":
			if _, err := w.Write(raw); err != nil {
				t.Error(err)
			}
		case "/redirect":
			http.Redirect(w, r, "http://127.0.0.1:1/advisory", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	config := source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD)
	config.Architecture, config.Url = "x86_64", server.URL+"/repodata/repomd.xml"
	doc, err := client.Fetch(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := Parse(config, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Online acquisition additionally records the actual referenced artifact,
	// not the repomd URL. Raw import has no acquisition provenance.
	if len(doc.GetArtifacts()) != 1 || doc.GetArtifacts()[0].GetUrl() != server.URL+"/repodata/advisories.xml" || !bytes.Equal(doc.GetArtifacts()[0].GetSha256(), digest[:]) {
		t.Fatalf("incorrect repomd artifact provenance: %v", doc.GetArtifacts())
	}
	imported.Artifacts = doc.GetArtifacts()
	if !proto.Equal(doc, imported) || calls.Load() != 2 {
		t.Fatalf("fetch/import mismatch or request bound: calls=%d", calls.Load())
	}
	corrupt.Store(true)
	if _, err := client.Fetch(context.Background(), config); err == nil {
		t.Fatal("repomd digest mismatch accepted")
	}
	config.Format, config.Url = advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, server.URL+"/redirect"
	if _, err := client.Fetch(context.Background(), config); err == nil {
		t.Fatal("HTTP redirect downgrade accepted")
	}
	config.Url = "http://127.0.0.1:1/advisory"
	if _, err := client.Fetch(context.Background(), config); err == nil {
		t.Fatal("plaintext source accepted")
	}
}

func TestProductAndRepositoryBindings(t *testing.T) {
	config := source("ubuntu", "noble", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)
	config.Architecture = "amd64"
	if !Applies(config, "ubuntu", "24.04", "x86_64") {
		t.Fatal("explicit noble alias not recognized")
	}
	if Applies(config, "ubuntu", "22.04", "x86_64") || Applies(config, "ubuntu", "24.04", "aarch64") || Applies(config, "debian", "24.04", "x86_64") {
		t.Fatal("mixed release, architecture or vendor")
	}
	config = source("rhel", "9.4", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)
	if Applies(config, "rhel", "9", "x86_64") || Applies(config, "rocky", "9.4", "x86_64") {
		t.Fatal("inferred RHEL stream/vendor equivalence")
	}
	location, checksum, err := updateLocation("https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml", fixture(t, "fedora44-repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(location, "f7508933e5ed78ccc41d1cea6dc7d5f93d998b7fe97e7c9e84268e2ce8aadcac-updateinfo.xml.zst") || hex.EncodeToString(checksum) != "f7508933e5ed78ccc41d1cea6dc7d5f93d998b7fe97e7c9e84268e2ce8aadcac" {
		t.Fatal("lost genuine Fedora metadata checksum/location")
	}
	for _, href := range []string{"https://evil.example/feed", "repodata/../feed", "repodata/feed?override=1"} {
		input := fmt.Sprintf(`<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo"><checksum type="sha256">%s</checksum><location href="%s"/></data></repomd>`, strings.Repeat("a", 64), href)
		if _, _, err := updateLocation("https://vendor.example/repodata/repomd.xml", []byte(input)); err == nil {
			t.Errorf("accepted unsafe href %s", href)
		}
	}
}

func TestCanceledFetch(t *testing.T) {
	client, err := New(&http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Fetch(ctx, source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)); err == nil {
		t.Fatal("canceled fetch succeeded")
	}
	if _, err := Parse(nil, strings.NewReader("{}")); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := Parse(source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON), io.Reader(nil)); err == nil {
		t.Fatal("nil reader accepted")
	}
}

func TestVendorMixedProductContainer(t *testing.T) {
	// Only the wrapper is synthetic; both nodes are unchanged contiguous
	// captures from the same actual Fedora44 updateinfo response.
	raw := append([]byte("<updates>"), fixture(t, "fedora44-sudo.xml")...)
	raw = append(raw, fixture(t, "fedora45-shim.xml")...)
	raw = append(raw, []byte("</updates>")...)
	config := source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO)
	config.Architecture = "x86_64"
	doc, err := Parse(config, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.GetAdvisories()) == 0 {
		t.Fatal("matching product omitted")
	}
	for _, advisory := range doc.GetAdvisories() {
		if advisory.GetId() != "FEDORA-2026-7d4732cbab" {
			t.Fatal("foreign release mixed into configured product")
		}
	}
	config.Release = "rawhide"
	if _, err := Parse(config, bytes.NewReader(raw)); err == nil {
		t.Fatal("rolling release alias accepted")
	}
}

func TestNormalizedSchemaBoundsAndCVEExtraction(t *testing.T) {
	raw := bytes.ReplaceAll(fixture(t, "ubuntu-USN-6859-1.json"), []byte("openssh"), []byte(strings.Repeat("a", 513)))
	if _, err := Parse(source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON), bytes.NewReader(raw)); err == nil {
		t.Fatal("oversized normalized package accepted")
	}
	cves := disclosedCVEs("CVE-2026-96512, CVE-2026-96512; xCVE-2026-11111; CVE-2026-22222suffix; (CVE-2025-1234).", nil)
	if len(cves) != 2 || cves[0] != "CVE-2026-96512" || cves[1] != "CVE-2025-1234" {
		t.Fatalf("unexpected disclosed CVEs: %v", cves)
	}
}

func TestLaterCVECannotLowerVendorSeverity(t *testing.T) {
	var record osvRecord
	if err := json.Unmarshal(fixture(t, "ubuntu-USN-6859-1.json"), &record); err != nil {
		t.Fatal(err)
	}
	for i := range record.Affected {
		cves := record.Affected[i].DatabaseSpecific.CVEsMap.CVEs
		if len(cves) == 0 {
			t.Fatal("vendor fixture lacks CVE severity")
		}
		lower := cves[0]
		lower.Severity = append(lower.Severity[:0:0], lower.Severity...)
		for j := range lower.Severity {
			if lower.Severity[j].Type == "Ubuntu" {
				lower.Severity[j].Score = "low"
			}
		}
		record.Affected[i].DatabaseSpecific.CVEsMap.CVEs = append(cves, lower)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range doc.Advisories {
		if finding.Severity != "high" {
			t.Fatalf("later lower-severity CVE hid highest vendor severity: %s", finding.Severity)
		}
	}
}
