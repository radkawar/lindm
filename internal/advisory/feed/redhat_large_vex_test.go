// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const (
	redHatLargeVEXBytes  = 107532378
	redHatLargeVEXSHA256 = "410bffef61795466c3b454ccbe33ff12864efc5ec3c411236bb1ca0d273f7c64"
	redHatLargeVEXURL    = "https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-33186.json"
)

func redHatLargeVEXFixture(t *testing.T) *io.LimitedReader {
	t.Helper()
	file, err := os.Open("testdata/redhat-cve-2026-33186.json.zst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	decoder, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20), zstd.WithDecoderMaxWindow(16<<20))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(decoder.Close)
	return &io.LimitedReader{R: decoder, N: redHatLargeVEXBytes + 1}
}

func TestRedHatStreamLargestOriginalVEX(t *testing.T) {
	// Independently derived from exact vendor CPEs, RPM purls, relationships and
	// product_status entries, not from the parser under test. Provenance records
	// each native relationship and the authenticated weekly archive custody.
	type identity struct {
		name   string
		source bool
	}
	type expectedClaim struct {
		arch, fixed string
		notAffected bool
	}
	want := map[identity]expectedClaim{
		{"rhc", false}:           {"x86_64", "1:0.2.7-4.el9_7", false},
		{"rhc", true}:            {"", "1:0.2.7-4.el9_7", false},
		{"image-builder", false}: {"x86_64", "0:52.1-1.el9_8", false},
		{"podman", true}:         {"", "", true},
		{"ignition", false}:      {"", "", false},
		{"ignition", true}:       {"", "", false},
	}
	seen := make(map[identity]int, len(want))
	pin, err := hex.DecodeString(redHatLargeVEXSHA256)
	if err != nil {
		t.Fatal(err)
	}
	config := redHatSource("9.8", "standard")
	config.Url = redHatLargeVEXURL
	config.ExpectedSha256 = pin
	input := redHatLargeVEXFixture(t)
	digest := sha256.New()
	claims := 0
	doc, err := ParseStream(t.Context(), config, io.TeeReader(input, digest), func(record *advisoryv1.Advisory) error {
		claims++
		if record.Id != "CVE-2026-33186" || len(record.Cves) != 1 || record.Cves[0] != "CVE-2026-33186" || record.SourceUrl != config.Url || record.PlatformRelease != "9.8" || record.PlatformStream != "standard" {
			t.Errorf("largest VEX lost native source/CVE identity: %v", record)
		}
		if record.SourcePackage {
			if record.Architecture != "" {
				t.Errorf("source package became an installed binary: %v", record)
			}
		} else if record.Architecture != "" && record.Architecture != "noarch" && record.Architecture != "x86_64" {
			t.Errorf("largest VEX crossed configured architecture: %v", record)
		}
		key := identity{record.PackageName, record.SourcePackage}
		expected, exists := want[key]
		if !exists {
			return nil
		}
		seen[key]++
		if record.Architecture != expected.arch || record.FixedVersion != expected.fixed || record.NotAffected != expected.notAffected || record.AssessmentUnknown || record.IntroducedVersion != "" || record.LastAffectedVersion != "" || record.ModuleName != "" || record.ModuleStream != "" {
			t.Errorf("largest VEX changed source-derived native status/backport: %v", record)
		}
		return nil
	}, nil)

	if err != nil {
		t.Fatal(err)
	}
	if len(doc.RejectedRecords) != 0 {
		t.Fatalf("largest legitimate VEX was rejected: %v", doc.RejectedRecords)
	}
	for key := range want {
		if seen[key] != 1 {
			t.Errorf("native package %s source=%t emitted %d times, want exactly once", key.name, key.source, seen[key])
		}
	}
	if claims < len(want) || input.N != 1 || !bytes.Equal(digest.Sum(nil), pin) || !bytes.Equal(doc.SourceSha256, pin) {
		t.Fatalf("largest VEX source identity or consumption: claims=%d remaining=%d digest=%x source_digest=%x", claims, input.N, digest.Sum(nil), doc.SourceSha256)
	}
	if len(doc.Advisories) != 0 || len(doc.Artifacts) != 0 || doc.SnapshotAt != nil || doc.CompleteSnapshot {
		t.Fatalf("offline VEX retained claims or invented online authenticity/coverage: %v", doc)
	}
}
