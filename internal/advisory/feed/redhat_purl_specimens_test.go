// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// The compressed fixtures preserve original members of the authenticated weekly
// archive. Hash the expanded stream, without allocating the original document.
func redHatPinnedGZIPFixture(t *testing.T, name, digest string) io.Reader {
	t.Helper()
	file, err := os.Open("testdata/redhat-" + name + ".json.gz")
	if err != nil {
		t.Fatal(err)
	}
	input, err := gzip.NewReader(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	hash := sha256.New()
	t.Cleanup(func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
		if err := file.Close(); err != nil {
			t.Error(err)
		}
		if got := hex.EncodeToString(hash.Sum(nil)); got != digest {
			t.Errorf("original signed-archive member changed or was not consumed: %s, got %s", name, got)
		}
	})
	return io.TeeReader(input, hash)
}

func TestRedHatGenuineNestedPURLNamespaceDoesNotIdentifyHostSource(t *testing.T) {
	input := redHatPinnedGZIPFixture(t, "cve-2021-27358", "5986198bc015955b43f5752e7e946aa73d32af7b50efce0c9802113c8a7d07e6")
	var claims advisoryv1.FeedDocument
	doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), input, func(record *advisoryv1.Advisory) error {
		claims.Advisories = append(claims.Advisories, record)
		return nil
	})
	if err != nil || doc == nil || len(doc.RejectedRecords) != 0 || len(claims.Advisories) != 2 {
		t.Fatalf("layered namespace poisoned independent native claims: metadata=%v claims=%v err=%v", doc, claims.Advisories, err)
	}
	for _, name := range []string{"grafana", "grafana-selinux"} {
		record := redHatRecord(t, &claims, name, "CVE-2021-27358", "", false)
		if !record.NotAffected || record.AssessmentUnknown || record.Architecture != "" || record.FixedVersion != "" || record.IntroducedVersion != "" || record.LastAffectedVersion != "" {
			t.Fatalf("native binary negative changed: %v", record)
		}
	}
}

func TestRedHatGenuineBareLabelVersionedPURLRemainsUnfixed(t *testing.T) {
	input := redHatPinnedGZIPFixture(t, "cve-2026-103111", "12d4ae96147a3aa6a2e2cd1ea633532680f316840f2bbea6b2429ec3871d85bf")
	var source, binary *advisoryv1.Advisory
	doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), input, func(record *advisoryv1.Advisory) error {
		if record.PackageName == "pcre2" && record.ModuleName == "" {
			if record.SourcePackage {
				source = record
			} else {
				binary = record
			}
		}
		return nil
	})
	if err != nil || doc == nil || len(doc.RejectedRecords) != 0 || source == nil || binary == nil {
		t.Fatalf("opaque display label displaced PURL identity: metadata=%v source=%v binary=%v err=%v", doc, source, binary, err)
	}
	if source.GetComponentVersion() != "0:10.44-1.el10.3" {
		t.Fatalf("exact vendor product declaration was lost independently of affected bounds: %v", source)
	}
	for _, record := range []*advisoryv1.Advisory{source, binary} {
		if len(record.Cves) != 1 || record.Cves[0] != "CVE-2026-103111" || record.AssessmentUnknown || record.NotAffected || record.FixedVersion != "" || record.IntroducedVersion != "" || record.LastAffectedVersion != "" {
			t.Fatalf("known_affected invented a fixed/exact version from component PURL: %v", record)
		}
	}
}

func TestRedHatGenuineColonNameQuarantinesWholeDocumentWithoutModuleRepair(t *testing.T) {
	input := redHatPinnedGZIPFixture(t, "cve-2023-44487", "6c3e890cb7965a23e2eca0d95612d8f8ba4e695de94b291d384aec11b32389cc")
	var claims []*advisoryv1.Advisory
	doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), input, func(record *advisoryv1.Advisory) error {
		claims = append(claims, record)
		return nil
	})
	if err != nil || doc == nil || len(doc.RejectedRecords) != 1 {
		t.Fatalf("invalid source component escaped rejection: metadata=%v err=%v", doc, err)
	}
	rejected := doc.RejectedRecords[0]
	if rejected.Id != "CVE-2023-44487" || rejected.Unscoped || len(rejected.PackageNames) <= 64 || !strings.Contains(rejected.Reason, "pkg:rpm/redhat/nginx:1.24?arch=src") {
		t.Fatalf("bounded module family lost scope or original diagnostic: %v", rejected)
	}
	// The original tree independently declares native nginx source RPMs with
	// rpmmod=nginx:1.22 and their binaries on RHEL 9. These bound the malformed
	// source module marker to the nginx component family, not to an invented
	// nginx:1.24 RPM identity. Earlier valid HTTP/2 and unrelated-to-nginx
	// component claims in this same rejected document must also be quarantined.
	for _, name := range []string{"nginx", "nginx-core", "nginx-filesystem", "httpd", "mod_http2", "buildah", "dotnet-runtime-6.0"} {
		if !slices.Contains(rejected.PackageNames, name) {
			t.Errorf("discarded document omitted component %q: %v", name, rejected.PackageNames)
		}
	}
	for _, name := range []string{"nginx:1.24", "bash", "rh-nginx118-nginx"} {
		if slices.Contains(rejected.PackageNames, name) {
			t.Errorf("invented or off-stream component %q quarantined", name)
		}
	}
	if len(claims) != 2*len(rejected.PackageNames) {
		t.Fatalf("native/source quarantine incomplete: claims=%d names=%d", len(claims), len(rejected.PackageNames))
	}
	for _, claim := range claims {
		if !claim.SourceRecordRejected || !claim.AssessmentUnknown || claim.NotAffected || len(claim.Cves) != 0 || claim.ModuleName != "" || claim.ModuleStream != "" || claim.FixedVersion != "" || claim.IntroducedVersion != "" || claim.LastAffectedVersion != "" {
			t.Fatalf("rejected document retained/repaired an advisory claim: %v", claim)
		}
	}
}

// One opaque product ID is declared once per module build that ships the same
// NEVRA; the PURLs differ only in rpmmod version:context. That is a semantic
// redeclaration of the normalized module name/stream identity, not a conflict.
func TestRedHatGenuineModuleBuildRedeclarationsAreNotConflicts(t *testing.T) {
	input := redHatPinnedGZIPFixture(t, "cve-2024-0985", "99d4546240af8264b060d4bc4f4e84deff0df8e6960df02d6de6af4c1ed15b1f")
	claims, modules := 0, 0
	doc, err := stageRedHatStream(t.Context(), redHatSource("9.8", "standard"), redHatValidator(t), input, func(record *advisoryv1.Advisory) error {
		claims++
		if record.ModuleName == "postgresql" && record.ModuleStream == "15" {
			modules++
		}
		return nil
	})
	if err != nil || doc == nil || len(doc.RejectedRecords) != 0 || claims == 0 || modules == 0 {
		t.Fatalf("module build redeclaration rejected native claims: metadata=%v claims=%d postgresql:15=%d err=%v", doc, claims, modules, err)
	}
}

func TestRedHatSameComponentRequiresIdenticalNormalizedIdentity(t *testing.T) {
	const base = "pkg:rpm/redhat/pg_repack@1.4.8-1.module%2Bel9.2.0%2B17405%2Baeb9ec60?arch=src&rpmmod="
	previous := redHatProduct{arch: "src"}
	previous.product.Helper.PURL = base + "postgresql:15:9020020240213145157:rhel9"
	for _, test := range []struct {
		purl string
		same bool
	}{
		{base + "postgresql:15:9030020240209100638:rhel9", true},
		{base + "postgresql:15", true},
		{base + "postgresql:16:9030020240209100638:rhel9", false},
		{base + "pgsql:15:9020020240213145157:rhel9", false},
		{"pkg:rpm/redhat/pg_repack@1.4.8-2.module%2Bel9.2.0%2B17405%2Baeb9ec60?arch=src&rpmmod=postgresql:15:9020020240213145157:rhel9", false},
		{"pkg:rpm/redhat/pg_repack@1.4.8-1.module%2Bel9.2.0%2B17405%2Baeb9ec60?arch=src&epoch=1&rpmmod=postgresql:15:9020020240213145157:rhel9", false},
		{"pkg:rpm/redhat/rhel9/pg_repack@1.4.8-1.module%2Bel9.2.0%2B17405%2Baeb9ec60?arch=src&rpmmod=postgresql:15:9020020240213145157:rhel9", false},
	} {
		var redeclared suseProduct
		redeclared.Helper.PURL = test.purl
		if got := redHatSameComponent(previous, redeclared); got != test.same {
			t.Errorf("%s: same=%t, want %t", test.purl, got, test.same)
		}
	}
	var differentCPE suseProduct
	differentCPE.Helper.PURL, differentCPE.Helper.CPE = previous.product.Helper.PURL, "cpe:/a:redhat:enterprise_linux:9::appstream"
	if redHatSameComponent(previous, differentCPE) {
		t.Error("differing product CPE treated as the same component")
	}
}
