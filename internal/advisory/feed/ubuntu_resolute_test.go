package feed

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// Genuine records from the canonical 2026-10-10 Ubuntu all.zip. Resolute is
// configured numerically ("26.04", ecosystem "Ubuntu:26.04:LTS", purl distro
// resolute). The export also keeps 15 withdrawn resolute records under the
// development-series label "Ubuntu:26.04" (here pam); withdrawal, not the
// label, removes them, and they never become rejections or coverage gaps.
func TestUbuntuResoluteCanonicalRecords(t *testing.T) {
	notice, withdrawn := fixture(t, "ubuntu-USN-8861-1.json"), fixture(t, "ubuntu-UBUNTU-CVE-2026-43916.json")
	for raw, want := range map[*[]byte]string{
		&notice:    "c8a3c9704e2a6567172f2ae4790fc9d5a2a41b27d6abe2a84aac79df54865dc1",
		&withdrawn: "8d191d0d10b90bfabd25d1ec7ac24f69a7696fa8b5191e1a04618314d8ca6f80",
	} {
		if digest := sha256.Sum256(*raw); hex.EncodeToString(digest[:]) != want {
			t.Fatalf("vendor fixture bytes changed: %s", want)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		config := source("ubuntu", "26.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP)
		config.Url, config.Architecture = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip", arch
		archive := osvZip(t, map[string][]byte{"USN-8861-1.json": notice, "UBUNTU-CVE-2026-43916.json": withdrawn}, zip.Deflate)
		doc, err := Parse(config, bytes.NewReader(archive))
		if err != nil {
			t.Fatal(err)
		}
		if !doc.CompleteSnapshot || len(doc.RejectedRecords) != 0 {
			t.Fatalf("%s: canonical resolute coverage: complete=%t rejected=%v", arch, doc.CompleteSnapshot, doc.RejectedRecords)
		}
		claims := map[string]bool{}
		for _, claim := range doc.Advisories {
			if claim.Id != "USN-8861-1" || claim.FixedVersion != "3.5.5-1ubuntu3.7" || len(claim.Cves) != 2 || claim.Cves[0] != "CVE-2026-42772" || claim.Cves[1] != "CVE-2026-54873" {
				t.Fatalf("%s: resolute claim: %v", arch, claim)
			}
			claims[fmt.Sprintf("%s/source=%t", claim.PackageName, claim.SourcePackage)] = true
		}
		want := []string{"openssl/source=true", "openssl/source=false", "libssl3t64/source=false", "openssl-provider-legacy/source=false"}
		if len(claims) != len(want) {
			t.Fatalf("%s: resolute source/binary claims: %v", arch, claims)
		}
		for _, key := range want {
			if !claims[key] {
				t.Fatalf("%s: missing %s in %v", arch, key, claims)
			}
		}
	}
	for _, release := range []string{"24.04", "22.04"} {
		if _, err := Parse(source("ubuntu", release, advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON), bytes.NewReader(notice)); err == nil {
			t.Fatalf("resolute-only notice applied to %s", release)
		}
	}
	if !Applies(source("ubuntu", "26.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP), "ubuntu", "26.04", "aarch64") || Applies(source("ubuntu", "26.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_ZIP), "ubuntu", "24.04", "aarch64") {
		t.Fatal("26.04 product binding")
	}
}
