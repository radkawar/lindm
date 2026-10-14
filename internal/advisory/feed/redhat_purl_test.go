// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestRedHatRPMNameUsesSinglePathDecoding(t *testing.T) {
	for _, test := range []struct {
		name, encoded, nativeName string
		valid                     bool
	}{
		{"escaped-plus", "gnutls-c%2B%2B", "gnutls-c++", true},
		{"literal-plus", "gnutls-c++", "gnutls-c++", true},
		{"lowercase-hex", "gnutls-c%2b%2b", "gnutls-c++", true},
		{"double-encoding", "gnutls-c%252B%252B", "", false},
		{"escaped-slash", "gnutls-c%2F%2B", "", false},
		{"invalid-encoding", "gnutls-c%2X%2B", "", false},
		{"truncated-encoding", "gnutls-c%2", "", false},
		{"escaped-space", "gnutls-c%20%2B", "", false},
		{"escaped-at", "gnutls-c%40%2B", "", false},
		{"opaque-display-label", "gnutls-c%2B", "gnutls-c+", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			component := redHatProduct{arch: "x86_64"}
			component.product.Name = "gnutls-c++-0:3.7.6-12.el9_0.x86_64"
			component.product.Helper.PURL = "pkg:rpm/redhat/" + test.encoded + "@3.7.6-12.el9_0?arch=x86_64"
			pkg, err := redHatPackage(component)
			if !test.valid {
				if err == nil {
					t.Fatalf("invalid native name accepted: %+v", pkg)
				}
				return
			}
			if err != nil || pkg.name != test.nativeName || pkg.version != "0:3.7.6-12.el9_0" || pkg.arch != "x86_64" {
				t.Fatalf("normative PURL path decoding changed RPM identity: %+v, %v", pkg, err)
			}
		})
	}
}

func TestRedHatRPMPURLAuthorityIgnoresDisplayLabels(t *testing.T) {
	for _, test := range []struct {
		label, purl, name, version, module, stream string
	}{
		{"pcre2.src", "pkg:rpm/redhat/pcre2@10.44-1.el10.3?arch=src", "pcre2", "0:10.44-1.el10.3", "", ""},
		{"openssl-1:3.0.7-28.el9_4.src", "pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=src&epoch=2", "openssl", "2:3.0.7-28.el9_4", "", ""},
		{"opaque component label", "pkg:rpm/redhat/nodejs@18.19.1-1.el9?arch=src&rpmmod=nodejs:18", "nodejs", "0:18.19.1-1.el9", "nodejs", "18"},
	} {
		t.Run(test.label, func(t *testing.T) {
			component := redHatProduct{arch: "src"}
			component.product.Name = test.label
			component.product.ID = "opaque product ID"
			component.product.Helper.PURL = test.purl
			pkg, err := redHatPackage(component)
			if err != nil || pkg.name != test.name || pkg.version != test.version || pkg.module != test.module || pkg.stream != test.stream || !pkg.source {
				t.Fatalf("display label changed authoritative PURL identity: %+v, %v", pkg, err)
			}
		})
	}
}

func TestRedHatRPMPURLNamespaceIsNotANamePrefix(t *testing.T) {
	for _, test := range []struct {
		name, purl        string
		offScope, invalid bool
	}{
		{"native", "pkg:rpm/redhat/kernel?arch=src", false, false},
		{"encoded-native-namespace", "pkg:rpm/red%68at/kernel?arch=src", false, false},
		{"layered-grafana", "pkg:rpm/redhat/rhacm2/acm-grafana-rhel8?arch=src", true, false},
		{"nested-kernel", "pkg:rpm/redhat/rhel9/kernel?arch=src", true, false},
		{"other-vendor", "pkg:rpm/fedora/kernel?arch=src", true, false},
		{"empty-namespace-part", "pkg:rpm/redhat//kernel?arch=src", false, true},
		{"encoded-namespace-separator", "pkg:rpm/redhat%2Frhel9/kernel?arch=src", false, true},
		{"double-encoded-namespace", "pkg:rpm/red%2568at/kernel?arch=src", false, true},
		{"invalid-namespace-escape", "pkg:rpm/red%2Xhat/kernel?arch=src", false, true},
		{"invalid-layered-name", "pkg:rpm/redhat/rhel9/kernel%2Fsrc?arch=src", false, true},
		{"invalid-layered-version", "pkg:rpm/redhat/rhel9/kernel@%2X?arch=src", false, true},
		{"module-not-name", "pkg:rpm/redhat/nginx:1.24?arch=src", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			component := redHatProduct{arch: "src"}
			component.product.Name = "kernel.src"
			component.product.Helper.PURL = test.purl
			pkg, err := redHatPackage(component)
			switch {
			case test.offScope:
				if !errors.Is(err, errRedHatNonNativeRPM) || pkg.name != "" {
					t.Fatalf("namespace was repaired into native RPM identity: %+v, %v", pkg, err)
				}
			case test.invalid:
				if err == nil || errors.Is(err, errRedHatNonNativeRPM) {
					t.Fatalf("malformed identity was accepted or silently skipped: %+v, %v", pkg, err)
				}
			default:
				if err != nil || pkg.name != "kernel" || !pkg.source {
					t.Fatalf("native PURL identity changed: %+v, %v", pkg, err)
				}
			}
		})
	}
}

func TestRedHatStatusControlsVersionSemantics(t *testing.T) {
	var notice suseCSAF
	if err := json.Unmarshal(redHatFixture(t, "rhsa-2024_6783"), &notice); err != nil {
		t.Fatal(err)
	}
	validator := redHatValidator(t)
	platform := redHatProduct{}
	platform.product.ID = "native-platform"
	platform.product.Helper.CPE = "cpe:/o:redhat:enterprise_linux:9"
	for _, arch := range []string{"src", "x86_64"} {
		for _, status := range []string{"fixed", "known_affected", "known_not_affected", "under_investigation"} {
			t.Run(arch+"/"+status, func(t *testing.T) {
				component := redHatProduct{arch: arch}
				component.product.ID, component.product.Name = "opaque-component", "pcre2.src"
				component.product.Helper.PURL = "pkg:rpm/redhat/pcre2@10.44-1.el10.3?arch=" + arch
				products := map[string]redHatProduct{platform.product.ID: platform, component.product.ID: component}
				relation := suseRelationship{Category: "default_component_of", Component: component.product.ID, Platform: platform.product.ID}
				vulnerability := redHatVulnerability{CVE: "CVE-2026-103111", Status: map[string][]string{status: {"opaque-relationship"}}}
				var record *advisoryv1.Advisory
				err := redHatVulnerabilityClaims(redHatSource("9.8", "standard"), &notice, vulnerability, products, map[string]redHatRelationship{"opaque-relationship": {suseRelationship: relation}}, validator, func(value *advisoryv1.Advisory) error {
					if record != nil {
						t.Fatal("duplicate component claim")
					}
					record = value
					return nil
				})
				if err != nil || record == nil {
					t.Fatalf("valid PURL/status not normalized: %v", err)
				}
				if record.SourcePackage != (arch == "src") || record.PackageName != "pcre2" || record.AssessmentUnknown != (status == "under_investigation") {
					t.Fatalf("PURL identity or uncertainty changed: %v", record)
				}
				switch status {
				case "fixed":
					if record.FixedVersion != "0:10.44-1.el10.3" || record.IntroducedVersion != "" || record.LastAffectedVersion != "" {
						t.Fatalf("fixed PURL EVR changed: %v", record)
					}
				case "known_not_affected":
					if !record.NotAffected || record.IntroducedVersion != "0:10.44-1.el10.3" || record.LastAffectedVersion != "0:10.44-1.el10.3" {
						t.Fatalf("version-specific negative became broad: %v", record)
					}
				default:
					if record.FixedVersion != "" || record.IntroducedVersion != "" || record.LastAffectedVersion != "" || record.NotAffected {
						t.Fatalf("unfixed status gained an invented version bound: %v", record)
					}
				}
			})
		}
	}
}

func TestRedHatGenuineEscapedRPMName(t *testing.T) {
	raw := redHatFixture(t, "rhsa-2022_6854")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "e8195ce6334f405c4401e413feb7843be1cb147e99f689473a53788cd4e07fea" {
		t.Fatal("retained RPM advisory differs from signed archive member")
	}
	var claims advisoryv1.FeedDocument
	_, err := stageRedHatStream(t.Context(), redHatSource("9.4", "standard"), redHatValidator(t), bytes.NewReader(raw), func(record *advisoryv1.Advisory) error {
		claims.Advisories = append(claims.Advisories, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record := redHatRecord(t, &claims, "gnutls-c++", "CVE-2022-2509", "", false)
	if record.FixedVersion != "0:3.7.6-12.el9_0" || record.Architecture != "x86_64" || record.PlatformStream != "standard" || record.AssessmentUnknown {
		t.Fatalf("genuine encoded package name lost native applicability: %v", record)
	}
}
