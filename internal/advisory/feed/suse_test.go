package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func suseValidator(t *testing.T) protovalidate.Validator {
	t.Helper()
	validator, err := protovalidate.New(protovalidate.WithMessages(&advisoryv1.Advisory{}))
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func suseSource(distro, release, architecture string) *advisoryv1.FeedSource {
	return &advisoryv1.FeedSource{Distro: distro, Release: release, Architecture: architecture, Url: "https://ftp.suse.com/pub/projects/security/csaf/suse-su-2024_2275-1.json"}
}

func TestSUSEBackportedOpenSSH(t *testing.T) {
	raw := fixture(t, "suse-suse-su-2024_2275-1.json")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "066aadd6f0472b23a2025c3f69ebfe4c0ba8dac9c550905ad029cbd929cff71c" {
		t.Fatal("SUSE vendor fixture bytes changed")
	}
	validator := suseValidator(t)
	for _, distro := range []string{"sles"} {
		for _, arch := range []string{"x86_64", "aarch64", "ppc64le", "s390x"} {
			t.Run(distro+"/"+arch, func(t *testing.T) {
				doc, err := parseSUSE(suseSource(distro, "15.6", arch), raw, validator)
				if err != nil {
					t.Fatal(err)
				}
				if doc.GetCompleteSnapshot() {
					t.Fatal("single advisory asserted complete product coverage")
				}
				var found *advisoryv1.Advisory
				seen := make(map[string]bool)
				for _, record := range doc.GetAdvisories() {
					if record.GetArchitecture() != arch || record.GetSourcePackage() || seen[record.GetPackageName()] {
						t.Fatalf("foreign architecture, inferred source package, or duplicate product: %v", record)
					}
					seen[record.GetPackageName()] = true
					if record.GetPackageName() == "openssh-server" {
						found = record
					}
				}
				if found == nil || found.GetId() != "SUSE-SU-2024:2275-1" || found.GetFixedVersion() != "0:9.6p1-150600.6.3.1" || len(found.GetCves()) != 1 || found.GetCves()[0] != "CVE-2024-6387" || found.GetSeverity() != "high" || found.GetPublishedAt().AsTime().Format("2006-01-02T15:04:05Z") != "2024-07-03T21:59:21Z" {
					t.Fatalf("lost vendor fix or publication authority: %v", found)
				}
				for _, boundary := range []struct {
					version string
					want    int
				}{
					{"0:9.6p1-150600.6.2.1", -1},
					{"0:9.6p1-150600.6.3.1", 0},
					{"0:9.6p1-150600.6.4.1", 1},
					{"1:9.6p1-150600.6.2.1", 1},
				} {
					got, err := Compare("rpm", boundary.version, found.GetFixedVersion())
					if err != nil || got != boundary.want {
						t.Errorf("native backport %s: got %d, %v; want %d", boundary.version, got, err, boundary.want)
					}
				}
			})
		}
	}
}

func TestSUSERejectsWrongScope(t *testing.T) {
	raw := fixture(t, "suse-suse-su-2024_2275-1.json")
	validator := suseValidator(t)
	for _, scope := range []struct{ distro, release, arch string }{
		{"rhel", "15.6", "x86_64"},
		{"sles", "15", "x86_64"},
		{"sles", "15.5", "x86_64"},
		{"sles", "15.6", ""},
		{"sles", "15.6", "riscv64"},
		{"sles", "15.6", "i586"},
		{"sles-sap", "15.6", "x86_64"},
		{"sled", "15.6", "x86_64"},
		{"opensuse-leap", "15.5", "x86_64"},
		// Leap 15.6 is listed in the notice but is not a registry release.
		{"opensuse-leap", "15.6", "x86_64"},
		{"opensuse-leap", "15.6", "i586"},
		{"opensuse-tumbleweed", "rolling", "x86_64"},
		{"opensuse-tumbleweed", "20240615", "x86_64"},
	} {
		t.Run(scope.distro+"/"+scope.release+"/"+scope.arch, func(t *testing.T) {
			if doc, err := parseSUSE(suseSource(scope.distro, scope.release, scope.arch), raw, validator); err == nil {
				t.Fatalf("unsupported scope accepted: %v", doc)
			}
		})
	}
	// i586 binaries appear in the product tree, but have no product relationship
	// or fixed-status statement for Leap. A listed binary alone is not evidence
	// of platform applicability.
}

func TestSUSERejectsUnsupportedApplicability(t *testing.T) {
	raw := fixture(t, "suse-suse-su-2024_2275-1.json")
	validator := suseValidator(t)
	for _, test := range []struct {
		name string
		edit func(*suseCSAF)
	}{
		{"product-range", func(n *suseCSAF) { n.Tree.Branches[0].Branches[0].Branches[0].Category = "product_version_range" }},
		{"relationship", func(n *suseCSAF) { n.Tree.Relationships[0].Category = "installed_on" }},
		{"missing-component", func(n *suseCSAF) { n.Tree.Relationships[0].Component = "absent" }},
		{"duplicate-product", func(n *suseCSAF) { n.Tree.Branches = append(n.Tree.Branches, n.Tree.Branches[0]) }},
		{"duplicate-relationship", func(n *suseCSAF) { n.Tree.Relationships = append(n.Tree.Relationships, n.Tree.Relationships[0]) }},
		{"no-vendor-fix", func(n *suseCSAF) { n.Vulnerabilities[0].Remediations[0].Category = "workaround" }},
		{"unknown-status", func(n *suseCSAF) {
			n.Vulnerabilities[0].Status["under_investigation"] = []string{n.Tree.Relationships[0].Product.ID}
		}},
		{"missing-date", func(n *suseCSAF) { n.Document.Tracking.Published = "" }},
		{"draft", func(n *suseCSAF) { n.Document.Tracking.Status = "draft" }},
		{"SAP-not-base", func(n *suseCSAF) {
			for i := range n.Tree.Branches[0].Branches {
				for j := range n.Tree.Branches[0].Branches[i].Branches {
					p := n.Tree.Branches[0].Branches[i].Branches[j].Product
					if p != nil && p.Helper.CPE == "cpe:/o:suse:sles:15:sp6" {
						p.Helper.CPE = "cpe:/o:suse:sles_sap:15:sp6"
					}
				}
			}
		}},
		{"EVR-conflict", func(n *suseCSAF) {
			for i := range n.Tree.Branches[0].Branches {
				for j := range n.Tree.Branches[0].Branches[i].Branches {
					p := n.Tree.Branches[0].Branches[i].Branches[j].Product
					if p != nil && strings.HasSuffix(p.Name, ".x86_64") {
						p.Helper.PURL = strings.ReplaceAll(p.Helper.PURL, "@9.6p1-", "@9.7p1-")
					}
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var notice suseCSAF
			if err := json.Unmarshal(raw, &notice); err != nil {
				t.Fatal(err)
			}
			test.edit(&notice)
			changed, err := json.Marshal(notice)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseSUSE(suseSource("sles", "15.6", "x86_64"), changed, validator); err == nil {
				t.Fatal("unsupported applicability accepted")
			}
		})
	}
}

func TestSUSERefusesGAMediaAsFirstFix(t *testing.T) {
	raw := fixture(t, "suse-opensuse-su-2024_11460-1.json")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "0de87daf06b54274658b2dfafb20f8e42066a6fbc67eaa1eeef0d2fde4b28166" {
		t.Fatal("Tumbleweed vendor fixture bytes changed")
	}
	// This is a genuine Tumbleweed record. The vendor's prose says the CVE
	// was fixed before 2.28, while the GA-media package is 2.29-3.9. It must
	// not assert that every earlier build (including 2.29-3.8) is vulnerable.
	_, err := parseSUSE(suseSource("opensuse-tumbleweed", "rolling", "x86_64"), raw, suseValidator(t))
	if err == nil || !strings.Contains(err.Error(), "GA-media") {
		t.Fatalf("GA-media build was treated as first fixed EVR: %v", err)
	}
}
