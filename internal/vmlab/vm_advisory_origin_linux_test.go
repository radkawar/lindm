//go:build linux

package vmlab

import (
	"slices"
	"testing"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/platform"
)

// A derivative publishes no feed: its advisories and air-gap lanes use the
// Ubuntu base's export and identity, bounded by the derivative's own
// architectures (Mint and Pop!_OS failed "no maintained vendor source").
func TestVMAdvisorySourceOfDerivativeIsItsBaseFeed(t *testing.T) {
	ubuntu, ok := platform.Lookup("ubuntu-24.04")
	if !ok {
		t.Fatal("missing Ubuntu 24.04")
	}
	base, err := vmAdvisorySource(ubuntu, "24.04", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"linuxmint-22.3", "pop-24.04"} {
		release, ok := platform.Lookup(key)
		if !ok {
			t.Fatalf("missing %s", key)
		}
		source, err := vmAdvisorySource(release, release.Version.Value, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if source.GetDistro() != base.GetDistro() || source.GetRelease() != base.GetRelease() || source.GetUrl() != base.GetUrl() || source.GetFormat() != base.GetFormat() ||
			source.GetArchitecture() != "amd64" || source.GetId() != "matrix-"+key+"-amd64" {
			t.Fatalf("%s source = %v, base %v", key, source, base)
		}
		if _, err := vmAdvisorySource(release, release.Version.Value, "aarch64"); err == nil {
			t.Fatalf("%s inherited its base's aarch64 coverage", key)
		}
		bundle, err := AirgapAdvisories(release, release.Version.Value, "x86_64")
		if err != nil || len(bundle.GetFeeds()) != 1 || bundle.GetFeeds()[0].GetDistro() != base.GetDistro() || bundle.GetFeeds()[0].GetUrl() != base.GetUrl() {
			t.Fatalf("%s air-gap feeds = %v, %v", key, bundle, err)
		}
		if got := advisoryOriginReason(release); got != "vendor_feed_unavailable_"+release.ID {
			t.Fatalf("%s origin reason %q", key, got)
		}
	}
	if advisoryOriginReason(ubuntu) != "" {
		t.Fatal("a base release was given a derivative origin reason")
	}
}

// Synthetic evidence exercises the derivative acceptance boundary only.
func derivativeAdvisoryEvidenceForTest() *VMAdvisoryEvidence {
	e := advisoryEvidenceForTest()
	e.PartialCoverage, e.VerifiedOrigin = "vendor feed unavailable for Linux Mint packages", "vendor_feed_unavailable_linuxmint"
	e.Packages = []*inventoryv1.Package{
		{Name: "native", Version: "1:2-3", Architecture: "x86_64", Manager: "dpkg"},
		{Name: "mint-common", Version: "2.2", Architecture: "all", Manager: "dpkg"},
	}
	e.Freshness = &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL, Reason: "vendor_feed_unavailable_linuxmint", UncoveredPackages: 1}
	e.Origin = &VMAdvisoryOriginEvidence{
		Reason: "vendor_feed_unavailable_linuxmint", BaseOrigin: "Ubuntu", BaseSuites: []string{"noble", "noble-security", "noble-updates"}, VendorOrigins: []string{"linuxmint"},
		Uncovered:        []*adminv1.UncoveredPackage{{Name: "mint-common", Version: "2.2", Architecture: "all", Reason: "vendor_feed_unavailable"}},
		UncoveredReasons: map[string]int{"vendor_feed_unavailable": 1},
		VendorPackages:   map[string][]string{"mint-common": {"linuxmint/zena"}},
		FindingPackages:  map[string][]string{"native": {"Ubuntu/noble-updates", "Ubuntu/noble"}},
	}
	return e
}

// A derivative passes only as a verified-origin PARTIAL evaluation: base
// findings for base-archive packages and its vendor packages UNKNOWN. The
// former oracle accepted only 'evaluated' or the feed_partial_coverage
// UNKNOWN, so a correct derivative evaluation could never qualify.
func TestVMAdvisoryDerivativeRequiresVerifiedOriginPartial(t *testing.T) {
	e := derivativeAdvisoryEvidenceForTest()
	if err := qualifyVMAdvisoryMatches(e); err != nil || e.Scope != "partial-feed matching" || e.Outcome != "qualified_verified_origin_partial_matching" {
		t.Fatalf("verified-origin partial evidence: scope=%s outcome=%s error=%v", e.Scope, e.Outcome, err)
	}
	for name, mutate := range map[string]func(*VMAdvisoryEvidence){
		"no origin oracle": func(e *VMAdvisoryEvidence) { e.Origin = nil },
		"evaluated as complete": func(e *VMAdvisoryEvidence) {
			e.Freshness.State, e.Freshness.Reason = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED, ""
		},
		"another derivative's reason": func(e *VMAdvisoryEvidence) { e.Freshness.Reason = "vendor_feed_unavailable_pop" },
		"uncovered count mismatch":    func(e *VMAdvisoryEvidence) { e.Freshness.UncoveredPackages = 2 },
		"uncovered not installed":     func(e *VMAdvisoryEvidence) { e.Origin.Uncovered[0].Version = "2.3" },
		"no vendor package uncovered": func(e *VMAdvisoryEvidence) {
			e.Origin.Uncovered[0].Reason, e.Origin.UncoveredReasons = "origin_unlisted", map[string]int{"origin_unlisted": 1}
		},
		"vendor package from the base": func(e *VMAdvisoryEvidence) { e.Origin.VendorPackages["mint-common"] = []string{"Ubuntu/noble"} },
		"finding for uncovered package": func(e *VMAdvisoryEvidence) {
			e.Findings[0].PackageName, e.Findings[0].InstalledVersion, e.Findings[0].Architecture = "mint-common", "2.2", "all"
		},
		"finding from vendor archive": func(e *VMAdvisoryEvidence) {
			e.Origin.FindingPackages["native"] = append(e.Origin.FindingPackages["native"], "linuxmint/zena")
		},
		"finding from unassessed pocket": func(e *VMAdvisoryEvidence) {
			e.Origin.FindingPackages["native"] = []string{"Ubuntu/noble-backports"}
		},
		"finding without APT listing": func(e *VMAdvisoryEvidence) { e.Origin.FindingPackages["native"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			e := derivativeAdvisoryEvidenceForTest()
			mutate(e)
			if err := qualifyVMAdvisoryMatches(e); err == nil {
				t.Fatal("unqualified derivative evaluation accepted")
			}
		})
	}
}

// apt-cache policy text as noble/zena print it: the global index list with
// release fields, then each package's version table. Index priorities differ
// under package pins, so indexes join on the text after the priority.
func TestParseAPTInstalledOriginsJoinsVersionTableToReleaseFields(t *testing.T) {
	output := `Package files:
 100 /var/lib/dpkg/status
     release a=now
 700 http://packages.linuxmint.com zena/main amd64 Packages
     release v=22.3,o=linuxmint,a=zena,n=zena,l=linuxmint,c=main,b=amd64
     origin packages.linuxmint.com
 500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64
     origin archive.ubuntu.com
 500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=main,b=amd64
     origin archive.ubuntu.com
Pinned packages:
@@package openssl
openssl:
  Installed: 3.0.13-0ubuntu3.5
  Candidate: 3.0.13-0ubuntu3.6
  Version table:
     3.0.13-0ubuntu3.6 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
 *** 3.0.13-0ubuntu3.5 100
        100 /var/lib/dpkg/status
     3.0.13-0ubuntu3 500
        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
@@package mint-common
mint-common:
  Installed: 2.2.0
  Candidate: 2.2.0
  Version table:
 *** 2.2.0 700
        700 http://packages.linuxmint.com zena/main amd64 Packages
        100 /var/lib/dpkg/status
@@package bash
bash:
  Installed: 5.2.21-2ubuntu4
  Candidate: 5.2.21-2ubuntu4
  Version table:
 *** 5.2.21-2ubuntu4 990
        990 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
        100 /var/lib/dpkg/status
`
	origins, err := parseAPTInstalledOrigins(output)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{"openssl": {}, "mint-common": {"linuxmint/zena"}, "bash": {"Ubuntu/noble"}} {
		if got, ok := origins[name]; !ok || !slices.Equal(got, want) {
			t.Fatalf("%s origins = %v, want %v", name, got, want)
		}
	}
	if _, err := parseAPTInstalledOrigins("@@package bash\n"); err == nil {
		t.Fatal("accepted output without APT index list")
	}
}
