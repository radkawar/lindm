// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"path/filepath"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	advisoryfeed "lindm/internal/advisory/feed"
)

// Scale fixtures promise unique names and the long names and versions that
// console layouts must wrap.
func TestSyntheticPackagesScale(t *testing.T) {
	for _, manager := range []string{"dpkg", "rpm"} {
		seen := map[string]bool{}
		longName, longVersion := false, false
		for i := range 3000 {
			name := SyntheticPackageName(manager, i)
			if seen[name] {
				t.Fatalf("%s package %d repeats %q", manager, i, name)
			}
			seen[name] = true
			longName = longName || len(name) > 100
			longVersion = longVersion || len(SyntheticPackageVersion(manager, i)) > 80
		}
		if !longName || !longVersion {
			t.Fatalf("%s: long name %v, long version %v", manager, longName, longVersion)
		}
	}
}

func TestConsoleDemoRepositoryHasAuthoredCriticalFinding(t *testing.T) {
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name           string
		supplementOnly bool
	}{{"fixtures", false}, {"real-vendor-supplement", true}} {
		t.Run(mode.name, func(t *testing.T) {
			files, config, err := consoleDemoFixtureFeeds(repository, "https://fixtures.example.invalid", mode.supplementOnly)
			if err != nil {
				t.Fatal(err)
			}
			var source *advisoryv1.FeedSource
			for _, candidate := range config.GetFeeds() {
				if candidate.GetId() == "demo-authored-critical-fedora-43" {
					source = candidate
				}
			}
			if source == nil {
				t.Fatal("authored Critical supplement missing")
			}
			if mode.supplementOnly && (len(config.GetFeeds()) != 1 || len(files) != 1) {
				t.Fatal("real-vendor supplement must not substitute fixture versions of vendor feeds")
			}
			document, err := advisoryfeed.Parse(source, bytes.NewReader(files["/feeds/fedora-43/authored-critical-supplement.xml"]))
			if err != nil {
				t.Fatal(err)
			}
			if !document.GetCompleteSnapshot() || len(document.GetAdvisories()) != 1 {
				t.Fatal("authored supplement must be a complete one-record controlled repository")
			}
			finding := document.GetAdvisories()[0]
			if finding.GetId() != "FEDORA-2099-123456789abc" || finding.GetSeverity() != "critical" ||
				finding.GetPackageName() != "synthetic-critical-library" || finding.GetArchitecture() != "x86_64" ||
				finding.GetFixedVersion() != "0:2.0-1.fc43" || len(finding.GetCves()) != 1 || finding.GetCves()[0] != "CVE-2099-99021" {
				t.Fatalf("authored Critical assessment changed: %v", finding)
			}
			if !mode.supplementOnly {
				var original *advisoryv1.FeedSource
				for _, candidate := range config.GetFeeds() {
					if candidate.GetId() == "demo-fedora-44" {
						original = candidate
					}
				}
				if original == nil {
					t.Fatal("original Fedora fixture source missing")
				}
				document, err := advisoryfeed.Parse(original, bytes.NewReader(files["/feeds/fedora-44/synthetic-updateinfo.xml"]))
				if err != nil {
					t.Fatal(err)
				}
				high, critical := false, false
				for _, finding := range document.GetAdvisories() {
					high = high || (finding.GetId() == "FEDORA-2099-abcdef1234" && finding.GetSeverity() == "high")
					critical = critical || finding.GetId() == "FEDORA-2099-123456789abc"
				}
				if !high || critical {
					t.Fatal("Critical supplement changed the original High fixture")
				}
			}
		})
	}
}
