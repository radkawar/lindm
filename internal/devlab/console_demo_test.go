package devlab

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/feed"
)

// Only a complete source lets the server report AFFECTED: single notices stay
// partial, so their devices (the Ubuntu route device included) read UNKNOWN.
// The Fedora controlled repository adds only the <updates> root and the
// labelled synthetic updates after the unchanged recorded vendor node; every
// synthetic package parses to exactly its fixed build.
func TestConsoleDemoAdvisoryCoverage(t *testing.T) {
	repository := filepath.Join("..", "..")
	files, sources, err := consoleDemoAdvisories(repository)
	if err != nil {
		t.Fatal(err)
	}
	complete := map[string]bool{}
	for _, configured := range sources {
		source := proto.CloneOf(configured)
		source.Url = "https://localhost" + configured.GetUrl()
		doc, err := feed.Parse(source, bytes.NewReader(files[configured.GetUrl()]))
		if err != nil {
			t.Fatalf("%s: %v", source.GetId(), err)
		}
		complete[source.GetId()] = doc.GetCompleteSnapshot()
		if source.GetId() != "demo-fedora-44" {
			continue
		}
		recorded, err := os.ReadFile(filepath.Join(repository, "internal", "advisory", "feed", "testdata", "fedora44-sudo.xml"))
		if err != nil {
			t.Fatal(err)
		}
		synthetic, err := consoleDemoUpdateinfo()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(files[configured.GetUrl()], slices.Concat([]byte("<updates>"), recorded, synthetic, []byte("</updates>"))) {
			t.Fatal("controlled repository changed the recorded vendor node")
		}
		fixed := map[string]string{}
		for _, claim := range doc.GetAdvisories() {
			if strings.HasPrefix(claim.GetId(), "FEDORA-2026-SYNTHETIC-") {
				if len(claim.GetCves()) != 0 || claim.GetArchitecture() != "x86_64" {
					t.Fatalf("synthetic claim cites a CVE or wrong architecture: %v", claim)
				}
				fixed[claim.GetPackageName()] = claim.GetFixedVersion()
			}
		}
		affected := ConsoleDemoAffectedPackages()
		if len(affected) != consoleDemoSyntheticUpdates*consoleDemoSubpackages || len(fixed) != len(affected) {
			t.Fatalf("synthetic claims = %d unique packages, want %d", len(fixed), len(affected))
		}
		for _, pkg := range affected {
			if fixed[pkg.Name] != pkg.Fixed || pkg.Installed >= pkg.Fixed {
				t.Fatalf("synthetic package %s: fixed %q, installed %q, want fixed %q", pkg.Name, fixed[pkg.Name], pkg.Installed, pkg.Fixed)
			}
		}
		if !slices.ContainsFunc(doc.GetAdvisories(), func(claim *advisoryv1.Advisory) bool {
			return claim.GetId() == "FEDORA-2026-7d4732cbab" && claim.GetPackageName() == "sudo" && claim.GetArchitecture() == "x86_64" && claim.GetFixedVersion() == "0:1.9.17-10.p2.fc44"
		}) {
			t.Fatalf("recorded sudo fix missing: %v", doc.GetAdvisories())
		}
	}
	want := map[string]bool{"demo-ubuntu-24.04": false, "demo-debian-12": false, "demo-fedora-44": true, "demo-rhel-9": false}
	if !maps.Equal(complete, want) {
		t.Fatalf("demo source coverage = %v, want %v", complete, want)
	}
}

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
