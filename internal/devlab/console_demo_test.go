package devlab

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/feed"
)

// Only a complete source lets the server report AFFECTED: single notices stay
// partial, so their devices (the Ubuntu route device included) read UNKNOWN.
// The Fedora controlled repository adds nothing but the <updates> root around
// the recorded vendor node.
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
		if !bytes.Equal(files[configured.GetUrl()], slices.Concat([]byte("<updates>"), recorded, []byte("</updates>"))) {
			t.Fatal("controlled repository changed the recorded vendor node")
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
