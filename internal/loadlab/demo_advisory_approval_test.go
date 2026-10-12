package loadlab

import (
	"bytes"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory"
	"lindm/internal/advisory/feed"
)

// The review proposal needs a finding the server reports AFFECTED: an enrolled
// host on the demo's one complete source (Fedora 44) whose installed package is
// older than the recorded vendor fix. Partial Ubuntu coverage cannot supply it.
func TestDemoAdvisoryProposalDeviceIsAffected(t *testing.T) {
	devices, err := demoDevices()
	if err != nil {
		t.Fatal(err)
	}
	var proposal *demoDevice
	for _, d := range devices {
		if d.proposal {
			if proposal != nil {
				t.Fatal("more than one advisory proposal device")
			}
			proposal = d
		}
	}
	if proposal == nil || proposal.key != "fedora-44" || proposal.state != "enrolled" {
		t.Fatalf("proposal device is not an enrolled Fedora 44 host: %+v", proposal)
	}
	raw, err := os.ReadFile("../advisory/feed/testdata/fedora44-sudo.xml")
	if err != nil {
		t.Fatal(err)
	}
	source := &advisoryv1.FeedSource{Id: "demo-fedora-44", Distro: proposal.release.ID, Release: proposal.versionID, Architecture: "x86_64", Format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, Url: "https://localhost/feeds/fedora-44/updateinfo.xml", MaxAgeSeconds: 604800}
	doc, err := feed.Parse(source, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var installed inventoryv1.PackageBatch
	if err := proto.Unmarshal(proposal.packages.batches[0], &installed); err != nil {
		t.Fatal(err)
	}
	var affected []string
	for _, p := range installed.GetPackages() {
		for _, claim := range doc.GetAdvisories() {
			if claim.GetPackageName() != p.GetName() || claim.GetArchitecture() != p.GetArchitecture() {
				continue
			}
			match, err := advisory.MatchesVersion(p.GetManager(), p.GetVersion(), claim)
			if err != nil {
				t.Fatal(err)
			}
			if match {
				affected = append(affected, claim.GetId()+" "+p.GetName()+" "+p.GetVersion()+" < "+claim.GetFixedVersion())
			}
		}
	}
	if len(affected) != 1 || affected[0] != "FEDORA-2026-7d4732cbab sudo 0:1.9.17-7.p2.fc44 < 0:1.9.17-10.p2.fc44" {
		t.Fatalf("recorded vendor fix does not affect the proposal device: %v", affected)
	}
}
