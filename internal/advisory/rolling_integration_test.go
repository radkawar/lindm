// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/feed"
	"lindm/internal/testdb"
)

// Projected vendor definitions are real. These installed package versions are
// controlled database inputs, not native qualification evidence.
func TestTumbleweedOVALProductAndInstallonlyMatching(t *testing.T) {
	pool, _ := testdb.Open(t)
	source := &advisoryv1.FeedSource{Id: "tumbleweed", Distro: "opensuse-tumbleweed", Release: "rolling", Architecture: "x86_64", Url: "https://ftp.suse.com/pub/projects/security/oval/opensuse.tumbleweed.xml.gz", Format: advisoryv1.FeedFormat_FEED_FORMAT_SUSE_OVAL, MaxAgeSeconds: 604800}
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("feed/testdata/suse-tumbleweed-subset.xml")
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	if _, err := z.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	doc, err := feed.Parse(source, &compressed)
	if err != nil {
		t.Fatal(err)
	}
	// Expired vendor generation must not become fresh when re-fetched today.
	doc.SnapshotAt = timestamppb.New(time.Now().UTC().Add(-8 * 24 * time.Hour))
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	pkg := func(name, version string) *inventoryv1.Package {
		return &inventoryv1.Package{Name: name, Version: version, Architecture: "x86_64", Manager: "rpm"}
	}
	for _, test := range []struct {
		name, distro, release string
		packages              []*inventoryv1.Package
		findings              int
	}{
		{"affected", "opensuse-tumbleweed", "20261007", []*inventoryv1.Package{pkg("openSUSE-release", "20261007-1.1"), pkg("kernel-source", "7.0.10-1.1")}, 1},
		{"fixed-instance", "opensuse-tumbleweed", "20261007", []*inventoryv1.Package{pkg("openSUSE-release", "20261007-1.1"), pkg("kernel-source", "7.0.10-1.1"), pkg("kernel-source", "7.0.11-1.1")}, 0},
		{"missing-product", "opensuse-tumbleweed", "20261007", []*inventoryv1.Package{pkg("kernel-source", "7.0.10-1.1")}, 0},
		{"old-product", "opensuse-tumbleweed", "20261007", []*inventoryv1.Package{pkg("openSUSE-release", "20201231-1.1"), pkg("kernel-source", "7.0.10-1.1")}, 0},
		{"different-product", "opensuse-leap", "16.0", []*inventoryv1.Package{pkg("openSUSE-release", "20261007-1.1"), pkg("kernel-source", "7.0.10-1.1")}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := seedInventory(t, pool, test.distro, test.release, test.packages...)
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Findings) != test.findings || out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
				t.Fatalf("predicate or stale coverage lost: %v", out)
			}
			if test.distro == "opensuse-tumbleweed" && out.GetFreshness().GetReason() != "feed_stale" {
				t.Fatalf("recent publication renewed old generation: %v", out)
			}
		})
	}
}
