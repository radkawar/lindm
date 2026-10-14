// SPDX-License-Identifier: Apache-2.0

//go:build integration && livefeed

package advisory

import (
	"net/http"
	"testing"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/testdb"
)

// This explicitly tagged qualification uses actual signed vendor exports and
// isolated PostgreSQL publication, never mocked HTTP or a production database.
func TestLiveRHEL9SignedArchivePublication(t *testing.T) {
	pool, _ := testdb.Open(t)
	source := &advisoryv1.FeedSource{Id: "rhel-9-standard", Distro: "rhel", Release: "9", Architecture: "x86_64", PlatformStream: "standard", Url: "https://security.access.redhat.com/data/csaf/v2/", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES, MaxAgeSeconds: 604800}
	// The service's progress watchdog and overall ceiling bound the refresh.
	ctx := t.Context()
	started := time.Now()
	service, err := New(ctx, pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("refresh duration=%s", time.Since(started).Round(time.Second))
	feeds, err := service.Feeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(feeds.Feeds) != 1 {
		t.Fatalf("feed status=%v", feeds)
	}
	status := feeds.Feeds[0]
	if status.AdvisoryCount == 0 || status.Error != "" || len(status.Artifacts) != 2 || status.SnapshotAt == nil {
		t.Fatalf("missing signed publication evidence: %v", status)
	}
	for _, artifact := range status.Artifacts {
		if artifact.SignerFingerprint == "" || len(artifact.Sha256) != 32 {
			t.Fatalf("missing authenticated artifact: %v", artifact)
		}
		t.Logf("authenticated archive: url=%s sha256=%x signer=%s", artifact.Url, artifact.Sha256, artifact.SignerFingerprint)
	}
	for _, rejected := range status.RejectedRecords {
		t.Logf("rejected vendor record: id=%s reason=%s packages=%v unscoped=%v", rejected.Id, rejected.Reason, rejected.PackageNames, rejected.Unscoped)
	}
	if status.Fresh {
		t.Fatal("partial RHEL coverage advertised clean completeness")
	}
	t.Logf("real RHEL publication: records=%d rejected=%d digest=%s signed_snapshot=%s checked=%s partial_coverage=true", status.AdvisoryCount, len(status.RejectedRecords), status.SourceSha256, status.SnapshotAt.AsTime().Format(time.RFC3339), status.CheckedAt.AsTime().Format(time.RFC3339))
}
