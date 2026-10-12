//go:build integration

package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/testdb"
)

// These database fixtures exercise classification and authority transitions, not
// a claim that their controlled older/fixed versions were installed on a VM.
// Recorded native inventories are exercised separately below.
func TestVendorBackportsPersistWithoutUpstreamFalsePositives(t *testing.T) {
	cases := []struct{ distro, release, file, name, manager, old, fixed, source string }{
		{"ubuntu", "24.04", "ubuntu-USN-6859-1.json", "openssh-server", "dpkg", "1:9.6p1-3ubuntu13.2", "1:9.6p1-3ubuntu13.3", "openssh"},
		{"debian", "12", "debian-DSA-5724-1.json", "openssh-server", "dpkg", "1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", "openssh"},
		{"rocky", "9", "rocky-RLSA-2024-6783.json", "openssl", "rpm", "1:3.0.7-27.el9_4", "1:3.0.7-28.el9_4", ""},
		{"almalinux", "9", "alma-ALSA-2024-6783.json", "openssl-libs", "rpm", "1:3.0.7-27.el9_4", "1:3.0.7-28.el9_4", ""},
		{"fedora", "44", "fedora44-sudo.xml", "sudo", "rpm", "0:1.9.17-9.p2.fc44", "0:1.9.17-10.p2.fc44", ""},
	}
	for _, tc := range cases {
		t.Run(tc.distro, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			s, source, doc := vendorService(t, pool, tc.distro, tc.release, tc.file)
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			arch := "x86_64"
			if tc.manager == "dpkg" {
				arch = "amd64"
			}
			old := &inventoryv1.Package{Name: tc.name, Version: tc.old, Manager: tc.manager, Architecture: arch, SourceName: tc.source}
			if tc.source != "" {
				old.SourceVersion = tc.old
			}
			oldID := seedInventory(t, pool, tc.distro, tc.release, old)
			fixed := proto.CloneOf(old)
			fixed.Version = tc.fixed
			if tc.source != "" {
				fixed.SourceVersion = tc.fixed
			}
			fixedID := seedInventory(t, pool, tc.distro, tc.release, fixed)
			response, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: oldID.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if len(response.GetFindings()) != 1 || response.Findings[0].GetFixedVersion() != tc.fixed {
				t.Fatalf("old package: %v", response)
			}
			response, err = listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: fixedID.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if len(response.GetFindings()) != 0 {
				t.Fatalf("backported fix incorrectly vulnerable: %v", response)
			}
			if source.Format == advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON && response.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
				t.Fatal("single advisory incorrectly establishes complete coverage")
			}
			if source.Format == advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO && response.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR {
				t.Fatal("fresh complete controlled repository failed to recognize fixed native package")
			}
		})
	}
}

func TestDeviceFindingsSortFiltersTotals(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"}, &inventoryv1.Package{Name: "sudo-devel", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	all, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), Sort: adminv1.DeviceFindingSort_DEVICE_FINDING_SORT_PACKAGE}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Findings) != 2 || all.Findings[0].PackageName != "sudo" || all.Findings[1].PackageName != "sudo-devel" {
		t.Fatalf("package order: %v", all.Findings)
	}
	if all.GetTotals().GetOpen() != 2 || all.GetTotals().GetAccepted() != 0 {
		t.Fatalf("totals: %v", all.GetTotals())
	}
	filtered, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PackagePrefix: "SUDO-D"}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Findings) != 1 || filtered.Findings[0].PackageName != "sudo-devel" || filtered.GetTotals().GetOpen() != 1 {
		t.Fatalf("package prefix filter: %v", filtered)
	}
	advisory := all.Findings[0].AdvisoryId
	byAdvisory, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), AdvisoryPrefix: strings.ToLower(advisory[:4])}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(byAdvisory.Findings) != 2 {
		t.Fatalf("advisory prefix filter: %v", byAdvisory)
	}
	none, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), AdvisoryPrefix: "NO-SUCH-"}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(none.Findings) != 0 || none.GetTotals().GetOpen() != 0 {
		t.Fatalf("unmatched advisory prefix: %v", none)
	}
	first, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1, Sort: adminv1.DeviceFindingSort_DEVICE_FINDING_SORT_PACKAGE}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1, Sort: adminv1.DeviceFindingSort_DEVICE_FINDING_SORT_PACKAGE, PageToken: first.NextPageToken}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Findings) != 1 || second.Findings[0].PackageName != "sudo-devel" || second.NextPageToken != "" {
		t.Fatalf("second page: %v", second)
	}
	// A token is bound to its sort and filters.
	if _, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1, PageToken: first.NextPageToken, PackagePrefix: "sudo"}, true, []byte("[]")); !errors.Is(err, ErrConflict) {
		t.Fatalf("token reused with different filters: %v", err)
	}
}

func TestAdvisoryFreshnessExceptionsScopeAndRevision(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"}, &inventoryv1.Package{Name: "sudo-devel", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	request := &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1}
	first, err := listEvaluated(t, s, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 1 || first.NextPageToken == "" {
		t.Fatalf("pagination: %v", first)
	}
	if first.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
		t.Fatalf("finding not affected: %v", first)
	}
	second, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1, PageToken: first.NextPageToken}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Findings) != 1 || second.Findings[0].Id == first.Findings[0].Id {
		t.Fatal("page repeated or lost a finding")
	}
	if _, err := listEvaluated(t, s, request, false, []byte("[]")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope findings exposed: %v", err)
	}
	summary, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, false, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Advisories) != 0 || summary.EvaluatedDevices != 0 || summary.UnknownDevices != 0 {
		t.Fatalf("scope leaked counts: %v", summary)
	}
	actor := uuid.New()
	if _, err := pool.Exec(t.Context(), "INSERT INTO principals(id,issuer,subject) VALUES($1,'https://advisory.test',$2)", actor, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	accept := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: id.String(), FindingId: first.Findings[0].Id, Reason: "Temporary documented risk acceptance", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
	accepted := acceptFinding(t, s, actor, accept)
	if replay := acceptFinding(t, s, actor, accept); !proto.Equal(accepted, replay) {
		t.Fatal("exact retry changed exception response")
	}
	changed := proto.CloneOf(accept)
	changed.Reason = "Different risk"
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(t.Context(), tx, actor, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request accepted: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	out, err := listEvaluated(t, s, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED {
		t.Fatal("active exception not visible")
	}
	if _, err := pool.Exec(t.Context(), "UPDATE advisory_exceptions SET accepted_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE finding_id=$1", uuid.MustParse(accept.FindingId)); err != nil {
		t.Fatal(err)
	}
	out, err = listEvaluated(t, s, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
		t.Fatal("expired exception did not resurface")
	}
	if _, err := pool.Exec(t.Context(), "UPDATE advisory_feeds SET expires_at=now()-interval '1 second' WHERE id=$1", source.Id); err != nil {
		t.Fatal(err)
	}
	summary, err = s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if summary.UnknownDevices != 1 || summary.EvaluatedDevices != 0 || len(summary.Advisories) != 1 || summary.Advisories[0].UnknownDevices != 1 {
		t.Fatalf("fleet freshness waited for background reevaluation: %v", summary)
	}
	// Inactive devices are outside the fleet population: their old findings
	// count neither as affected nor as found on a device not fully checked.
	mustExec(t, t.Context(), pool, "UPDATE devices SET state='recovery_hold' WHERE id=$1", id)
	summary, err = s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil || summary.UnknownDevices != 0 || len(summary.Advisories) != 0 {
		t.Fatalf("inactive device counted in advisory summary: %v %v", summary, err)
	}
	mustExec(t, t.Context(), pool, "UPDATE devices SET state='active' WHERE id=$1", id)
	out, err = listEvaluated(t, s, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatal("stale feed shown healthy/affected with current certainty")
	}
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// Identical content keeps the feed generation, so the persisted evaluation
	// and its cursor stay valid instead of being rebuilt per read.
	if second, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1, PageToken: first.NextPageToken}, true, []byte("[]")); err != nil || len(second.Findings) != 1 || second.Findings[0].Id == first.Findings[0].Id {
		t.Fatalf("unchanged evaluation cursor: %v %v", second, err)
	}
	// A new host observation replaces the evaluation once the background job
	// runs; the old cursor must not silently rebind to it.
	mustExec(t, t.Context(), pool, "UPDATE host_observations SET received_at=clock_timestamp() WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", id)
	mustExec(t, t.Context(), pool, "UPDATE devices d SET host_received_at=h.received_at FROM host_observations h WHERE h.generation_id=d.current_generation_id AND d.id=$1", id)
	if _, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageToken: first.NextPageToken}, true, []byte("[]")); !errors.Is(err, ErrConflict) {
		t.Fatalf("obsolete evaluation cursor silently rebound: %v", err)
	}
	// Published snapshots are immutable; age arrives by time passing past the
	// expiry the evaluation bound. Reads recheck it without a worker run.
	mustExec(t, t.Context(), pool, "UPDATE advisory_evaluations SET expires_at=now()-interval '1 second' WHERE device_id=$1", id)
	out, err = s.ListDevice(t.Context(), request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "inventory_stale" {
		t.Fatalf("stale inventory shown healthy: %v", out.Freshness)
	}
}

func TestAdvisoryImportPinAndFailedPublicationPreserveFeed(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	before, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Import(t.Context(), source.Id, bytes.NewReader([]byte(`{}`))); err == nil {
		t.Fatal("corrupt feed accepted")
	}
	after, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision != after.Revision || !bytes.Equal(before.SourceSha256, after.SourceSha256) {
		t.Fatal("failed import replaced published feed")
	}
}

func TestAdvisoryOfflineImportCannotEstablishCurrentCoverage(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-10.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	request := &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}
	before, err := listEvaluated(t, s, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR {
		t.Fatalf("controlled complete feed did not establish native fix: %v", before)
	}
	raw, err := os.ReadFile("feed/testdata/fedora44-sudo.xml")
	if err != nil {
		t.Fatal(err)
	}
	// The same explicitly synthetic complete wrapper as vendorService preserves
	// the byte pin. An offline replay still lacks trustworthy acquisition time.
	raw = append(append([]byte("<updates>"), raw...), []byte("</updates>")...)
	if err := s.Import(t.Context(), source.Id, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	summary, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if summary.UnknownDevices != 1 || summary.EvaluatedDevices != 0 {
		t.Fatalf("offline replay retained apparently current fleet coverage: %v", summary)
	}
	after, err := listEvaluated(t, s, request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if after.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || len(after.Findings) != 0 {
		t.Fatalf("offline byte integrity was mistaken for acquisition freshness: %v", after)
	}
}

func TestFeedConfigurationChangeReparsesUnchangedSourceBytes(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(source)
	changed.Release = "22.04"
	reconfigured, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{changed}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("feed/testdata/ubuntu-USN-6859-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := reconfigured.Import(t.Context(), changed.Id, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "ubuntu", "22.04", &inventoryv1.Package{
		Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.9", Architecture: "amd64", Manager: "dpkg",
		SourceName: "openssh", SourceVersion: "1:8.9p1-3ubuntu0.9",
	})
	out, err := listEvaluated(t, reconfigured, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || out.Findings[0].FixedVersion != "1:8.9p1-3ubuntu0.10" {
		t.Fatalf("old release interpretation reused after configuration change: %v", out)
	}
}

func TestUncoveredMultilibArchitectureIsUnknown(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "i686", Manager: "rpm"})
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 || out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "package_architecture_uncovered" {
		t.Fatalf("x86_64 repository cleared an uncovered multilib package: %v", out)
	}
}

// The server's evaluator serves feeds configured and published by another
// process (the refresh CLI or a fixture) in the shared database. A device
// evaluated before any applicable feed existed is rechecked once one is
// configured, without the server's own configuration listing that feed.
func TestEvaluatorRechecksFeedlessDevicesAfterExternalConfiguration(t *testing.T) {
	pool, _ := testdb.Open(t)
	server, err := New(t.Context(), pool, nil, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	before, err := listEvaluated(t, server, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || before.Freshness.Reason != "feed_unavailable" {
		t.Fatalf("device without a feed: %v", before.Freshness)
	}
	if attempted, err := server.EvaluatePending(t.Context(), evaluationBatch); err != nil || attempted != 0 {
		t.Fatalf("unchanged feed-less device evaluated again: %d %v", attempted, err)
	}
	external, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := external.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	after, err := listEvaluated(t, server, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if after.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED || len(after.Findings) != 1 {
		t.Fatalf("externally configured feed not evaluated: %v", after)
	}
}

// An evaluation concurrent with an uncommitted feed configuration waits for it
// instead of reading the feed set first: evaluated before the configuration's
// commit with a later time, the device would stay feed_unavailable, because
// ClaimAdvisoryEvaluations rechecks only feeds configured after evaluated_at
// (Debian 13 x86_64 matrix advisories, debianel2-debadv-x86-20261012T140542Z).
func TestEvaluationWaitsForConcurrentFeedConfiguration(t *testing.T) {
	pool, _ := testdb.Open(t)
	server, err := New(t.Context(), pool, nil, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	q := advisorydb.New(tx)
	if err := q.LockAdvisoryFeedConfiguration(t.Context()); err != nil {
		t.Fatal(err)
	}
	source := &advisoryv1.FeedSource{Id: "fedora-44", Distro: "fedora", Release: "44", Architecture: "x86_64", Url: "https://vendor.example/fedora44-sudo.xml", Format: advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, MaxAgeSeconds: 86400}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.ConfigureAdvisoryFeed(t.Context(), advisorydb.ConfigureAdvisoryFeedParams{ID: source.GetId(), Distro: source.GetDistro(), Release: source.GetRelease(), SourceUrl: source.GetUrl(), ConfigBytes: encoded, Revision: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		evaluation advisorydb.AdvisoryEvaluation
		err        error
	}
	done := make(chan outcome, 1)
	go func() {
		evaluation, err := server.Evaluate(t.Context(), id)
		done <- outcome{evaluation, err}
	}()
	select {
	case got := <-done:
		t.Fatalf("evaluation read the feed set during an uncommitted configuration: %+v", got)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.evaluation.FeedID != source.GetId() {
		t.Fatalf("evaluation after the configuration committed = %+v, %v; want feed %s", got.evaluation, got.err, source.GetId())
	}
}

// Native rpm reports imported signing keys as gpg-pubkey rows without an ARCH
// tag. They are keyring entries, not packages, and must not make every RPM
// device's architecture coverage UNKNOWN. Any other architecture-less row still
// does.
func TestRPMSigningKeyRowsDoNotMakeCoverageUnknown(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	sudo := &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"}
	key := &inventoryv1.Package{Name: "gpg-pubkey", Version: "0:7db87c81-4ab02935", Manager: "rpm"}
	keyed := seedInventory(t, pool, "fedora", "44", sudo, key)
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: keyed.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED || len(out.Findings) != 1 || out.Findings[0].PackageName != "sudo" {
		t.Fatalf("signing key row changed device exposure: %v", out)
	}
	unarchitected := seedInventory(t, pool, "fedora", "44", sudo, &inventoryv1.Package{Name: "gpg-pubkey-helper", Version: "0:1.0-1.fc44", Manager: "rpm"})
	out, err = listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: unarchitected.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "package_architecture_uncovered" {
		t.Fatalf("architecture-less package other than a signing key was covered: %v", out.Freshness)
	}
}

func TestAdvisoryRejectedRecordsStayScopedAndDurable(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	before, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	// Controlled parser output deliberately shares an ID with a valid notice
	// for another package. Rejection labels must bind package identity too.
	rejected := &advisoryv1.RejectedRecord{Id: doc.Advisories[0].Id, Reason: "advisory: malformed package identity", PackageNames: []string{"openssl"}}
	doc.RejectedRecords = []*advisoryv1.RejectedRecord{rejected}
	for _, sourcePackage := range []bool{false, true} {
		doc.Advisories = append(doc.Advisories, &advisoryv1.Advisory{Id: rejected.Id, PackageName: "openssl", SourcePackage: sourcePackage, SourceUrl: source.Url, AssessmentUnknown: true, SourceRecordRejected: true})
	}
	// The same raw digest with new rejection metadata must invalidate old
	// evaluations and publish the synthetic records atomically.
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	after, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision == after.Revision {
		t.Fatal("changed rejection metadata reused the old feed revision")
	}
	// Reconstruct the service to prove this is a persisted manifest projection,
	// not transient parser state.
	s, err = New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Feeds(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Feeds) != 1 || !status.Feeds[0].Fresh || len(status.Feeds[0].RejectedRecords) != 1 || !proto.Equal(status.Feeds[0].RejectedRecords[0], rejected) {
		t.Fatalf("scoped rejection metadata or current coverage lost: %v", status)
	}
	id := seedInventory(t, pool, "fedora", "44",
		&inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"},
		&inventoryv1.Package{Name: "openssl", Version: "1:3.0.7-27.el9_4", Architecture: "x86_64", Manager: "rpm", SourceName: "openssl", SourceVersion: "1:3.0.7-27.el9_4"},
		&inventoryv1.Package{Name: "openssl-libs", Version: "1:3.0.7-27.el9_4", Architecture: "x86_64", Manager: "rpm", SourceName: "openssl", SourceVersion: "1:3.0.7-27.el9_4"})
	request := &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1}
	found := make(map[string]*adminv1.AdvisoryFinding)
	for {
		out, err := listEvaluated(t, s, request, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "source_record_rejected" || len(out.Findings) != 1 {
			t.Fatalf("rejected source exposure was not unknown: %v", out)
		}
		finding := out.Findings[0]
		if _, exists := found[finding.PackageName]; exists {
			t.Fatalf("duplicate finding across rejection pages: %v", finding)
		}
		found[finding.PackageName] = finding
		if finding.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
			t.Fatalf("device uncertainty did not dominate finding state: %v", finding)
		}
		if finding.PackageName == "sudo" {
			if finding.Reason != "" || finding.FixedVersion == "" {
				t.Fatalf("valid unrelated finding mislabeled as rejected: %v", finding)
			}
		} else if finding.Reason != "source_record_rejected" || finding.FixedVersion != "" {
			t.Fatalf("rejected binary/source mapping lost its reason: %v", finding)
		}
		if out.NextPageToken == "" {
			break
		}
		request.PageToken = out.NextPageToken
	}
	if len(found) != 3 {
		t.Fatalf("lost implicated source or binary package: %v", found)
	}
	if _, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, false, []byte("[]")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected findings escaped device scope: %v", err)
	}
	actor := uuid.New()
	mustExec(t, t.Context(), pool, "INSERT INTO principals(id,issuer,subject) VALUES($1,'https://advisory.test',$2)", actor, uuid.NewString())
	acceptFinding(t, s, actor, &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: id.String(), FindingId: found["openssl"].Id, Reason: "Documented temporary source uncertainty", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))})
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range out.Findings {
		if finding.PackageName == "openssl" && (finding.Exception == nil || finding.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || finding.Reason != "source_record_rejected") {
			t.Fatalf("risk acceptance overrode rejected-source uncertainty: %v", finding)
		}
	}
	unrelated := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-10.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	unaffected, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: unrelated.String()}, true, []byte("[]"))
	if err != nil || unaffected.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR || len(unaffected.GetFindings()) != 0 {
		t.Fatalf("scoped rejection contaminated unrelated device: %v %v", unaffected, err)
	}
	summary, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil || summary.GetUnknownDevices() != 1 || summary.GetEvaluatedDevices() != 1 {
		t.Fatalf("rejected exposure became evaluated fleet coverage: %v %v", summary, err)
	}
	hidden, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, false, []byte("[]"))
	if err != nil || hidden.GetUnknownDevices() != 0 || hidden.GetEvaluatedDevices() != 0 || len(hidden.GetAdvisories()) != 0 {
		t.Fatalf("rejected exposure leaked through scoped summary: %v %v", hidden, err)
	}
}

func TestAdvisoryUnscopedRejectionAndManifestCapacity(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	doc.RejectedRecords = []*advisoryv1.RejectedRecord{{Id: "malformed-record", Reason: "advisory: package identity unavailable", Unscoped: true}}
	// Publication must not assert complete coverage even if its caller leaves
	// CompleteSnapshot set on a record with no trustworthy package scope.
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	status, err := s.Feeds(t.Context())
	if err != nil || len(status.GetFeeds()) != 1 || status.Feeds[0].Fresh || len(status.Feeds[0].RejectedRecords) != 1 {
		t.Fatalf("unscoped rejection asserted complete coverage: %v %v", status, err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-10.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil || out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.GetFreshness().GetReason() != "feed_partial_coverage" || len(out.GetFindings()) != 0 {
		t.Fatalf("unscoped rejection cleared a device: %v %v", out, err)
	}
	before, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	doc.RejectedRecords[0].Reason = strings.Repeat("x", 64<<10)
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized manifest did not fail before SQL publication: %v", err)
	}
	after, err := advisorydb.New(pool).GetAdvisoryFeed(t.Context(), source.Id)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision != after.Revision || !bytes.Equal(before.SourceManifest, after.SourceManifest) || before.ExpiresAt != after.ExpiresAt {
		t.Fatal("oversized manifest replaced or renewed the last valid publication")
	}
}

// The fleet's grouped unchecked causes are exactly the reasons the device
// findings view reports for each unknown device, over the same population.
func TestAdvisoryUncheckedGroupsMatchDeviceFreshness(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	ubuntu := &inventoryv1.Package{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.3", Manager: "dpkg", Architecture: "amd64", SourceName: "openssh", SourceVersion: "1:9.6p1-3ubuntu13.3"}
	debian := &inventoryv1.Package{Name: "openssh-server", Version: "1:9.2p1-2+deb12u3", Manager: "dpkg", Architecture: "amd64", SourceName: "openssh", SourceVersion: "1:9.2p1-2+deb12u3"}
	type device struct {
		id              uuid.UUID
		osID, osVersion string
		wantReason      string
	}
	devices := []device{
		{seedInventory(t, pool, "ubuntu", "24.04", ubuntu), "ubuntu", "24.04", "feed_partial_coverage"},
		{seedInventory(t, pool, "ubuntu", "24.04", ubuntu), "ubuntu", "24.04", "feed_partial_coverage"},
		{seedInventory(t, pool, "ubuntu", "24.04", ubuntu), "ubuntu", "24.04", "inventory_stale"},
		{seedInventory(t, pool, "debian", "12", debian), "debian", "12", "feed_unavailable"},
	}
	if err := drainEvaluations(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	// One evaluation outlived its inventory; one device was never evaluated.
	mustExec(t, t.Context(), pool, "UPDATE advisory_evaluations SET expires_at=now()-interval '1 second' WHERE device_id=$1", devices[2].id)
	devices = append(devices, device{seedInventory(t, pool, "ubuntu", "24.04", ubuntu), "ubuntu", "24.04", evaluationPending})
	want := make(map[string]uint64)
	for _, d := range devices {
		out, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: d.id.String()}, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		if out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.GetFreshness().GetReason() != d.wantReason {
			t.Fatalf("fixture device %s/%s did not reach %s: %v", d.osID, d.osVersion, d.wantReason, out.GetFreshness())
		}
		want[d.wantReason+"/"+out.GetFreshness().GetFeedId()+"/"+d.osID+"/"+d.osVersion]++
	}
	summary, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]uint64)
	total := uint64(0)
	for _, group := range summary.GetUncheckedGroups() {
		reason := strings.ToLower(strings.TrimPrefix(group.GetReason().String(), "ADVISORY_UNCHECKED_REASON_"))
		got[reason+"/"+group.GetFeedId()+"/"+group.GetOsId()+"/"+group.GetOsVersion()] += group.GetDevices()
		total += group.GetDevices()
		if wantName := map[string]string{"ubuntu": "Ubuntu 24.04 LTS", "debian": "Debian 12"}[group.GetOsId()]; group.GetOsName() != wantName {
			t.Fatalf("group OS name %q, want %q", group.GetOsName(), wantName)
		}
	}
	if !maps.Equal(got, want) || total != summary.GetUnknownDevices() || total != uint64(len(devices)) {
		t.Fatalf("unchecked groups %v (total %d of %d unknown) differ from device freshness %v", got, total, summary.GetUnknownDevices(), want)
	}
	hidden, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, false, []byte("[]"))
	if err != nil || len(hidden.GetUncheckedGroups()) != 0 {
		t.Fatalf("unchecked groups leaked out-of-scope devices: %v %v", hidden, err)
	}
	status, err := s.Feeds(t.Context())
	if err != nil || len(status.GetFeeds()) != 1 || status.Feeds[0].GetOsName() != "Ubuntu 24.04 LTS" {
		t.Fatalf("feed OS name: %v %v", status, err)
	}
}

func TestAdvisoryRejectedRecordLegacyAssessmentRemainsUnknown(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	// Simulate the fields an older server understands. The new rejection flag
	// and manifest are not needed to preserve the existing unknown assessment.
	doc.Advisories = []*advisoryv1.Advisory{{Id: "rejected-record", PackageName: "openssl", SourceUrl: source.Url, AssessmentUnknown: true}}
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "openssl", Version: "1:3.0.7-27.el9_4", Architecture: "x86_64", Manager: "rpm"})
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil || out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.GetFreshness().GetReason() != "vendor_assessment_unknown" || len(out.GetFindings()) != 1 || out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatalf("legacy assessment fields failed closed compatibility: %v %v", out, err)
	}
}

func vendorService(t *testing.T, pool *pgxpool.Pool, distro, release, file string) (*Service, *advisoryv1.FeedSource, *advisoryv1.FeedDocument) {
	t.Helper()
	raw, err := os.ReadFile("feed/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	format := advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON
	if distro == "fedora" {
		format = advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO
		raw = append(append([]byte("<updates>"), raw...), []byte("</updates>")...)
	}
	digest := sha256.Sum256(raw)
	source := &advisoryv1.FeedSource{Id: distro + "-" + release, Distro: distro, Release: release, Url: "https://vendor.example/" + file, Format: format, MaxAgeSeconds: 86400, ExpectedSha256: digest[:]}
	if distro == "fedora" {
		source.Architecture = "x86_64"
	}
	doc, err := feed.Parse(source, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	return s, source, doc
}

func acceptFinding(t *testing.T, s *Service, actor uuid.UUID, req *adminv1.AcceptAdvisoryFindingRequest) *adminv1.AcceptAdvisoryFindingResponse {
	t.Helper()
	tx, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if err := advisorydb.New(tx).LockAdvisoryDevice(t.Context(), uuid.MustParse(req.DeviceId)); err != nil {
		t.Fatal(err)
	}
	out, err := s.Accept(t.Context(), tx, actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return out
}

func seedInventory(t *testing.T, pool *pgxpool.Pool, distro, release string, packages ...*inventoryv1.Package) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	deviceID, generation, snapshot := uuid.New(), uuid.New(), uuid.New()
	payload, err := proto.Marshal(&inventoryv1.PackageBatch{Packages: packages})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	mustExec(t, ctx, pool, "INSERT INTO devices(id,state,hostname,os_id,os_version,architecture,enrolled_at,host_received_at,snapshot_received_at) VALUES($1,'active','advisory-fixture',$2,$3,'x86_64',now(),now(),now())", deviceID, distro, release)
	mustExec(t, ctx, pool, "INSERT INTO enrollment_generations(id,device_id,state,created_at) VALUES($1,$2,'active',now())", generation, deviceID)
	mustExec(t, ctx, pool, "UPDATE devices SET current_generation_id=$2 WHERE id=$1", deviceID, generation)
	mustExec(t, ctx, pool, `INSERT INTO package_snapshots(id,device_id,generation_id,sequence,state,manifest_digest,manifest_bytes,created_at,started_at,finished_at,accepted_at,open_until,receipt_expires_at,committed_at,backend,package_count,batch_count,encoded_bytes,metadata_bytes,reserved_bytes,bulk_retained)
VALUES($1,$2,$3,1,'committed',$4,$5,now(),now(),now(),now(),now()+interval '24 hours',now()+interval '2160 hours',now(),$6,$7,1,$8,0,0,true)`, snapshot, deviceID, generation, digest[:], payload, packages[0].Manager, len(packages), len(payload))
	for i, p := range packages {
		mustExec(t, ctx, pool, "INSERT INTO snapshot_packages(snapshot_id,position,name,version,architecture,manager,source_name,source_version,module_status,module_name,module_stream,module_version,module_context) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)", snapshot, i, p.Name, p.Version, p.Architecture, p.Manager, p.SourceName, p.SourceVersion, int32(p.GetModule().GetStatus()), p.GetModule().GetName(), p.GetModule().GetStream(), p.GetModule().GetVersion(), p.GetModule().GetContext())
	}
	mustExec(t, ctx, pool, "UPDATE enrollment_generations SET current_snapshot_id=$2 WHERE id=$1", generation, snapshot)
	mustExec(t, ctx, pool, `INSERT INTO host_observations(generation_id,sequence,started_at,finished_at,received_at,digest,boot_id_status,boot_id_value,hostname_status,hostname_value,os_id_status,os_id_value,os_version_status,os_version_value,architecture_status,architecture_value,kernel_release_status,kernel_release_value,hardware_vendor_status,hardware_vendor_value,hardware_model_status,hardware_model_value,hardware_serial_status,hardware_serial_value)
VALUES($1,1,now(),now(),(SELECT host_received_at FROM devices WHERE id=$2),$3,1,'fixture-boot',1,'advisory-fixture',1,$4,1,$5,1,'x86_64',1,'fixture-kernel',2,'',2,'',2,'')`, generation, deviceID, digest[:], distro, release)
	mustExec(t, ctx, pool, "INSERT INTO package_attempts(generation_id,sequence,started_at,finished_at,received_at,status,backend,snapshot_id,digest) VALUES($1,1,now(),now(),now(),1,$2,$3,$4)", generation, packages[0].Manager, snapshot, digest[:])
	return deviceID
}

// listEvaluated runs the background evaluation job to completion, then reads
// the persisted evaluation exactly as the admin API does.
func listEvaluated(t *testing.T, s *Service, req *adminv1.ListDeviceFindingsRequest, unrestricted bool, scopes []byte) (*adminv1.ListDeviceFindingsResponse, error) {
	t.Helper()
	if err := drainEvaluations(t.Context(), s); err != nil {
		return nil, err
	}
	return s.ListDevice(t.Context(), req, unrestricted, scopes)
}

func drainEvaluations(ctx context.Context, s *Service) error {
	for range 1000 {
		attempted, err := s.EvaluatePending(ctx, evaluationBatch)
		if err != nil || attempted < evaluationBatch {
			return err
		}
	}
	return errors.New("pending advisory evaluations did not drain")
}

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}
