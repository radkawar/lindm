//go:build integration

package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"os"
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
			response, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: oldID.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if len(response.GetFindings()) != 1 || response.Findings[0].GetFixedVersion() != tc.fixed {
				t.Fatalf("old package: %v", response)
			}
			response, err = s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: fixedID.String()}, true, []byte("[]"))
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

func TestAdvisoryFreshnessExceptionsScopeAndRevision(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"}, &inventoryv1.Package{Name: "sudo-devel", Version: "0:1.9.17-9.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	request := &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1}
	first, err := s.ListDevice(t.Context(), request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 1 || first.NextPageToken == "" {
		t.Fatalf("pagination: %v", first)
	}
	if first.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
		t.Fatalf("finding not affected: %v", first)
	}
	second, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageSize: 1, PageToken: first.NextPageToken}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Findings) != 1 || second.Findings[0].Id == first.Findings[0].Id {
		t.Fatal("page repeated or lost a finding")
	}
	if _, err := s.ListDevice(t.Context(), request, false, []byte("[]")); !errors.Is(err, ErrNotFound) {
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
	out, err := s.ListDevice(t.Context(), request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED {
		t.Fatal("active exception not visible")
	}
	if _, err := pool.Exec(t.Context(), "UPDATE advisory_exceptions SET accepted_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE finding_id=$1", uuid.MustParse(accept.FindingId)); err != nil {
		t.Fatal(err)
	}
	out, err = s.ListDevice(t.Context(), request, true, []byte("[]"))
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
	out, err = s.ListDevice(t.Context(), request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatal("stale feed shown healthy/affected with current certainty")
	}
	if _, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: id.String(), PageToken: first.NextPageToken}, true, []byte("[]")); !errors.Is(err, ErrConflict) {
		t.Fatalf("obsolete evaluation cursor silently rebound: %v", err)
	}
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE package_snapshots SET started_at=now()-interval '3 days',finished_at=now()-interval '2 days' WHERE device_id=$1", id); err != nil {
		t.Fatal(err)
	}
	out, err = s.ListDevice(t.Context(), request, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatal("stale inventory shown healthy")
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
	before, err := s.ListDevice(t.Context(), request, true, []byte("[]"))
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
	after, err := s.ListDevice(t.Context(), request, true, []byte("[]"))
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
	out, err := reconfigured.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
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
	out, err := s.ListDevice(t.Context(), &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 || out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "package_architecture_uncovered" {
		t.Fatalf("x86_64 repository cleared an uncovered multilib package: %v", out)
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

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}
