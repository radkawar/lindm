//go:build integration

package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory"
	advisoryfeed "lindm/internal/advisory/feed"
	"lindm/internal/identity"
)

func TestAdvisoryAcceptanceFreshActorScopeAndDurableRetry(t *testing.T) {
	f := newEnrolled(t, 0)
	raw, err := os.ReadFile("../advisory/feed/testdata/ubuntu-USN-6859-1.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	source := &advisoryv1.FeedSource{Id: "noble", Distro: "ubuntu", Release: "24.04", Url: "https://api.osv.dev/v1/vulns/USN-6859-1", Format: advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, MaxAgeSeconds: 86400, ExpectedSha256: digest[:]}
	store, err := advisory.New(f.ctx, f.svc.pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(f.ctx, source.Id, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	f.svc.advisories = store
	host := hostObservation(f.generation, 1, "advisory-acceptance")
	host.Observation.StartedAt = timestamppb.New(f.now)
	host.Observation.FinishedAt = timestamppb.New(f.now)
	host.Observation.OsId.Value = "ubuntu"
	host.Observation.OsVersion.Value = "24.04"
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(host)); err != nil {
		t.Fatal(err)
	}
	batch := packageBatch(t, &inventoryv1.Package{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.2", Architecture: "amd64", Manager: "dpkg", SourceName: "openssh", SourceVersion: "1:9.6p1-3ubuntu13.2"})
	manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{batch})
	manifest.Backend = "dpkg"
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.SnapshotId, 0, batch, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	// Reads serve persisted evaluations only: publication alone is pending
	// until the background job evaluates the new snapshot.
	pending, err := f.svc.ListDeviceFindings(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if pending.Msg.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || pending.Msg.GetFreshness().GetReason() != "evaluation_pending" || len(pending.Msg.GetFindings()) != 0 {
		t.Fatalf("read matched inline instead of serving the persisted evaluation: %v", pending.Msg)
	}
	if _, err := store.EvaluatePending(f.ctx, 32); err != nil {
		t.Fatal(err)
	}
	findings, err := f.svc.ListDeviceFindings(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings.Msg.Findings) != 1 {
		t.Fatalf("expected real vendor finding: %v", findings.Msg)
	}
	request := &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: f.deviceID, FindingId: findings.Msg.Findings[0].Id, Reason: "Authorized expiring risk acceptance", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}
	restricted, actor, _ := dispatchIdentity(t, f.svc.pool, &authv1.DeviceScope{DeviceIds: []string{uuid.NewString()}})
	f.svc.identity = restricted
	if _, err := f.svc.AcceptAdvisoryFinding(identity.WithPrincipal(f.ctx, actor), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("fresh out-of-scope authority accepted: %v", err)
	}
	var count int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM advisory_exceptions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("denied acceptance committed an exception")
	}
	allowed, allowedActor, directory := dispatchIdentity(t, f.svc.pool, &authv1.DeviceScope{DeviceIds: []string{f.deviceID}})
	f.svc.identity = allowed
	allowedCtx := identity.WithPrincipal(f.ctx, allowedActor)
	accepted, err := f.svc.AcceptAdvisoryFinding(allowedCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.svc.AcceptAdvisoryFinding(allowedCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(accepted.Msg, replay.Msg) {
		t.Fatalf("authorized exact retry changed response: %v", err)
	}
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='advisory.exception.accepted'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("exact retry duplicated audit: %d", count)
	}
	directory.membership(t, false)
	if _, err := f.svc.AcceptAdvisoryFinding(allowedCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked actor replayed exception: %v", err)
	}
}

func TestAdvisoriesMatchRecordedNativeInventory(t *testing.T) {
	for _, test := range []struct {
		name, distro, release, manager, packages, feed, sourceURL, arch string
		packageDigest                                                   string
		platform, platformDigest, stream, wantReason                    string
		format                                                          advisoryv1.FeedFormat
		wantFindings                                                    int
	}{
		{
			name: "ubuntu-noble", distro: "ubuntu", release: "24.04", manager: "dpkg",
			packages: "ubuntu-noble-packages.json", feed: "ubuntu-USN-6859-1.json",
			sourceURL:     "https://api.osv.dev/v1/vulns/USN-6859-1",
			packageDigest: "529f706837ea1d4d1adabce51b66c255def8aad158f05a0388a170f4d7c24248",
			format:        advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON,
		},
		{
			// Actual 26.04.1 openssl 3.5.5-1ubuntu3.5 on both architectures
			// predates USN-8861-1's resolute fix 3.5.5-1ubuntu3.7: all three
			// installed binaries are affected.
			name: "ubuntu-resolute-amd64", distro: "ubuntu", release: "26.04", manager: "dpkg",
			packages: "ubuntu-resolute-amd64-packages.json", feed: "ubuntu-USN-8861-1.json",
			sourceURL:     "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip",
			packageDigest: "5b6f29a9104b39e7d5874e1197a99d17512bc545f0e0f34ba633059ebe2ff67a",
			format:        advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, wantFindings: 3,
		},
		{
			name: "ubuntu-resolute-arm64", distro: "ubuntu", release: "26.04", manager: "dpkg", arch: "aarch64",
			packages: "ubuntu-resolute-arm64-packages.json", feed: "ubuntu-USN-8861-1.json",
			sourceURL:     "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip",
			packageDigest: "49bbea1b10885fa9ab17faec97cf5867805804a18ce66ce1de7df4fd72150080",
			format:        advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON, wantFindings: 3,
		},
		{
			name: "fedora44", distro: "fedora", release: "44", manager: "rpm",
			packages: "fedora44-packages.json", feed: "fedora44-sudo.xml",
			sourceURL:     "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/f7508933e5ed78ccc41d1cea6dc7d5f93d998b7fe97e7c9e84268e2ce8aadcac-updateinfo.xml.zst",
			packageDigest: "4748213c95a0da8b071f5603adba4c4582466247aa44d75c49c59818f68b927d",
			format:        advisoryv1.FeedFormat_FEED_FORMAT_RPM_UPDATEINFO, wantFindings: 1,
		},
		{
			name: "rhel98", distro: "rhel", release: "9.8", manager: "rpm",
			packages: "rhel98-packages.json", feed: "redhat-rhsa-2024_6783.json",
			sourceURL:     "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_6783.json",
			packageDigest: "2e98b89d9b2cf4d4911c81a1bb2680fcc93daac3cee90dc9e03478077668648b",
			platform:      "rhel98-platform.json", platformDigest: "97a325bd4ff0f436b57dcbcc4ab370cc1a4c193b04da81f98707d5b32ce6947b",
			format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, stream: "standard",
			wantReason: "rhel_platform_stream_unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newEnrolled(t, 0)
			raw, err := os.ReadFile("../advisory/feed/testdata/" + test.feed)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			source := &advisoryv1.FeedSource{
				Id: test.name, Distro: test.distro, Release: test.release, Url: test.sourceURL,
				Format: test.format, MaxAgeSeconds: 86400, ExpectedSha256: digest[:], PlatformStream: test.stream,
			}
			if test.manager == "rpm" {
				source.Architecture = "x86_64"
			}
			store, err := advisory.New(f.ctx, f.svc.pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Import(f.ctx, source.Id, bytes.NewReader(raw)); err != nil {
				t.Fatal(err)
			}
			f.svc.advisories = store
			recorded, err := os.ReadFile("../advisory/testdata/" + test.packages)
			if err != nil {
				t.Fatal(err)
			}
			packageDigest := sha256.Sum256(recorded)
			if hex.EncodeToString(packageDigest[:]) != test.packageDigest {
				t.Fatal("recorded package bytes no longer match the native provenance")
			}
			packages := new(inventoryv1.PackageBatch)
			if err := protojson.Unmarshal(recorded, packages); err != nil {
				t.Fatal(err)
			}
			host := hostObservation(f.generation, 1, test.name)
			host.Observation.StartedAt = timestamppb.New(f.now)
			host.Observation.FinishedAt = timestamppb.New(f.now)
			host.Observation.OsId.Value = test.distro
			host.Observation.OsVersion.Value = test.release
			host.Observation.Architecture.Value = "x86_64"
			if test.arch != "" {
				host.Observation.Architecture.Value = test.arch
			}
			if test.platform != "" {
				platformBytes, err := os.ReadFile("../advisory/testdata/" + test.platform)
				if err != nil {
					t.Fatal(err)
				}
				platformDigest := sha256.Sum256(platformBytes)
				if hex.EncodeToString(platformDigest[:]) != test.platformDigest {
					t.Fatal("recorded platform bytes no longer match native provenance")
				}
				host.Observation.Details = nativeDetailsFixture()
				host.Observation.Details.Platform = new(inventoryv1.PlatformDetails)
				if err := protojson.Unmarshal(platformBytes, host.Observation.Details.Platform); err != nil {
					t.Fatal(err)
				}
				// An unregistered VM cannot establish a servicing stream. Independently
				// prove the recorded package exceeds the real mainstream fix, without
				// attributing synthetic repository or entitlement evidence to that VM.
				doc, err := advisoryfeed.Parse(source, bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, record := range doc.GetAdvisories() {
					if record.GetPackageName() != "openssl-libs" || record.GetArchitecture() != "x86_64" || record.GetFixedVersion() == "" {
						continue
					}
					found = true
					comparison, err := advisoryfeed.Compare("rpm", packages.Packages[0].Version, record.FixedVersion)
					if err != nil || comparison < 0 {
						t.Fatalf("actual RHEL package predates vendor fix: %v, %v", record, err)
					}
				}
				if !found {
					t.Fatal("real RHEL advisory lacks recorded-package fix")
				}
			}
			if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(host)); err != nil {
				t.Fatal(err)
			}
			batch := packageBatch(t, packages.Packages...)
			manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{batch})
			manifest.Backend = test.manager
			if _, err := f.begin(t, manifest, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := f.put(t, manifest.SnapshotId, 0, batch, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := f.commit(t, manifest, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := store.EvaluatePending(f.ctx, 32); err != nil {
				t.Fatal(err)
			}
			response, err := f.svc.ListDeviceFindings(f.ownerCtx, connect.NewRequest(&adminv1.ListDeviceFindingsRequest{DeviceId: f.deviceID}))
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Msg.Findings) != test.wantFindings {
				t.Fatalf("recorded native package classification: %v", response.Msg)
			}
			reason := test.wantReason
			if reason == "" {
				reason = "feed_partial_coverage"
			}
			if response.Msg.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || response.Msg.Freshness.Reason != reason {
				t.Fatalf("selected real advisory subset claimed whole-device coverage: %v", response.Msg.Freshness)
			}
			if test.distro == "fedora" {
				finding := response.Msg.Findings[0]
				if finding.AdvisoryId != "FEDORA-2026-7d4732cbab" || finding.InstalledVersion != "0:1.9.17-7.p2.fc44" || finding.FixedVersion != "0:1.9.17-10.p2.fc44" || len(finding.Cves) != 1 || finding.Cves[0] != "CVE-2026-96512" {
					t.Fatalf("recorded Fedora sudo exposure: %v", finding)
				}
			}
			if test.release == "26.04" {
				for _, finding := range response.Msg.Findings {
					if finding.AdvisoryId != "USN-8861-1" || finding.InstalledVersion != "3.5.5-1ubuntu3.5" || finding.FixedVersion != "3.5.5-1ubuntu3.7" || len(finding.Cves) != 2 || finding.Cves[0] != "CVE-2026-42772" || finding.Cves[1] != "CVE-2026-54873" {
						t.Fatalf("recorded resolute openssl exposure: %v", finding)
					}
				}
			}
		})
	}
}
