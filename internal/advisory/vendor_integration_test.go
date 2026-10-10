//go:build integration

package advisory

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"os"
	"slices"
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
	"lindm/internal/advisory/feed"
	"lindm/internal/testdb"
)

// Vendor statements are genuine pinned fixtures; installed boundary versions and
// enabled repository evidence here are controlled database fixtures, not VM claims.
func TestAdvisoryLaunchFamilyBackportsAndNativeStreams(t *testing.T) {
	for _, test := range []struct {
		name, distro, release, stream, file, url, packageName, manager, old, fixed, cve, module string
		format                                                                                  advisoryv1.FeedFormat
	}{
		{"sles", "sles", "15.6", "", "suse-suse-su-2024_2275-1.json", "https://ftp.suse.com/pub/projects/security/csaf/suse-su-2024_2275-1.json", "openssh", "rpm", "9.6p1-150600.6.2.1", "9.6p1-150600.6.3.1", "CVE-2024-6387", "", advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF},
		{"leap", "opensuse-leap", "15.6", "", "suse-suse-su-2024_2275-1.json", "https://ftp.suse.com/pub/projects/security/csaf/suse-su-2024_2275-1.json", "openssh", "rpm", "9.6p1-150600.6.2.1", "9.6p1-150600.6.3.1", "CVE-2024-6387", "", advisoryv1.FeedFormat_FEED_FORMAT_SUSE_CSAF},
		{"arch", "arch", "rolling", "", "arch-backport.json", "https://security.archlinux.org/all.json", "wpa_supplicant", "pacman", "2:2.9-7", "2:2.9-8", "CVE-2021-0326", "", advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON},
		{"debian-tracker", "debian", "12", "", "debian-tracker-subset.json", "https://security-tracker.debian.org/tracker/data/json", "openssh-server", "dpkg", "1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", "CVE-2024-6387", "", advisoryv1.FeedFormat_FEED_FORMAT_DEBIAN_TRACKER_JSON},
		{"rhel-standard", "rhel", "9", "standard", "redhat-rhsa-2024_6783.json", "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_6783.json", "openssl-libs", "rpm", "1:3.0.7-27.el9_4", "1:3.0.7-28.el9_4", "CVE-2024-6119", "", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF},
		{"rhel-e4s", "rhel", "8.6", "e4s", "redhat-rhsa-2024_7846.json", "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_7846.json", "openssl-libs", "rpm", "1:1.1.1k-13.el8_6", "1:1.1.1k-14.el8_6", "CVE-2024-5535", "", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF},
		{"rhel-eus-module", "rhel", "8.8", "eus", "redhat-rhsa-2024_1880.json", "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1880.json", "nodejs", "rpm", "1:18.19.0-1.module+el8.8.0+21592+14a8b93e", "1:18.19.1-1.module+el8.8.0+21592+14a8b93e", "CVE-2023-46809", "18", advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			source := &advisoryv1.FeedSource{Id: test.name, Distro: test.distro, Release: test.release, PlatformStream: test.stream, Architecture: "x86_64", Format: test.format, Url: test.url, MaxAgeSeconds: 86400}
			s, doc := launchVendor(t, pool, source, test.file)
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			p := &inventoryv1.Package{Name: test.packageName, Version: test.old, Architecture: "x86_64", Manager: test.manager}
			if test.manager == "dpkg" {
				p.Architecture = "amd64"
				p.SourceName, p.SourceVersion = "openssh", test.old
				// Deliberately newer binary version: source advisories must use the
				// native source version, not the binary's sortable version string.
				p.Version = "9:99.0-1"
			}
			if test.distro == "rhel" {
				p.Module = &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}
				if test.module != "" {
					p.Module.Modular, p.Module.Name, p.Module.Stream = true, "nodejs", test.module
					p.Module.Version, p.Module.Context = "8080020240322102042", "63b34585"
				}
			}
			for _, fixed := range []bool{false, true} {
				installed := proto.CloneOf(p)
				if fixed {
					if test.manager == "dpkg" {
						installed.SourceVersion = test.fixed
					} else {
						installed.Version = test.fixed
					}
				}
				id := seedInventory(t, pool, test.distro, test.release, installed)
				if test.distro == "rhel" {
					seedRHELPlatform(t, pool, id, test.release, test.stream)
				}
				out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, finding := range out.GetFindings() {
					if slices.Contains(finding.GetCves(), test.cve) {
						found = true
						comparison, err := feed.Compare(test.manager, finding.GetFixedVersion(), test.fixed)
						if err != nil || comparison != 0 {
							t.Fatalf("wrong native fix: %v %v", finding, err)
						}
					}
					if test.module != "" && !slices.Equal(finding.GetCves(), []string{"CVE-2023-46809", "CVE-2024-21892", "CVE-2024-22019"}) {
						t.Fatalf("matching CVEs overwritten within one advisory: %v", finding)
					}
					if test.manager == "dpkg" && (finding.GetPublishedAt() != nil || slices.Contains(finding.GetCves(), "CVE-2024-6409")) {
						t.Fatalf("Debian unknown date or not-affected status fabricated: %v", finding)
					}
				}
				if found == fixed {
					t.Fatalf("backport classification fixed=%v: %v", fixed, out)
				}
				if out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
					t.Fatalf("partial vendor data established complete coverage: %v", out)
				}
			}
			if test.module != "" {
				p.Module.Stream = "20"
				id := seedInventory(t, pool, test.distro, test.release, p)
				seedRHELPlatform(t, pool, id, test.release, test.stream)
				out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
				if err != nil || len(out.GetFindings()) != 0 {
					t.Fatalf("another module stream inherited an advisory: %v %v", out, err)
				}
			}
		})
	}
}

func TestAdvisoryDebianUndeterminedRemainsUnknown(t *testing.T) {
	pool, _ := testdb.Open(t)
	source := &advisoryv1.FeedSource{Id: "debian", Distro: "debian", Release: "12", Format: advisoryv1.FeedFormat_FEED_FORMAT_DEBIAN_TRACKER_JSON, Url: "https://security-tracker.debian.org/tracker/data/json", MaxAgeSeconds: 86400}
	s, doc := launchVendor(t, pool, source, "debian-tracker-subset.json")
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "debian", "12", &inventoryv1.Package{Name: "libjs-angularjs", Version: "1.8.3-1+deb12u1", Architecture: "all", Manager: "dpkg", SourceName: "angular.js", SourceVersion: "1.8.3-1+deb12u1"})
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.GetFindings()) != 1 || out.GetFindings()[0].GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.GetFindings()[0].GetFixedVersion() != "" || out.GetFindings()[0].GetPublishedAt() != nil {
		t.Fatalf("undetermined vendor assessment was invented: %v", out)
	}
}

func TestAdvisorySignedSnapshotAgeAndManifestPersist(t *testing.T) {
	pool, _ := testdb.Open(t)
	s, source, doc := vendorService(t, pool, "fedora", "44", "fedora44-sudo.xml")
	// Controlled publication inputs test age/provenance persistence, not a claim
	// that Fedora signs CSAF. Genuine signatures have separate acquisition tests.
	doc.SnapshotAt = timestamppb.New(time.Now().UTC().Truncate(time.Microsecond).Add(-48 * time.Hour))
	doc.Artifacts = []*advisoryv1.FeedArtifact{{Url: source.Url, Sha256: doc.SourceSha256, SignerFingerprint: "77E79ABE93673533ED09EBE2DCE3823597F5EAC4"}}
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	status, err := s.Feeds(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.GetFeeds()) != 1 || !proto.Equal(status.Feeds[0].GetSnapshotAt(), doc.SnapshotAt) || len(status.Feeds[0].GetArtifacts()) != 1 || !proto.Equal(status.Feeds[0].Artifacts[0], doc.Artifacts[0]) || status.Feeds[0].ExpiresAt.AsTime().After(time.Now()) {
		t.Fatalf("signed source freshness/provenance lost: %v", status)
	}
	id := seedInventory(t, pool, "fedora", "44", &inventoryv1.Package{Name: "sudo", Version: "0:1.9.17-10.p2.fc44", Architecture: "x86_64", Manager: "rpm"})
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil || out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.GetFreshness().GetReason() != "feed_stale" {
		t.Fatalf("recent fetch renewed an old signed snapshot: %v %v", out, err)
	}
}

func launchVendor(t *testing.T, pool *pgxpool.Pool, source *advisoryv1.FeedSource, file string) (*Service, *advisoryv1.FeedDocument) {
	t.Helper()
	raw, err := os.ReadFile("feed/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	source.ExpectedSha256 = digest[:]
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := feed.Parse(source, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s, doc
}

func seedRHELPlatform(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, release, stream string) {
	t.Helper()
	major, _, _ := strings.Cut(release, ".")
	suffix := ""
	if stream != "standard" {
		suffix = "-" + stream
	}
	platform := &inventoryv1.PlatformDetails{
		Cpe:            &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: "cpe:/o:redhat:enterprise_linux:" + major + "::baseos"},
		ReleaseverLock: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Value: release},
		Repositories:   &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: "dnf4", Ids: []string{"rhel-" + major + "-for-x86_64-baseos" + suffix + "-rpms"}},
	}
	encoded, err := proto.Marshal(&inventoryv1.NativeDetails{Platform: platform})
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, t.Context(), pool, "UPDATE host_observations SET details=$2 WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", id, encoded)
}

func TestAdvisoryArchAbsentVersionIsNativeRollingEvidence(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		status       inventoryv1.CollectionStatus
		stale        bool
	}{
		{"unavailable", "feed_partial_coverage", inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, false},
		{"collection-failed", "host_inventory_stale_or_failed", inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT, false},
		{"host-stale", "inventory_stale", inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			source := &advisoryv1.FeedSource{Id: "arch", Distro: "arch", Release: "rolling", Architecture: "x86_64", Format: advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON, Url: "https://security.archlinux.org/all.json", MaxAgeSeconds: 86400}
			s, doc := launchVendor(t, pool, source, "arch-backport.json")
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			id := seedInventory(t, pool, "arch", "rolling", &inventoryv1.Package{Name: "wpa_supplicant", Version: "2:2.9-7", Architecture: "any", Manager: "pacman"})
			mustExec(t, t.Context(), pool, "UPDATE devices SET os_version='' WHERE id=$1", id)
			mustExec(t, t.Context(), pool, "UPDATE host_observations SET os_version_status=$2,os_version_value='' WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", id, int16(test.status))
			if test.stale {
				mustExec(t, t.Context(), pool, "UPDATE host_observations SET started_at=now()-interval '48 hours',finished_at=now()-interval '48 hours' WHERE generation_id=(SELECT current_generation_id FROM devices WHERE id=$1)", id)
			}
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if len(out.GetFindings()) != 1 || !slices.Contains(out.Findings[0].GetCves(), "CVE-2021-0326") || out.Findings[0].GetFixedVersion() != "2:2.9-8" {
				t.Fatalf("native rolling inventory lost its known package finding: %v", out)
			}
			if out.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.GetFreshness().GetReason() != test.reason {
				t.Fatalf("native release absence was confused with collection failure: %v", out.GetFreshness())
			}
		})
	}
}
