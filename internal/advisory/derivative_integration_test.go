// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/testdb"
)

const ubuntuArchiveKey = "F6ECB3762474EDA9D21B7022871920D1991BC93C"

var (
	ubuntuUpdates   = &inventoryv1.AptListing{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble-updates", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED, Signer: ubuntuArchiveKey}
	ubuntuSecurity  = &inventoryv1.AptListing{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble-security", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED, Signer: ubuntuArchiveKey}
	ubuntuBackports = &inventoryv1.AptListing{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble-backports", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED, Signer: ubuntuArchiveKey}
	mintZena        = &inventoryv1.AptListing{Origin: "linuxmint", Label: "linuxmint", Suite: "zena", Codename: "zena", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED, Signer: "302F0738F465C1535761F965A6616109451BBBF2"}
	popRelease      = &inventoryv1.AptListing{Origin: "pop-os-release", Label: "Pop!_OS Release", Suite: "noble", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED, Signer: "63C46DF0140D738961429F4E204DD8AEC33A7AFF"}
	// Release claiming Ubuntu's identity, verified with some other key.
	foreignClaim  = &inventoryv1.AptListing{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_VERIFIED, Signer: strings.Repeat("AB", 20)}
	unsignedClaim = &inventoryv1.AptListing{Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble", Codename: "noble", Signature: inventoryv1.AptReleaseSignature_APT_RELEASE_SIGNATURE_UNSIGNED}
)

// openssh is the source package of USN-6859-1; every binary of an older
// source version is a candidate on an Ubuntu 24.04 device.
func opensshBinary(name, version string, listings ...*inventoryv1.AptListing) *inventoryv1.Package {
	return &inventoryv1.Package{Name: name, Version: version, Architecture: "amd64", Manager: "dpkg", SourceName: "openssh", SourceVersion: version,
		Origin: &inventoryv1.PackageOrigin{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Listings: listings}}
}

func vendorBinary(name, version string, listings ...*inventoryv1.AptListing) *inventoryv1.Package {
	return &inventoryv1.Package{Name: name, Version: version, Architecture: "all", Manager: "dpkg", SourceName: name, SourceVersion: version,
		Origin: &inventoryv1.PackageOrigin{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Listings: listings}}
}

// seedOriginInventory seeds a device like seedInventory and stores each
// package's APT origin evidence exactly as snapshot ingestion does.
func seedOriginInventory(t *testing.T, pool *pgxpool.Pool, distro, release string, packages ...*inventoryv1.Package) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	id := seedInventory(t, pool, distro, release, packages...)
	var snapshot uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT g.current_snapshot_id FROM devices d JOIN enrollment_generations g ON g.id=d.current_generation_id WHERE d.id=$1", id).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	for position, p := range packages {
		mustExec(t, ctx, pool, "UPDATE snapshot_packages SET origin_status=$3 WHERE snapshot_id=$1 AND position=$2", snapshot, position, int16(p.GetOrigin().GetStatus()))
		for ordinal, l := range p.GetOrigin().GetListings() {
			mustExec(t, ctx, pool, "INSERT INTO snapshot_package_listings(snapshot_id,position,ordinal,origin,label,suite,codename,signature,signer) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
				snapshot, position, ordinal, l.GetOrigin(), l.GetLabel(), l.GetSuite(), l.GetCodename(), int16(l.GetSignature()), l.GetSigner())
		}
	}
	return id
}

func completeUbuntuService(t *testing.T, pool *pgxpool.Pool) *Service {
	t.Helper()
	s, source, doc := vendorService(t, pool, "ubuntu", "24.04", "ubuntu-USN-6859-1.json")
	// The fixture holds one USN; mark it a complete export so coverage, not
	// feed completeness, decides the device state under test.
	doc.CompleteSnapshot = true
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return s
}

func uncoveredReasons(t *testing.T, s *Service, id uuid.UUID, pageSize uint32) (map[string]string, *adminv1.AdvisoryFreshness) {
	t.Helper()
	reasons := map[string]string{}
	token := ""
	var fresh *adminv1.AdvisoryFreshness
	for range 100 {
		out, err := s.ListUncovered(t.Context(), &adminv1.ListDeviceUncoveredPackagesRequest{DeviceId: id.String(), PageSize: pageSize, PageToken: token}, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		if uint32(len(out.Packages)) > pageSize {
			t.Fatalf("page exceeded its size: %v", out)
		}
		fresh = out.Freshness
		for _, p := range out.Packages {
			if _, repeated := reasons[p.Name]; repeated {
				t.Fatalf("page repeated %s", p.Name)
			}
			reasons[p.Name] = p.Reason
		}
		if out.NextPageToken == "" {
			return reasons, fresh
		}
		token = out.NextPageToken
	}
	t.Fatal("uncovered pages did not terminate")
	return nil, nil
}

func TestLinuxMintAppliesUbuntuFeedOnlyToVerifiedUbuntuOrigin(t *testing.T) {
	pool, _ := testdb.Open(t)
	s := completeUbuntuService(t, pool)
	old := "1:9.6p1-3ubuntu13.2"
	id := seedOriginInventory(t, pool, "linuxmint", "22.3",
		opensshBinary("openssh-server", old, ubuntuSecurity, ubuntuUpdates),
		// Same vulnerable version also listed by Mint: ambiguous, so never a finding.
		opensshBinary("openssh-client", old, ubuntuUpdates, mintZena),
		// Vulnerable versions without verified Ubuntu origin.
		opensshBinary("openssh-sftp-server", old),
		opensshBinary("ssh", old, foreignClaim),
		opensshBinary("ssh-askpass-gnome", old, unsignedClaim),
		opensshBinary("openssh-tests", old, ubuntuBackports),
		vendorBinary("mint-common", "2.3.1", mintZena),
	)
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := out.GetFreshness()
	if fresh.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || fresh.GetReason() != "vendor_feed_unavailable_linuxmint" || fresh.GetUncoveredPackages() != 6 {
		t.Fatalf("freshness = %v", fresh)
	}
	if len(out.Findings) != 1 || out.Findings[0].PackageName != "openssh-server" || out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED || out.Findings[0].FixedVersion != "1:9.6p1-3ubuntu13.3" {
		t.Fatalf("findings = %v", out.Findings)
	}
	reasons, listed := uncoveredReasons(t, s, id, 2)
	want := map[string]string{
		"openssh-client":      "origin_ambiguous",
		"openssh-sftp-server": "origin_unlisted",
		"ssh":                 "origin_not_covered",
		"ssh-askpass-gnome":   "origin_unverified",
		"openssh-tests":       "base_pocket_uncovered",
		"mint-common":         "vendor_feed_unavailable",
	}
	if len(reasons) != len(want) {
		t.Fatalf("uncovered = %v", reasons)
	}
	for name, reason := range want {
		if reasons[name] != reason {
			t.Errorf("%s reason = %q, want %q", name, reasons[name], reason)
		}
	}
	if listed.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL {
		t.Fatalf("uncovered freshness = %v", listed)
	}
	summary, err := s.Summary(t.Context(), &adminv1.ListAdvisorySummaryRequest{}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if summary.PartialDevices != 1 || summary.EvaluatedDevices != 0 || summary.UnknownDevices != 0 || len(summary.Advisories) != 1 || summary.Advisories[0].AffectedDevices != 1 {
		t.Fatalf("summary = %v", summary)
	}
	// Re-evaluating unchanged evidence keeps the evaluation identity.
	again, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil || again.GetFreshness().GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || len(again.Findings) != 1 {
		t.Fatalf("re-evaluation = %v, %v", again, err)
	}
}

func TestPopOSPartialNamesItsVendor(t *testing.T) {
	pool, _ := testdb.Open(t)
	s := completeUbuntuService(t, pool)
	id := seedOriginInventory(t, pool, "pop", "24.04",
		opensshBinary("openssh-server", "1:9.6p1-3ubuntu13.3", ubuntuUpdates),
		vendorBinary("pop-default-settings", "8.0.0~1727", popRelease),
	)
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if fresh := out.GetFreshness(); fresh.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || fresh.GetReason() != "vendor_feed_unavailable_pop" || fresh.GetUncoveredPackages() != 1 || len(out.Findings) != 0 {
		t.Fatalf("pop evaluation = %v", out)
	}
	reasons, _ := uncoveredReasons(t, s, id, 50)
	if len(reasons) != 1 || reasons["pop-default-settings"] != "vendor_feed_unavailable" {
		t.Fatalf("uncovered = %v", reasons)
	}
}

func TestDerivativeCoverageLeavesOtherDevicesUnchanged(t *testing.T) {
	pool, _ := testdb.Open(t)
	s := completeUbuntuService(t, pool)
	old := "1:9.6p1-3ubuntu13.2"
	t.Run("ubuntu-ignores-origin-evidence", func(t *testing.T) {
		id := seedOriginInventory(t, pool, "ubuntu", "24.04",
			opensshBinary("openssh-server", old, ubuntuUpdates),
			opensshBinary("openssh-client", old, ubuntuUpdates, mintZena),
			opensshBinary("openssh-sftp-server", old))
		out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		if fresh := out.GetFreshness(); fresh.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED || fresh.GetUncoveredPackages() != 0 || len(out.Findings) != 3 {
			t.Fatalf("ubuntu evaluation = %v", out)
		}
		uncovered, err := s.ListUncovered(t.Context(), &adminv1.ListDeviceUncoveredPackagesRequest{DeviceId: id.String()}, true, []byte("[]"))
		if err != nil || len(uncovered.Packages) != 0 {
			t.Fatalf("ubuntu uncovered = %v, %v", uncovered, err)
		}
	})
	t.Run("unqualified-derivative-release", func(t *testing.T) {
		id := seedOriginInventory(t, pool, "linuxmint", "22.2", opensshBinary("openssh-server", old, ubuntuUpdates))
		out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		if fresh := out.GetFreshness(); fresh.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || fresh.GetReason() != "feed_unavailable" || len(out.Findings) != 0 {
			t.Fatalf("mint 22.2 evaluation = %v", out)
		}
	})
	t.Run("derivative-without-origin-evidence", func(t *testing.T) {
		// Historical snapshots predate origin collection: nothing is
		// verifiably Ubuntu, so nothing is known.
		pkg := opensshBinary("openssh-server", old)
		pkg.Origin = nil
		id := seedOriginInventory(t, pool, "linuxmint", "22.3", pkg)
		out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
		if err != nil {
			t.Fatal(err)
		}
		if fresh := out.GetFreshness(); fresh.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || fresh.GetReason() != "package_origin_unavailable" || len(out.Findings) != 0 {
			t.Fatalf("historical mint evaluation = %v", out)
		}
	})
}

// Derivative coverage keys finding sets by policy and origin evidence: equal
// Mint inventories share one set, while a base device with the same package
// rows never reuses (or is reused by) a coverage-restricted set.
func TestDerivativeFindingSetsAreKeyedByOriginEvidence(t *testing.T) {
	pool, _ := testdb.Open(t)
	s := completeUbuntuService(t, pool)
	ctx := t.Context()
	old := "1:9.6p1-3ubuntu13.2"
	packages := func() []*inventoryv1.Package {
		return []*inventoryv1.Package{opensshBinary("openssh-server", old, ubuntuUpdates), opensshBinary("openssh-client", old, ubuntuUpdates, mintZena)}
	}
	firstMint := seedOriginInventory(t, pool, "linuxmint", "22.3", packages()...)
	secondMint := seedOriginInventory(t, pool, "linuxmint", "22.3", packages()...)
	ubuntu := seedOriginInventory(t, pool, "ubuntu", "24.04", packages()...)
	if err := drainEvaluations(ctx, s); err != nil {
		t.Fatal(err)
	}
	setOf := func(device uuid.UUID) (set uuid.UUID, uncovered int32) {
		t.Helper()
		if err := pool.QueryRow(ctx, "SELECT e.finding_set_id, s.uncovered_packages FROM advisory_evaluations e JOIN advisory_finding_sets s ON s.id=e.finding_set_id WHERE e.device_id=$1", device).Scan(&set, &uncovered); err != nil {
			t.Fatal(err)
		}
		return set, uncovered
	}
	mintSet, mintUncovered := setOf(firstMint)
	secondSet, _ := setOf(secondMint)
	ubuntuSet, ubuntuUncovered := setOf(ubuntu)
	if mintSet != secondSet || mintSet == ubuntuSet || mintUncovered != 1 || ubuntuUncovered != 0 {
		t.Fatalf("sets mint=%s/%d second=%s ubuntu=%s/%d", mintSet, mintUncovered, secondSet, ubuntuSet, ubuntuUncovered)
	}
	var findings int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_set_findings WHERE set_id=$1", mintSet).Scan(&findings); err != nil || findings != 1 {
		t.Fatalf("mint set findings = %d, %v", findings, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM advisory_set_findings WHERE set_id=$1", ubuntuSet).Scan(&findings); err != nil || findings != 2 {
		t.Fatalf("ubuntu set findings = %d, %v", findings, err)
	}
}
