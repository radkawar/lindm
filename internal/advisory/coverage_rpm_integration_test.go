// SPDX-License-Identifier: Apache-2.0

//go:build integration

package advisory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	configv1 "lindm/gen/lindm/config/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpmauthority"
	"lindm/internal/testdb"
)

func signedRpmFixture(t *testing.T, name string) *inventoryv1.Package {
	t.Helper()
	raw, err := os.ReadFile("../rpmauthority/testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ ImmutableHeader, Signature []byte }
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	i, err := rpmauthority.Parse(f.ImmutableHeader)
	if err != nil {
		t.Fatal(err)
	}
	return &inventoryv1.Package{Name: i.Name, Version: i.Version, Architecture: i.Architecture, Manager: "rpm", SourceName: i.SourceName, SourceVersion: i.SourceVersion, SourceArchitecture: i.SourceArchitecture, Module: i.Module, RpmAuthority: &inventoryv1.RpmAuthority{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, ImmutableHeader: f.ImmutableHeader, Signature: f.Signature}}
}

// Product declarations below are authored controlled matching inputs, NOT
// claimed vendor advisories. RPM signatures and installed identities are real;
// closed-feed acquisition/signature/completeness has separate feed tests.
func completeRhelFixture(t *testing.T, pool *pgxpool.Pool, release string, packages ...*inventoryv1.Package) (*Service, *advisoryv1.FeedSource, *advisoryv1.FeedDocument) {
	t.Helper()
	source := &advisoryv1.FeedSource{Id: "controlled-rhel-" + release, Distro: "rhel", Release: release, PlatformStream: "standard", Architecture: "x86_64", Format: advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF, Url: "https://security.access.redhat.com/data/csaf/v2/", MaxAgeSeconds: 86400}
	s, err := New(t.Context(), pool, &configv1.AdvisoryConfig{Feeds: []*advisoryv1.FeedSource{source}}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("controlled complete RHEL product declaration fixture " + release))
	doc := &advisoryv1.FeedDocument{SourceSha256: digest[:], CompleteSnapshot: true}
	for _, p := range packages {
		doc.Advisories = append(doc.Advisories, &advisoryv1.Advisory{Id: "SYNTHETIC-RHEL-" + p.Name, PackageName: p.Name, ComponentVersion: p.Version, FixedVersion: "99:99-1", Architecture: p.Architecture, PlatformRelease: release, PlatformStream: "standard", ModuleName: p.GetModule().GetName(), ModuleStream: p.GetModule().GetStream(), Severity: "high", Cves: []string{"CVE-2099-99030"}, SourceUrl: source.Url})
	}
	return s, source, doc
}

func TestCompleteRHELNativeCoverageAndThirdPartyGapsPersist(t *testing.T) {
	for _, release := range []string{"9", "10"} {
		t.Run(release, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			fixture := "dbus"
			if release == "10" {
				fixture = "dbus10"
			}
			native := signedRpmFixture(t, fixture)
			thirdParty := &inventoryv1.Package{Name: "epel-unassessed-addon", Version: "0:1-1.el" + release, Architecture: "aarch64", Manager: "rpm", Module: &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}}
			s, source, doc := completeRhelFixture(t, pool, release, native)
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			id := seedInventory(t, pool, "rhel", release, native, thirdParty)
			seedRHELPlatform(t, pool, id, release, "standard")
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || out.Freshness.UncoveredPackages != 1 || len(out.Findings) != 1 || out.Findings[0].PackageName != native.Name || out.Findings[0].State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
				t.Fatalf("complete feed lost bounded native coverage: %v", out)
			}
			// A new service instance reads only persisted finding-set and uncovered
			// rows, not the first instance's matching state or an in-memory cache.
			reopened, err := New(t.Context(), pool, s.config, http.DefaultClient)
			if err != nil {
				t.Fatal(err)
			}
			reasons, fresh := uncoveredReasons(t, reopened, id, 1)
			if len(reasons) != 1 || reasons[thirdParty.Name] != "rpm_authority_unavailable" || fresh.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL {
				t.Fatalf("uncovered projection not durable: %v %v", reasons, fresh)
			}
			var raw []byte
			var signer string
			if err := pool.QueryRow(t.Context(), `SELECT p.rpm_authority,p.rpm_signer FROM snapshot_packages p JOIN enrollment_generations g ON g.current_snapshot_id=p.snapshot_id JOIN devices d ON d.current_generation_id=g.id WHERE d.id=$1 AND p.position=0`, id).Scan(&raw, &signer); err != nil {
				t.Fatal(err)
			}
			want, err := proto.MarshalOptions{Deterministic: true}.Marshal(native.RpmAuthority)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, want) || signer != rpmauthority.Fingerprint {
				t.Fatal("native proof bytes or server-verifying signer were not retained")
			}
			// Equal names, versions, source and module with absent evidence must
			// not share the native finding set or inherit its clean/affected result.
			historical := proto.CloneOf(native)
			historical.RpmAuthority = nil
			oldID := seedInventory(t, pool, "rhel", release, historical)
			seedRHELPlatform(t, pool, oldID, release, "standard")
			old, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: oldID.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if old.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || old.Freshness.Reason != "rhel_no_covered_packages" || old.Freshness.UncoveredPackages != 1 || len(old.Findings) != 0 {
				t.Fatalf("historical evidence inherited authority: %v", old)
			}
			reasons, fresh = uncoveredReasons(t, s, oldID, 1)
			if reasons[native.Name] != "rpm_authority_unavailable" || fresh.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || fresh.UncoveredPackages != 1 {
				t.Fatalf("historical gap hidden: %v %v", reasons, fresh)
			}
		})
	}
}

func TestRHELScopedVendorRejectionDoesNotPoisonOtherPackages(t *testing.T) {
	pool, _ := testdb.Open(t)
	native, sourceBinary := signedRpmFixture(t, "dbus"), signedRpmFixture(t, "fuse-common")
	s, source, doc := completeRhelFixture(t, pool, "9", native, sourceBinary)
	// Exact binary membership is independent of the signed source alias.
	// An unversioned source assessment can apply without inventing an epoch.
	doc.Advisories[1].NotAffected = true
	doc.Advisories[1].FixedVersion = ""
	doc.Advisories = append(doc.Advisories, &advisoryv1.Advisory{Id: "SYNTHETIC-RHEL-SOURCE", PackageName: sourceBinary.SourceName, SourcePackage: true, Architecture: sourceBinary.SourceArchitecture, PlatformRelease: "9", PlatformStream: "standard", Severity: "medium", Cves: []string{"CVE-2099-99031"}, SourceUrl: source.Url})
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := seedInventory(t, pool, "rhel", "9.8", native, sourceBinary)
	seedRHELPlatform(t, pool, id, "9.8", "standard")
	out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 2 || out.Freshness.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatalf("independently proven binary/source alias was not covered: %v", out)
	}
	doc.RejectedRecords = []*advisoryv1.RejectedRecord{{Id: "SYNTHETIC-REJECTED-COMPONENT", Reason: "vendor_component_unusable", PackageNames: []string{sourceBinary.SourceName}}}
	for _, isSource := range []bool{false, true} {
		doc.Advisories = append(doc.Advisories, &advisoryv1.Advisory{Id: "SYNTHETIC-REJECTED-COMPONENT", PackageName: sourceBinary.SourceName, SourcePackage: isSource, AssessmentUnknown: true, SourceRecordRejected: true, PlatformRelease: "9", PlatformStream: "standard", SourceUrl: source.Url})
	}
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	out, err = listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || out.Freshness.UncoveredPackages != 1 || len(out.Findings) != 1 || out.Findings[0].PackageName != native.Name {
		t.Fatalf("bounded rejection poisoned unrelated package: %v", out)
	}
	reasons, _ := uncoveredReasons(t, s, id, 1)
	if reasons[sourceBinary.Name] != "source_record_rejected" {
		t.Fatalf("matched malformed vendor component hidden: %v", reasons)
	}
	// With no proved component scope, the complete-source assertion is lost
	// regardless of the valid packages and their exact product declarations.
	doc.RejectedRecords[0].Unscoped = true
	doc.RejectedRecords[0].PackageNames = nil
	if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	out, err = listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "feed_partial_coverage" || out.Freshness.UncoveredPackages != 1 {
		t.Fatalf("unscoped rejection claimed coverage: %v", out)
	}
	reasons, unknownFresh := uncoveredReasons(t, s, id, 1)
	if reasons[sourceBinary.Name] != "source_record_rejected" || unknownFresh.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || unknownFresh.UncoveredPackages != 1 {
		t.Fatalf("unscoped source hid known bounded gap: %v %v", reasons, unknownFresh)
	}
}

func TestRHELUnsignedForgedSourceAndModuleRemainExplicitUncovered(t *testing.T) {
	for _, kind := range []string{"unsigned", "unknown-signature", "source-forgery", "source-architecture-forgery", "module-forgery", "no-product-membership", "source-only-membership", "module-product-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			native := signedRpmFixture(t, "dbus")
			s, source, doc := completeRhelFixture(t, pool, "9", native)
			reason := ""
			switch kind {
			case "unsigned":
				native.RpmAuthority.Signature = nil
				reason = "rpm_unsigned"
			case "unknown-signature":
				native.RpmAuthority.Signature[len(native.RpmAuthority.Signature)-1] ^= 1
				reason = "rpm_signature_unverified"
			case "source-forgery":
				native.SourceName = "openssl"
				reason = "rpm_identity_mismatch"
			case "source-architecture-forgery":
				native.SourceArchitecture = "nosrc"
				reason = "rpm_identity_mismatch"
			case "module-forgery":
				native.Module.Modular = true
				native.Module.Name = "nodejs"
				native.Module.Stream = "18"
				native.Module.Version = "9020020240101000000"
				native.Module.Context = "abcdef01"
				reason = "rpm_identity_mismatch"
			case "no-product-membership":
				doc.Advisories = nil
				reason = rhelMembershipUnproved
			case "source-only-membership":
				r := doc.Advisories[0]
				r.PackageName = native.SourceName
				r.SourcePackage = true
				r.Architecture = native.SourceArchitecture
				r.ComponentVersion = "0:" + native.SourceVersion
				r.FixedVersion = ""
				r.NotAffected = true
				reason = rhelMembershipUnproved
			case "module-product-mismatch":
				doc.Advisories[0].ModuleName = "nodejs"
				doc.Advisories[0].ModuleStream = "18"
				reason = rhelMembershipUnproved
			}
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			id := seedInventory(t, pool, "rhel", "9.8", native)
			seedRHELPlatform(t, pool, id, "9.8", "standard")
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "rhel_no_covered_packages" || out.Freshness.UncoveredPackages != 1 || len(out.Findings) != 0 {
				t.Fatalf("unproved identity/product got clean or affected authority: %v", out)
			}
			reasons, _ := uncoveredReasons(t, s, id, 1)
			if len(reasons) != 1 || reasons[native.Name] != reason {
				t.Fatalf("uncovered reason = %v, want %s", reasons, reason)
			}
		})
	}
}

func TestRHELGenuinePairedSourceAndBinaryAssessments(t *testing.T) {
	// Authentic, unchanged RHSA-2024:6783 enumerates source epoch1 and exact
	// binary epoch1 together. Its matching genuine RPM is already fixed.
	// Only the generation-completeness wrapper and negative normalized-claim
	// mutations are controlled test inputs; this is not a one-document feed
	// acquisition/completeness assertion.
	for _, kind := range []string{"genuine-pair", "other-source-document", "other-source-cve", "binary-module-mismatch", "binary-architecture-mismatch", "source-without-binary-assessment", "binary-negative-other-version", "binary-negative-installed-version"} {
		t.Run(kind, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			native := signedRpmFixture(t, "openssl")
			s, source, controlled := completeRhelFixture(t, pool, "9", native)
			controlled.Advisories[0].NotAffected = true
			controlled.Advisories[0].FixedVersion = ""
			raw, err := os.ReadFile("feed/testdata/redhat-rhsa-2024_6783.json")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := feed.Parse(source, bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			var kept []*advisoryv1.Advisory
			var sources, binaries int
			for _, record := range doc.Advisories {
				if record.GetSourcePackage() && record.GetPackageName() == native.SourceName {
					sources++
					if record.GetComponentVersion() != "1:"+native.SourceVersion {
						t.Fatalf("genuine source epoch changed: %v", record)
					}
					switch kind {
					case "other-source-document":
						record.Id = "SYNTHETIC-SOURCE-OTHER-DOCUMENT"
					case "other-source-cve":
						record.Cves = []string{"CVE-2099-99039"}
					}
				}
				if !record.GetSourcePackage() && record.GetPackageName() == native.Name && record.GetArchitecture() == native.Architecture {
					binaries++
					switch kind {
					case "binary-negative-other-version", "binary-negative-installed-version":
						version := native.Version
						if kind == "binary-negative-other-version" {
							version = "1:3.0.7-29.el9_4"
						}
						record.NotAffected = true
						record.FixedVersion = ""
						record.ComponentVersion = version
						record.IntroducedVersion = version
						record.LastAffectedVersion = version
					case "binary-module-mismatch":
						record.ModuleName = "nodejs"
						record.ModuleStream = "18"
					case "binary-architecture-mismatch":
						record.Architecture = "aarch64"
					case "source-without-binary-assessment":
						continue
					}
				}
				kept = append(kept, record)
			}
			if sources == 0 || binaries == 0 {
				t.Fatal("retained authentic document did not produce paired source/binary claims")
			}
			doc.Advisories = append(kept, controlled.Advisories...)
			doc.CompleteSnapshot = true
			digest := sha256.Sum256(append(raw, []byte(kind)...))
			doc.SourceSha256 = digest[:]
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			id := seedInventory(t, pool, "rhel", "9.8", native)
			seedRHELPlatform(t, pool, id, "9.8", "standard")
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if kind == "genuine-pair" || kind == "binary-negative-installed-version" {
				if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR || out.Freshness.UncoveredPackages != 0 || len(out.Findings) != 0 {
					t.Fatalf("genuine fixed binary claim did not supersede redundant source range: %v", out)
				}
			} else {
				if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.UncoveredPackages != 1 || len(out.Findings) != 0 {
					t.Fatalf("unproved source comparison silently produced clean: %v", out)
				}
				reasons, _ := uncoveredReasons(t, s, id, 1)
				if reasons[native.Name] != "rpm_source_epoch_unavailable" {
					t.Fatalf("source epoch uncertainty hidden: %v", reasons)
				}
			}
		})
	}
}

func TestRHELSourceFixedOnlyMinimumEpochBoundPersists(t *testing.T) {
	for _, clear := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "minimum-proves-clear"}[clear], func(t *testing.T) {
			pool, _ := testdb.Open(t)
			native, unrelated := signedRpmFixture(t, "dbus"), signedRpmFixture(t, "fuse-common")
			s, source, doc := completeRhelFixture(t, pool, "9", native, unrelated)
			fixed := "1:1-1"
			if clear {
				fixed = "0:" + native.SourceVersion
			}
			doc.Advisories = append(doc.Advisories, &advisoryv1.Advisory{Id: "SYNTHETIC-SOURCE-MINIMUM-BOUND", PackageName: native.SourceName, SourcePackage: true, Architecture: native.SourceArchitecture, ComponentVersion: fixed, FixedVersion: fixed, PlatformRelease: "9", PlatformStream: "standard", Cves: []string{"CVE-2099-99038"}, SourceUrl: source.Url})
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			id := seedInventory(t, pool, "rhel", "9.8", native, unrelated)
			seedRHELPlatform(t, pool, id, "9.8", "standard")
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if clear {
				if out.Freshness.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || out.Freshness.UncoveredPackages != 0 || len(out.Findings) != 2 {
					t.Fatalf("valid source lower bound was not usable: %v", out)
				}
			} else {
				if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || out.Freshness.UncoveredPackages != 1 || len(out.Findings) != 1 || out.Findings[0].PackageName != unrelated.Name {
					t.Fatalf("source epoch gap poisoned unrelated package or hid uncertainty: %v", out)
				}
				reasons, _ := uncoveredReasons(t, s, id, 1)
				if reasons[native.Name] != "rpm_source_epoch_unavailable" {
					t.Fatal(reasons)
				}
			}
		})
	}
}

func TestRHELCoverageDoesNotCountImportedRPMKeysAsPackages(t *testing.T) {
	for _, kind := range []string{"covered", "historical", "keyring-only"} {
		t.Run(kind, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			native := signedRpmFixture(t, "dbus")
			s, source, doc := completeRhelFixture(t, pool, "9", native)
			if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			key := &inventoryv1.Package{Name: "gpg-pubkey", Version: "0:fd431d51-4ae0493b", Manager: "rpm", Module: &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}}
			packages := []*inventoryv1.Package{key}
			if kind != "keyring-only" {
				if kind == "historical" {
					native.RpmAuthority = nil
				}
				packages = append(packages, native)
			}
			id := seedInventory(t, pool, "rhel", "9.8", packages...)
			seedRHELPlatform(t, pool, id, "9.8", "standard")
			out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "covered":
				if out.Freshness.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL || out.Freshness.UncoveredPackages != 0 || len(out.Findings) != 1 {
					t.Fatalf("keyring entry became a false coverage gap: %v", out)
				}
			case "historical":
				if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.UncoveredPackages != 1 {
					t.Fatalf("keyring entry hid absence of every covered package: %v", out)
				}
				reasons, _ := uncoveredReasons(t, s, id, 1)
				if len(reasons) != 1 || reasons[native.Name] != "rpm_authority_unavailable" {
					t.Fatal(reasons)
				}
			case "keyring-only":
				if out.Freshness.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || out.Freshness.Reason != "rhel_no_covered_packages" || out.Freshness.UncoveredPackages != 0 {
					t.Fatalf("no installable packages became clean: %v", out)
				}
			}
		})
	}
}

// A false policy decision models a root becoming revoked/expired after a valid
// evaluation. Actual cryptographic root-policy decisions are independently
// exercised in rpmauthority; these assertions exercise the durable read paths
// without mutating the pinned production trust root or stored evaluations.
func TestRHELFleetReadsRequireCurrentSigningAuthority(t *testing.T) {
	for _, release := range []string{"9", "10"} {
		for _, kind := range []string{"clear", "affected", "accepted", "partial"} {
			t.Run(release+"/"+kind, func(t *testing.T) {
				pool, _ := testdb.Open(t)
				fixture := "dbus"
				if release == "10" {
					fixture = "dbus10"
				}
				native := signedRpmFixture(t, fixture)
				s, source, doc := completeRhelFixture(t, pool, release, native)
				if kind == "clear" {
					doc.Advisories[0].NotAffected = true
					doc.Advisories[0].FixedVersion = ""
				}
				if err := s.publish(t.Context(), source, doc, time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
				packages := []*inventoryv1.Package{native}
				if kind == "partial" {
					packages = append(packages, &inventoryv1.Package{Name: "third-party-addon", Version: "0:1-1", Architecture: "x86_64", Manager: "rpm", Module: &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}})
				}
				id := seedInventory(t, pool, "rhel", release, packages...)
				seedRHELPlatform(t, pool, id, release, "standard")
				out, err := listEvaluated(t, s, &adminv1.ListDeviceFindingsRequest{DeviceId: id.String()}, true, []byte("[]"))
				if err != nil {
					t.Fatal(err)
				}
				if kind == "accepted" {
					if len(out.Findings) != 1 {
						t.Fatalf("expected one finding before acceptance: %v", out)
					}
					actor := uuid.New()
					if _, err := pool.Exec(t.Context(), `INSERT INTO principals(id,issuer,subject) VALUES($1,'https://advisory.test',$2)`, actor, actor.String()); err != nil {
						t.Fatal(err)
					}
					acceptFinding(t, s, actor, &adminv1.AcceptAdvisoryFindingRequest{RequestId: uuid.NewString(), DeviceId: id.String(), FindingId: out.Findings[0].Id, Reason: "Controlled root-policy regression", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))})
				}
				req := &adminv1.ListAdvisorySummaryRequest{}
				trusted, err := s.summary(t.Context(), req, true, []byte("[]"), true)
				if err != nil {
					t.Fatal(err)
				}
				if trusted.UnknownDevices != 0 || trusted.EvaluatedDevices+trusted.PartialDevices != 1 || (kind == "partial" && trusted.PartialDevices != 1) {
					t.Fatalf("fixture was not current before root-policy change: %v", trusted)
				}
				var before string
				if err := pool.QueryRow(t.Context(), `SELECT state FROM advisory_evaluations WHERE device_id=$1`, id).Scan(&before); err != nil {
					t.Fatal(err)
				}
				untrusted, err := s.summary(t.Context(), req, true, []byte("[]"), false)
				if err != nil {
					t.Fatal(err)
				}
				if untrusted.UnknownDevices != 1 || untrusted.EvaluatedDevices != 0 || untrusted.PartialDevices != 0 || len(untrusted.UncheckedGroups) != 1 || untrusted.UncheckedGroups[0].Devices != 1 {
					t.Fatalf("invalid root retained trusted fleet population: %v", untrusted)
				}
				for _, row := range untrusted.Advisories {
					if row.UnknownDevices != 1 || row.AcceptedDevices != 0 || row.AffectedDevices != 0 {
						t.Fatalf("invalid root retained affected/accepted authority: %v", row)
					}
				}
				if kind != "clear" && len(untrusted.Advisories) != 1 {
					t.Fatalf("invalid root lost retained unknown finding: %v", untrusted)
				}
				hidden, err := s.summary(t.Context(), req, false, []byte("[]"), false)
				if err != nil || hidden.UnknownDevices != 0 || len(hidden.Advisories) != 0 || len(hidden.UncheckedGroups) != 0 {
					t.Fatalf("root-policy guard leaked scoped devices: %v %v", hidden, err)
				}
				q := advisorydb.New(pool)
				groups, err := q.ListAdvisoryUncheckedGroups(t.Context(), advisorydb.ListAdvisoryUncheckedGroupsParams{ScopeUnrestricted: true, Scopes: []byte("[]"), RpmAuthorityValid: false})
				if err != nil || len(groups) != 1 || groups[0].Reason != "rpm_authority_unavailable" || groups[0].FeedID != source.Id {
					t.Fatalf("root-policy unchecked reason drift: %v %v", groups, err)
				}
				totals, err := q.CountDeviceAdvisoryFindings(t.Context(), advisorydb.CountDeviceAdvisoryFindingsParams{DeviceID: id, RpmAuthorityValid: false})
				if err != nil || totals.Accepted != 0 {
					t.Fatalf("invalid root retained accepted device totals: %v %v", totals, err)
				}
				dq := devicedb.New(pool)
				population, err := dq.FleetSummaryAdvisoryDevices(t.Context(), devicedb.FleetSummaryAdvisoryDevicesParams{ScopeUnrestricted: true, Scopes: []byte("[]"), RpmAuthorityValid: false})
				if err != nil || population.Total != 1 || population.Evaluated != 0 || population.Partial != 0 {
					t.Fatalf("directory fleet population retained trusted root: %v %v", population, err)
				}
				findings, err := dq.FleetSummaryFindings(t.Context(), devicedb.FleetSummaryFindingsParams{ScopeUnrestricted: true, Scopes: []byte("[]"), RpmAuthorityValid: false})
				if err != nil || findings.CriticalFindings != 0 || findings.HighFindings != 0 || findings.MediumFindings != 0 || findings.LowFindings != 0 || findings.OtherFindings != 0 {
					t.Fatalf("directory fleet severity retained trusted root: %v %v", findings, err)
				}
				search := devicedb.SearchDevicesParams{ScopeUnrestricted: true, Scopes: []byte("[]"), RpmAuthorityValid: false, UpperEnrolledAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MetadataFilter: []byte("{}"), ComplianceRanks: []int32{}, PatchBuckets: []string{}, PatchStaleAfterSeconds: 86400, RowLimit: 10}
				devices, err := dq.SearchDevices(t.Context(), search)
				if err != nil || len(devices) != 1 || devices[0].FindingsChecked || devices[0].FindingsPartial || devices[0].FindingsHigh != 0 {
					t.Fatalf("directory posture retained trusted root: %v %v", devices, err)
				}
				if kind == "affected" || kind == "partial" {
					search.AdvisoryID = doc.Advisories[0].Id
					search.AdvisorySeverity = doc.Advisories[0].Severity
					search.RpmAuthorityValid = true
					devices, err = dq.SearchDevices(t.Context(), search)
					if err != nil || len(devices) != 1 {
						t.Fatalf("valid-root advisory drilldown missing: %v %v", devices, err)
					}
					search.RpmAuthorityValid = false
					devices, err = dq.SearchDevices(t.Context(), search)
					if err != nil || len(devices) != 0 {
						t.Fatalf("invalid-root advisory drilldown remained trusted: %v %v", devices, err)
					}
				}
				var after string
				if err := pool.QueryRow(t.Context(), `SELECT state FROM advisory_evaluations WHERE device_id=$1`, id).Scan(&after); err != nil || after != before {
					t.Fatalf("read-time policy guard mutated persisted evaluation: %q -> %q: %v", before, after, err)
				}
			})
		}
	}
}

func TestRPMReadPolicyDoesNotChangeOtherPlatforms(t *testing.T) {
	pool, _ := testdb.Open(t)
	for _, fixture := range []struct {
		os, release string
		want        bool
	}{
		{"rhel", "9", false}, {"rhel", "9.8", false}, {"rhel", "10.2", false},
		{"rhel", "8.10", true}, {"rocky", "9.8", true}, {"ubuntu", "24.04", true}, {"fedora", "44", true},
	} {
		var current bool
		if err := pool.QueryRow(t.Context(), `SELECT advisory_rpm_authority_current($1,$2,false)`, fixture.os, fixture.release).Scan(&current); err != nil || current != fixture.want {
			t.Fatalf("policy scope %s/%s: %t, want %t: %v", fixture.os, fixture.release, current, fixture.want, err)
		}
	}
}
