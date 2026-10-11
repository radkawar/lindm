//go:build linux

package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/devlab"
	"lindm/internal/platform"
)

func TestVMAdvisoryInventoryDigestBindsCompleteMultiset(t *testing.T) {
	a := nativePackage{name: "one", version: "1:2-3", architecture: "x86_64", manager: "rpm", module: nativeModule{status: truthSuccess}}
	b := nativePackage{name: "two", version: "2-1", architecture: "noarch", manager: "rpm", sourceName: "source", sourceVersion: "2-1", module: nativeModule{status: truthSuccess}}
	first := map[nativePackage]int{a: 2, b: 1}
	second := make(map[nativePackage]int)
	second[b], second[a] = 1, 2
	rows, digest, err := vmAdvisoryInventory(first)
	if err != nil {
		t.Fatal(err)
	}
	_, same, err := vmAdvisoryInventory(second)
	if err != nil || digest != same || len(rows) != 3 {
		t.Fatalf("unstable complete multiset: rows=%d digest=%s second=%s error=%v", len(rows), digest, same, err)
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	if digest != hex.EncodeToString(expected[:]) {
		t.Fatal("inventory digest cannot be reproduced from recorded rows")
	}
	second[a] = 1
	_, changed, err := vmAdvisoryInventory(second)
	if err != nil || changed == digest {
		t.Fatalf("duplicate loss did not change digest: %v", err)
	}
	delete(second, b)
	b.sourceVersion = "3-1"
	second[b] = 1
	_, sourceChanged, err := vmAdvisoryInventory(second)
	if err != nil || sourceChanged == changed {
		t.Fatalf("source identity loss did not change digest: %v", err)
	}
	for _, invalid := range []map[nativePackage]int{nil, {a: 0}, {a: -1}, {a: 100001}} {
		if _, _, err := vmAdvisoryInventory(invalid); err == nil {
			t.Fatal("accepted empty or invalid inventory")
		}
	}
}

// Synthetic rows exercise the evidence acceptance boundary only. They are not
// vendor-feed fixtures and do not claim a native VM or production matcher pass.
func advisoryEvidenceForTest() *VMAdvisoryEvidence {
	digest := sha256.Sum256([]byte("unit-test transport bytes"))
	hash := hex.EncodeToString(digest[:])
	url := "https://vendor.example/export"
	return &VMAdvisoryEvidence{
		Source:    &advisoryv1.FeedSource{Id: "test-source", Url: url},
		Feed:      &adminv1.AdvisoryFeedStatus{Id: "test-source", SourceUrl: url, SourceSha256: hash, CheckedAt: timestamppb.New(time.Now()), ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), AdvisoryCount: 1, Fresh: true, Artifacts: []*advisoryv1.FeedArtifact{{Url: url, Sha256: digest[:]}}},
		Refresh:   &devlab.AcceptanceFeedResult{Artifacts: []devlab.AcceptanceFeedArtifact{{URL: url, SHA256: hash, Bytes: 25}}},
		Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED},
		Packages:  []*inventoryv1.Package{{Name: "native", Version: "1:2-3", Architecture: "x86_64", Manager: "rpm"}},
		Findings:  []*adminv1.AdvisoryFinding{{AdvisoryId: "vendor-1", FeedId: "test-source", SourceUrl: url, PackageName: "native", InstalledVersion: "1:2-3", Architecture: "x86_64", State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED}},
	}
}

func TestVMAdvisoryAcquisitionRequiresActualHashedPublication(t *testing.T) {
	if err := vmAdvisoryAcquisition(advisoryEvidenceForTest()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*VMAdvisoryEvidence){
		"empty publication":           func(e *VMAdvisoryEvidence) { e.Feed.AdvisoryCount = 0 },
		"failed publication":          func(e *VMAdvisoryEvidence) { e.Feed.Error = "parser_failed" },
		"no transport":                func(e *VMAdvisoryEvidence) { e.Refresh.Artifacts = nil },
		"changed transport digest":    func(e *VMAdvisoryEvidence) { e.Refresh.Artifacts[0].SHA256 = strings.Repeat("a", 64) },
		"different origin":            func(e *VMAdvisoryEvidence) { e.Refresh.Artifacts[0].URL = "https://other.example/export" },
		"empty body":                  func(e *VMAdvisoryEvidence) { e.Refresh.Artifacts[0].Bytes = 0 },
		"missing published artifacts": func(e *VMAdvisoryEvidence) { e.Feed.Artifacts = nil },
		"missing publication hash":    func(e *VMAdvisoryEvidence) { e.Feed.SourceSha256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			e := advisoryEvidenceForTest()
			mutate(e)
			if err := vmAdvisoryAcquisition(e); err == nil {
				t.Fatal("unbound publication accepted")
			}
		})
	}
}

func TestVMAdvisoryQualificationNeverPassesEmptyOrUnknown(t *testing.T) {
	e := advisoryEvidenceForTest()
	if err := qualifyVMAdvisoryMatches(e); err != nil || e.AffectedMatches != 1 || e.Outcome != "qualified_native_match" {
		t.Fatalf("bound positive evidence: %+v, %v", e, err)
	}
	for name, mutate := range map[string]func(*VMAdvisoryEvidence){
		"empty": func(e *VMAdvisoryEvidence) { e.Findings = nil },
		"fixed": func(e *VMAdvisoryEvidence) {
			e.Findings[0].State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR
		},
		"accepted risk": func(e *VMAdvisoryEvidence) {
			e.Findings[0].State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED
		},
		"unknown coverage": func(e *VMAdvisoryEvidence) {
			e.Freshness.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
		},
		"stale feed":         func(e *VMAdvisoryEvidence) { e.Feed.Fresh = false },
		"wrong version":      func(e *VMAdvisoryEvidence) { e.Findings[0].InstalledVersion = "2-3" },
		"wrong architecture": func(e *VMAdvisoryEvidence) { e.Findings[0].Architecture = "aarch64" },
		"wrong source":       func(e *VMAdvisoryEvidence) { e.Findings[0].FeedId = "other" },
		"not installed":      func(e *VMAdvisoryEvidence) { e.Packages = nil },
	} {
		t.Run(name, func(t *testing.T) {
			e := advisoryEvidenceForTest()
			mutate(e)
			if err := qualifyVMAdvisoryMatches(e); err == nil {
				t.Fatal("unqualified native match accepted")
			}
		})
	}
}

func TestVMAdvisoryPartialEmptyMatchRequiresIndependentBoundary(t *testing.T) {
	e := advisoryEvidenceForTest()
	e.Findings = nil
	e.PartialCoverage = "vendor omits historical records"
	e.Feed.Fresh = false
	e.Freshness.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
	e.Freshness.Reason = "feed_partial_coverage"
	if err := qualifyVMAdvisoryMatches(e); err == nil {
		t.Fatal("empty native matching passed without a positive independent oracle")
	}
	e.Boundary = &VMAdvisoryBoundaryEvidence{
		Input:             &devlab.PublishedAdvisoryBoundary{Claim: &advisoryv1.Advisory{FixedVersion: "2"}, VulnerableVersion: "1"},
		NativeComparisons: [3]int{-1, 0, 1}, ServerComparisons: [3]int{-1, 0, 1}, VulnerableMatched: true,
	}
	if err := qualifyVMAdvisoryMatches(e); err != nil || e.Scope != "partial-feed matching" || e.Freshness.GetState() != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		t.Fatalf("honest partial matching oracle: scope=%s error=%v", e.Scope, err)
	}
	e.Boundary.NativeComparisons[0] = 0
	if err := qualifyVMAdvisoryMatches(e); err == nil {
		t.Fatal("native/server comparator disagreement accepted")
	}
	e.Boundary.NativeComparisons[0] = -1
	e.Feed.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour))
	if err := qualifyVMAdvisoryMatches(e); err == nil {
		t.Fatal("partial coverage hid expired vendor evidence")
	}
}

func TestVMAdvisorySourceUsesRegistryExportAndArchitectureBoundary(t *testing.T) {
	registered, ok := platform.Lookup("arch")
	if !ok {
		t.Fatal("missing Arch registry row")
	}
	release := *registered
	// An isolated export tests derivation, not live vendor coverage. Its partial
	// declaration must not prevent recording the server's actual UNKNOWN result.
	release.Advisory.Exports = map[platform.Feed]platform.AdvisoryExport{release.Advisory.Feeds[0]: {URL: "https://vendor.example/arch.json", Format: "arch-json", MaxAgeSeconds: 86400}}
	source, err := vmAdvisorySource(&release, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if source.GetArchitecture() != "x86_64" || source.GetDistro() != release.ID || source.GetRelease() != "rolling" || source.GetUrl() != "https://vendor.example/arch.json" || source.GetFormat() != advisoryv1.FeedFormat_FEED_FORMAT_ARCH_JSON {
		t.Fatalf("incorrect primary export: %v", source)
	}
	alias, err := vmAdvisorySource(&release, "x86_64")
	if err != nil || !proto.Equal(source, alias) {
		t.Fatalf("architecture alias changed feed: %v", err)
	}
	if _, err := vmAdvisorySource(&release, "aarch64"); err == nil {
		t.Fatal("Arch Linux ARM silently inherited official Arch coverage")
	}
	release.Advisory.Exports = nil
	if _, err := vmAdvisorySource(&release, "x86_64"); err == nil {
		t.Fatal("invented missing primary export")
	}
}
