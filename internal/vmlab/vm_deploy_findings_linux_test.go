// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"fmt"
	"testing"
	"time"

	"lindm/internal/deploylab"
	"lindm/internal/platform"
)

func nativeDeployFindingsProofs() []*VMDeployFindingsProof {
	var proofs []*VMDeployFindingsProof
	for index, stage := range []string{"installed", "upgraded", "restored"} {
		started := time.Date(2026, 10, 15, 12+index, 0, 0, 0, time.UTC)
		observed := started.Add(30 * time.Minute)
		findings := &deploylab.FindingsEvidence{SnapshotID: fmt.Sprintf("snapshot-%d", index), InventorySequence: uint64(index + 1), FeedID: "vendor", SourceSHA256: "digest", InventoryAt: started.Add(time.Minute), ObservedAt: observed, State: "ADVISORY_FINDING_STATE_CLEAR", CompleteCoverage: true}
		proofs = append(proofs, &VMDeployFindingsProof{
			Stage: stage, StartedAt: started, ObservedAt: observed, ElapsedMilliseconds: (30 * time.Minute).Milliseconds(),
			DeviceID: "original-device", ManagedActionID: fmt.Sprintf("action-%d", index), ManagedSnapshotID: findings.SnapshotID,
			SnapshotID: findings.SnapshotID, InventorySequence: findings.InventorySequence, PackageCount: 100,
			FeedID: findings.FeedID, SourceSHA256: findings.SourceSHA256, EvaluatedAt: started.Add(29 * time.Minute), EvaluationState: "evaluated", Findings: findings,
		})
	}
	return proofs
}

func TestNativeDeployFindingsRequireFreshOriginalDeviceProofAfterRestore(t *testing.T) {
	if err := validateDeployFindingsStages("original-device", nativeDeployFindingsProofs()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]*VMDeployFindingsProof){
		func(p []*VMDeployFindingsProof) { p[2].DeviceID = "new-device" },
		func(p []*VMDeployFindingsProof) { p[2].Stage = "upgraded" },
		func(p []*VMDeployFindingsProof) { p[2].ManagedActionID = p[0].ManagedActionID },
		func(p []*VMDeployFindingsProof) { p[2].EvaluatedAt = p[1].EvaluatedAt },
		func(p []*VMDeployFindingsProof) { p[2].SnapshotID = "unrelated-snapshot" },
		func(p []*VMDeployFindingsProof) { p[2].SourceSHA256 = "unrelated-source" },
		func(p []*VMDeployFindingsProof) { p[2].PackageCount = 0 },
		func(p []*VMDeployFindingsProof) { p[2].ManagedSnapshotID = "" },
		func(p []*VMDeployFindingsProof) { p[2].EvaluatedAt = time.Time{} },
		func(p []*VMDeployFindingsProof) { p[2].Findings.State = "ADVISORY_FINDING_STATE_UNKNOWN" },
		func(p []*VMDeployFindingsProof) { p[2].ElapsedMilliseconds = 1 },
	} {
		proofs := nativeDeployFindingsProofs()
		mutate(proofs)
		if err := validateDeployFindingsStages("original-device", proofs); err == nil {
			t.Fatal("missing, unknown, stale, mismatched or replayed restore findings qualified")
		}
	}
	if err := validateDeployFindingsStages("original-device", nativeDeployFindingsProofs()[:2]); err == nil {
		t.Fatal("lifecycle without restored findings qualified")
	}
}

func TestNativeDeployFindingsKeepPartialAssessmentMeaningful(t *testing.T) {
	proofs := nativeDeployFindingsProofs()
	proof := proofs[0]
	proof.Findings.State = "ADVISORY_FINDING_STATE_PARTIAL"
	proof.Findings.CompleteCoverage = false
	proof.Findings.UncoveredPackages = 7
	proof.Findings.Reason = "package_origin_uncovered"
	if err := validateDeployFindingsStages("original-device", proofs); err == nil {
		t.Fatal("browser partial assessment disagreed with durable evaluation but qualified")
	}
	proof.EvaluationState = "partial"
	if err := validateDeployFindingsStages("original-device", proofs); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDeployExpectedVendorIdentityComesFromRegistry(t *testing.T) {
	for _, test := range []struct{ key, version string }{{"ubuntu-24.04", "24.04"}, {"rhel-9", "9.8"}, {"debian-12", "12"}, {"debian-13", "13"}} {
		release, ok := platform.Lookup(test.key)
		if !ok {
			t.Fatal("native server platform missing")
		}
		sources, err := deployAdvisoryExpectations(release, test.version, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		if len(sources) != 1 {
			t.Fatal("expected exactly one maintained vendor export")
		}
		for index, source := range sources {
			export := release.Advisory.Exports[release.Advisory.Feeds[index]]
			if source.SourceURL != export.URL || source.PlatformStream != export.PlatformStream || source.Distro != release.ID {
				t.Fatal("native proof changed vendor source or stream identity")
			}
		}
	}
}

func TestNativeDeployVendorExpectationsFailClosedForAbsentOrInvalidExports(t *testing.T) {
	registered, ok := platform.Lookup("debian-13")
	if !ok {
		t.Fatal("native server platform missing")
	}
	release := *registered
	release.Advisory.Feeds = []platform.Feed{platform.FeedDebianTracker, platform.FeedOSV}
	if sources, err := deployAdvisoryExpectations(&release, "13", "x86_64"); err != nil || len(sources) != 1 || sources[0].SourceURL != registered.Advisory.Exports[platform.FeedOSV].URL {
		t.Fatalf("unexported feed hid the maintained vendor export: sources=%+v err=%v", sources, err)
	}
	release.Advisory.Exports = nil
	if _, err := deployAdvisoryExpectations(&release, "13", "x86_64"); err == nil {
		t.Fatal("missing maintained vendor exports admitted")
	}
	release.Advisory.Exports = map[platform.Feed]platform.AdvisoryExport{platform.FeedOSV: {Format: "osv-zip", MaxAgeSeconds: 86400}}
	if _, err := deployAdvisoryExpectations(&release, "13", "x86_64"); err == nil {
		t.Fatal("invalid maintained vendor export admitted")
	}
}
