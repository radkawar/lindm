// SPDX-License-Identifier: Apache-2.0

package deploylab

import (
	"strings"
	"testing"
	"time"
)

func findingsBrowserProof() (BrowserRequest, BrowserEvidence) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	source := AdvisorySource{Distro: "ubuntu", Release: "24.04", SourceURL: "https://vendor.invalid/export.zip"}
	request := BrowserRequest{Phase: "findings", DeviceID: "same-device", ManagedActionID: "new-managed-action", AdvisorySources: []AdvisorySource{source}, FindingsWaitMilliseconds: InitialFindingsWait.Milliseconds()}
	evidence := BrowserEvidence{Phase: "findings", Passed: true, BrowserVersion: "Chromium", PasswordAndPasskey: true, DeviceID: request.DeviceID, Screenshots: []string{"masked.png"}, Findings: &FindingsEvidence{
		SnapshotID: "b0b7a78e-07b1-419b-80ae-bd95e67d6694", InventorySequence: 3, FeedID: "automatic-vendor", Source: source, SourceSHA256: strings.Repeat("a", 64),
		FeedCheckedAt: now.Add(-time.Minute), FeedExpiresAt: now.Add(time.Hour), AdvisoryCount: 123, InventoryAt: now.Add(-30 * time.Second), InventoryExpiresAt: now.Add(time.Hour), ObservedAt: now,
		State: "ADVISORY_FINDING_STATE_CLEAR", CompleteCoverage: true,
	}}
	return request, evidence
}

func TestFindingsEvidenceRequiresPublishedCurrentManagedEvaluation(t *testing.T) {
	request, complete := findingsBrowserProof()
	if err := ValidateBrowserEvidence(request, &complete); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*BrowserEvidence){
		func(e *BrowserEvidence) { e.PasswordAndPasskey = false },
		func(e *BrowserEvidence) { e.DeviceID = "other-device" },
		func(e *BrowserEvidence) { e.Findings.SnapshotID = "" },
		func(e *BrowserEvidence) { e.Findings.Source.SourceURL = "https://different.invalid/export" },
		func(e *BrowserEvidence) { e.Findings.Source.PlatformStream = "eus" },
		func(e *BrowserEvidence) { e.Findings.SourceSHA256 = "" },
		func(e *BrowserEvidence) { e.Findings.AdvisoryCount = 0 },
		func(e *BrowserEvidence) { e.Findings.FeedExpiresAt = e.Findings.ObservedAt },
		func(e *BrowserEvidence) { e.Findings.InventoryExpiresAt = e.Findings.ObservedAt },
		func(e *BrowserEvidence) { e.Findings.State = "ADVISORY_FINDING_STATE_UNKNOWN" },
		func(e *BrowserEvidence) { e.Findings.Totals.Open = 1 },
	} {
		evidence := complete
		copy := *complete.Findings
		evidence.Findings = &copy
		mutate(&evidence)
		if err := ValidateBrowserEvidence(request, &evidence); err == nil {
			t.Fatal("unpublished, mismatched, stale or unknown findings qualified")
		}
	}
	request.ManagedActionID = ""
	if err := ValidateBrowserEvidence(request, &complete); err == nil {
		t.Fatal("enrollment alone qualified as managed inventory")
	}
}

func TestFindingsEvidencePreservesExplicitPartialCoverage(t *testing.T) {
	request, evidence := findingsBrowserProof()
	evidence.Findings.State = "ADVISORY_FINDING_STATE_PARTIAL"
	evidence.Findings.Reason = "package_origin_uncovered"
	evidence.Findings.UncoveredPackages = 7
	if err := ValidateBrowserEvidence(request, &evidence); err == nil {
		t.Fatal("partial evaluation labelled complete qualified")
	}
	evidence.Findings.CompleteCoverage = false
	if err := ValidateBrowserEvidence(request, &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.Findings.Reason = ""
	if err := ValidateBrowserEvidence(request, &evidence); err == nil {
		t.Fatal("unexplained partial coverage qualified")
	}
}

func TestColdFindingsDeadlineDoesNotChangeOtherPhases(t *testing.T) {
	request, _ := findingsBrowserProof()
	if got := BrowserTimeout(request); got != 95*time.Minute {
		t.Fatalf("cold findings timeout %v", got)
	}
	request.FindingsWaitMilliseconds = SubsequentFindingsWait.Milliseconds()
	if got := BrowserTimeout(request); got != 20*time.Minute {
		t.Fatalf("subsequent findings timeout %v", got)
	}
	request.Phase = "manage"
	if got := BrowserTimeout(request); got != 10*time.Minute {
		t.Fatalf("ordinary phase timeout changed: %v", got)
	}
}
