// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/deploylab"
)

func TestDeployResultScopeCannotQualifyWithoutFindings(t *testing.T) {
	for _, without := range []bool{false, true} {
		for _, passed := range []bool{false, true} {
			result := &VMDeployResult{Passed: passed, Scope: "full-native", LifecycleQualified: true}
			setDeployResultScope(result, VMDeployOptions{WithoutFindings: without})
			body, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatal(err)
			}
			if record["findings_excluded"] != without || record["lifecycle_qualified"] != (passed && !without) || record["passed"] != passed {
				t.Fatalf("without=%t passed=%t: incorrect qualification: %s", without, passed, body)
			}
			if without && record["scope"] != deploylab.ServerLifecycleScope {
				t.Fatalf("scoped result lost its label: %s", body)
			}
			if !without && record["scope"] != nil {
				t.Fatalf("default full lane gained a restricted scope: %s", body)
			}
		}
	}
}

func TestDeployValidationFailureRetainsExplicitServerLifecycleScope(t *testing.T) {
	for _, without := range []bool{false, true} {
		result, err := DeployVM(t.Context(), &labv1.ImageManifest{}, VMDeployOptions{WithoutFindings: without})
		if err == nil || result == nil {
			t.Fatal("invalid manifest did not produce retained failure evidence")
		}
		if result.Passed || result.LifecycleQualified || result.OwnedCleanupComplete || result.Failure == "" || result.FinishedAt.IsZero() {
			t.Fatalf("failed deployment promoted to qualification: %+v", result)
		}
		if result.FindingsExcluded != without || (without && result.Scope != deploylab.ServerLifecycleScope) || (!without && result.Scope != "") {
			t.Fatalf("early failure lost explicit qualification scope: %+v", result)
		}
	}
}

func TestDeployManagedPhasesRequireCompletedFreshInventoryWithoutFindings(t *testing.T) {
	for _, stage := range []string{"installed", "upgraded", "restored"} {
		t.Run(stage, func(t *testing.T) {
			for _, without := range []bool{false, true} {
				request := deploylab.BrowserRequest{Phase: "manage", DeviceID: "original-device"}
				complete := deploylab.BrowserEvidence{Phase: "manage", Passed: true, BrowserVersion: "Chromium", DeviceID: request.DeviceID, ActionID: stage + "-action", ActionCompleted: true, ActionFinishedAt: time.Now(), FreshInventoryReceived: true, Screenshots: []string{"masked.png"}}
				for _, damage := range []func(*deploylab.BrowserEvidence){
					func(*deploylab.BrowserEvidence) {},
					func(e *deploylab.BrowserEvidence) { e.ActionCompleted = false },
					func(e *deploylab.BrowserEvidence) { e.FreshInventoryReceived = false },
					func(e *deploylab.BrowserEvidence) { e.DeviceID = "replacement-device" },
				} {
					evidence := complete
					damage(&evidence)
					managementErr := deploylab.ValidateBrowserEvidence(request, &evidence)
					managed, findings := false, false
					findingsErr := errors.New("independent findings failed")
					err := observeDeployManagedPhase(VMDeployOptions{WithoutFindings: without}, func() error {
						managed = true
						return managementErr
					}, func() error {
						findings = true
						return findingsErr
					})
					if !managed || findings != (managementErr == nil && !without) {
						t.Fatalf("without=%t: management or Findings observation incorrectly skipped", without)
					}
					if managementErr != nil && !errors.Is(err, managementErr) {
						t.Fatalf("management gate bypassed: %v", err)
					}
					if managementErr == nil && without && err != nil {
						t.Fatalf("excluded Findings blocked server lifecycle: %v", err)
					}
					if managementErr == nil && !without && !errors.Is(err, findingsErr) {
						t.Fatalf("default full lane bypassed Findings: %v", err)
					}
				}
			}
		})
	}
}
