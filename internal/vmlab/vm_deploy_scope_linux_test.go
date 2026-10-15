// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/deploylab"
	"lindm/internal/platform"
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

func TestDeployDeviceManifestSelectsIndependentNativeInventory(t *testing.T) {
	server, err := LoadManifest(filepath.Join("..", "..", "lab", "images", "rocky-9.8-x86_64.json"))
	if err != nil {
		t.Fatal(err)
	}
	device, err := LoadManifest(filepath.Join("..", "..", "lab", "images", "ubuntu-noble-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name           string
		supplied, want *labv1.ImageManifest
	}{
		{name: "default", want: server},
		{name: "explicit", supplied: device, want: device},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected, err := deployDeviceManifest(server, test.supplied)
			if err != nil || selected != test.want {
				t.Fatalf("selected device image = %v, %v", selected, err)
			}
		})
	}
	selected, err := deployDeviceManifest(server, device)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := deployAdvisoryExpectations(manifestRelease(selected), selected.Version, selected.Architecture)
	if err != nil || len(sources) == 0 {
		t.Fatalf("selected device has no real expected vendor source: %v", err)
	}
	for _, source := range sources {
		if source.Distro != "ubuntu" || source.Release != "24.04" {
			t.Fatalf("Findings borrowed the server's device coverage: %+v", source)
		}
	}
	if manifestRelease(server).Advisory.Partial == "" || server.Distribution != "rocky" {
		t.Fatal("independent managed device changed Rocky's device coverage")
	}
	device.Architecture = "arm64"
	if _, err := deployDeviceManifest(server, device); err == nil {
		t.Fatal("foreign device architecture admitted to native x86 deployment")
	}
	if _, err := deployDeviceManifest(server, &labv1.ImageManifest{}); err == nil {
		t.Fatal("invalid independent device manifest admitted")
	}
}

func TestDeployDeviceEntitlementInputDoesNotReachUnentitledGuest(t *testing.T) {
	const token = "/protected/redhat-token"
	for _, test := range []struct {
		server, device, input, want string
		refuse                      bool
	}{
		{server: "rhel-10", device: "ubuntu-24.04", input: token},
		{server: "ubuntu-24.04", device: "rhel-9", input: token, want: token},
		{server: "rhel-10", device: "rhel-9", input: token, want: token},
		{server: "rocky-9", device: "ubuntu-24.04"},
		{server: "rocky-9", device: "ubuntu-24.04", input: token, refuse: true},
		{server: "rhel-10", device: "ubuntu-24.04", refuse: true},
		{server: "ubuntu-24.04", device: "rhel-9", refuse: true},
	} {
		t.Run(test.server+"/"+test.device+"/"+test.input, func(t *testing.T) {
			server, ok := platform.Lookup(test.server)
			if !ok {
				t.Fatal("missing server fixture")
			}
			device, ok := platform.Lookup(test.device)
			if !ok {
				t.Fatal("missing managed-device fixture")
			}
			got, err := deployDeviceTokenFile(server, device, test.input)
			if (err != nil) != test.refuse || got != test.want {
				t.Fatalf("device entitlement input = %q, %v", got, err)
			}
		})
	}
}

func TestDeployIndependentDeviceStillRequiresFullFindings(t *testing.T) {
	for _, without := range []bool{false, true} {
		result := &VMDeployResult{Passed: true}
		setDeployResultScope(result, VMDeployOptions{DeviceManifest: &labv1.ImageManifest{Id: "independent-device"}, WithoutFindings: without})
		if result.FindingsExcluded != without || result.LifecycleQualified != !without {
			t.Fatalf("alternate device changed Findings qualification: %+v", result)
		}
	}
}
