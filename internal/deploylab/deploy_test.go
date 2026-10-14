// SPDX-License-Identifier: Apache-2.0

package deploylab

import (
	"testing"
	"time"
)

func TestManagementEvidenceRequiresLiveCompletedAction(t *testing.T) {
	request := BrowserRequest{Phase: "manage", DeviceID: "same-device"}
	complete := BrowserEvidence{Phase: "manage", Passed: true, BrowserVersion: "Chromium", DeviceID: request.DeviceID, ActionID: "new-action", ActionCompleted: true, ActionFinishedAt: time.Now(), FreshInventoryReceived: true, Screenshots: []string{"masked.png"}}
	if err := ValidateBrowserEvidence(request, &complete); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*BrowserEvidence){
		func(e *BrowserEvidence) { e.DeviceID = "other-device" },
		func(e *BrowserEvidence) { e.ActionID = "" },
		func(e *BrowserEvidence) { e.ActionCompleted = false },
		func(e *BrowserEvidence) { e.ActionFinishedAt = time.Time{} },
		func(e *BrowserEvidence) { e.FreshInventoryReceived = false },
		func(e *BrowserEvidence) { e.Screenshots = nil },
	} {
		evidence := complete
		mutation(&evidence)
		if err := ValidateBrowserEvidence(request, &evidence); err == nil {
			t.Fatal("database-only, mismatched or incomplete management evidence was admitted")
		}
	}
}

func TestSetupAndClipboardEvidenceAreIndependent(t *testing.T) {
	setup := BrowserEvidence{Phase: "setup", Passed: true, BrowserVersion: "Chromium", Screenshots: []string{"masked.png"}}
	if err := ValidateBrowserEvidence(BrowserRequest{Phase: "setup"}, &setup); err == nil {
		t.Fatal("password-only setup qualified")
	}
	setup.PasswordAndPasskey = true
	if err := ValidateBrowserEvidence(BrowserRequest{Phase: "setup"}, &setup); err != nil {
		t.Fatal(err)
	}
	copy := BrowserEvidence{Phase: "copy", Passed: true, BrowserVersion: "Chromium", Screenshots: []string{"masked.png"}, CommandSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", CommandSource: "response-field"}
	if err := ValidateBrowserEvidence(BrowserRequest{Phase: "copy"}, &copy); err == nil {
		t.Fatal("non-clipboard enrollment command qualified")
	}
	copy.CommandSource = "browser-clipboard"
	if err := ValidateBrowserEvidence(BrowserRequest{Phase: "copy"}, &copy); err != nil {
		t.Fatal(err)
	}
	copy.CommandSHA256 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	if err := ValidateBrowserEvidence(BrowserRequest{Phase: "copy"}, &copy); err == nil {
		t.Fatal("malformed clipboard digest qualified")
	}
}

func TestAuditCountsOnlyObservedOperatorBoundaries(t *testing.T) {
	commands, decisions, failures := Counts([]Operation{{Kind: "command", Passed: true}, {Kind: "decision", Passed: true}, {Kind: "command"}, {Kind: "harness", Passed: true}})
	if commands != 2 || decisions != 1 || failures != 1 {
		t.Fatalf("counts %d/%d/%d", commands, decisions, failures)
	}
}

func TestCustodyRequiresDigestBoundNewOwnerStepUp(t *testing.T) {
	request := BrowserRequest{Phase: "custody", CustodySHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", CustodyExports: []CustodyExport{{Kind: "canonical_authority", Path: "/protected/identities.age", SHA256: "observed-ciphertext"}}}
	complete := BrowserEvidence{Phase: "custody", Passed: true, BrowserVersion: "Chromium", Screenshots: []string{"masked.png"}, OwnerStepUp: true, OwnerCustodyAttested: true, CustodySHA256: request.CustodySHA256, CustodyExports: append([]CustodyExport(nil), request.CustodyExports...)}
	if err := ValidateBrowserEvidence(request, &complete); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*BrowserEvidence){
		func(e *BrowserEvidence) { e.OwnerStepUp = false },
		func(e *BrowserEvidence) { e.OwnerCustodyAttested = false },
		func(e *BrowserEvidence) { e.CustodySHA256 = "other-bundle" },
		func(e *BrowserEvidence) { e.CustodyExports = nil },
	} {
		evidence := complete
		mutate(&evidence)
		if err := ValidateBrowserEvidence(request, &evidence); err == nil {
			t.Fatal("unscoped login UV or unrelated custody confirmation qualified")
		}
	}
}
