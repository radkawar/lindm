// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestAssistanceHotUnplugRejectsUnrelatedSessionEnds(t *testing.T) {
	for _, cause := range []agentv1.AssistanceEndCause{
		agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_EXPIRED,
		agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED,
		agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED,
		agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED,
	} {
		if acceptedAssistanceUnplugEnd(cause, "capture_exited") {
			t.Fatalf("unrelated terminal cause qualified unplug: %s", cause)
		}
	}
	if acceptedAssistanceUnplugEnd(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "unrelated_encoder_failure") {
		t.Fatal("unrelated failure qualified hot-unplug")
	}
	if !acceptedAssistanceUnplugEnd(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, "capture_exited") || !acceptedAssistanceUnplugEnd(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_PORTAL_CLOSED, "portal_session_closed") {
		t.Fatal("documented native selected-stream terminal path rejected")
	}
}

func TestAssistanceRefusalNeedsUnchangedNativeClipboard(t *testing.T) {
	const nonce = "111111111111111111111111"
	scenario := &assistanceScenarioEvidence{Name: "clipboard", SessionID: "session", LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	boundary := &assistanceNativeBoundary{
		Boundary: "clipboard-session-end-refused", SessionID: "session", ObservedAt: time.Now(),
		RequestID: "11111111-1111-4111-8111-111111111111", Code: "failed_precondition", Reason: "assistance_ended", HTTPStatus: 400,
		ClipboardBefore: nonce, ClipboardAfter: nonce,
		Guest:       &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123, Pasted: nonce, PasteSerial: 2},
		GuestBefore: &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123, Pasted: nonce, PasteSerial: 1},
	}
	if err := verifyAssistanceNativeBoundary(scenario, boundary); err != nil {
		t.Fatal(err)
	}
	boundary.Guest.Pasted = "changed"
	if err := verifyAssistanceNativeBoundary(scenario, boundary); err == nil {
		t.Fatal("RPC refusal alone qualified unchanged native clipboard")
	}
	boundary.Guest.Pasted = nonce
	boundary.Reason = "assistance_not_creator"
	if err := verifyAssistanceNativeBoundary(scenario, boundary); err == nil {
		t.Fatal("wrong actor denial substituted for ended-session refusal")
	}
}

func TestAssistanceTierOneRequiresEveryNativeBoundary(t *testing.T) {
	result := &VMAssistanceResult{}
	for _, scenario := range []string{"clipboard", "clipboard-limited", "clipboard-policy", "clipboard-permission", "keyboard", "monitors"} {
		evidence := &assistanceScenarioEvidence{Name: scenario}
		for _, name := range requiredAssistanceBoundaries(scenario) {
			result.BoundaryWitnesses = append(result.BoundaryWitnesses, assistanceEvidenceFile{Name: name, Path: name + ".json"})
			evidence.BoundaryWitnesses = append(evidence.BoundaryWitnesses, name+".json")
		}
		result.Scenarios = append(result.Scenarios, evidence)
	}
	if !completeAssistanceNativeBoundaries(result) {
		t.Fatal("complete boundary set rejected")
	}
	all := result.BoundaryWitnesses
	for i, boundary := range all {
		result.BoundaryWitnesses = append(append([]assistanceEvidenceFile{}, all[:i]...), all[i+1:]...)
		if completeAssistanceNativeBoundaries(result) {
			t.Fatalf("missing boundary %s qualified full Tier1", boundary.Name)
		}
	}
	result.BoundaryWitnesses = all
	result.Scenarios = nil
	if completeAssistanceNativeBoundaries(result) {
		t.Fatal("orphaned boundary artifacts qualified Tier1 without their scenarios")
	}
}
