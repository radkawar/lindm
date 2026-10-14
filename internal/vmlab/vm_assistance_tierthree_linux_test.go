// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"testing"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

func tierThreeAudit(actions ...string) []assistanceAuditEvidence {
	rows := make([]assistanceAuditEvidence, 0, len(actions))
	for _, action := range actions {
		rows = append(rows, assistanceAuditEvidence{Action: action})
	}
	return rows
}

func completeElevationWitness() *assistanceTierThreeWitness {
	return &assistanceTierThreeWitness{Scenario: "elevation", Policy: assistanceTierThreePolicy(), Elevation: &assistanceElevationWitness{
		GuidanceOCR: "remote control paused for your password", ControlDisabled: true, ProbeEvents: 16, PkexecExit: "0", InputAfter: true,
		Paused:   &agentv1.AssistanceInputState{Epoch: 3, Paused: true, Pause: agentv1.AssistanceInputPause_ASSISTANCE_INPUT_PAUSE_ELEVATION},
		Resumed:  &agentv1.AssistanceInputState{Epoch: 4},
		Refusals: []assistanceRPCRefusal{{HTTPStatus: 400, Code: "failed_precondition", Reason: "assistance_input_paused"}, {HTTPStatus: 400, Code: "failed_precondition", Reason: "assistance_input_paused"}},
	}, Audit: tierThreeAudit("assistance.elevation.request", "assistance.elevation.pause", "assistance.elevation.resume")}
}

func overlayObservation(head int) assistanceOverlayObservation {
	return assistanceOverlayObservation{Head: head, Expected: [2]float64{0.3, 0.3}, Centroid: [2]float64{0.31, 0.29}, Pixels: 400}
}

func completeAnnotationWitness() *assistanceTierThreeWitness {
	stroke := assistanceOverlayObservation{Expected: [2]float64{0.6, 0.3}, Pixels: 300}
	return &assistanceTierThreeWitness{Scenario: "annotation", Policy: assistanceTierThreePolicy(), Annotation: &assistanceAnnotationWitness{
		Mode: "on", NoticeOCR: "support pointer on your screen", Pointer: []assistanceOverlayObservation{overlayObservation(0)}, Stroke: &stroke,
		LocalClick: &assistancePointerWitness{X: 0.3, Y: 0.3}, ConsoleHidden: true, Report: &agentv1.AssistanceAnnotationReport{Hidden: true, Clears: 1},
	}, Audit: tierThreeAudit("assistance.annotation.enable", "assistance.annotation.clear", "assistance.annotation.disable")}
}

func completeAudioWitness() *assistanceTierThreeWitness {
	levels := func(output, microphone float64) *assistanceToneLevels {
		return &assistanceToneLevels{Present: true, Frames: 40, Levels: map[string]float64{"440": output, "880": microphone}}
	}
	return &assistanceTierThreeWitness{Scenario: "audio", Policy: assistanceTierThreePolicy(), Audio: &assistanceAudioWitness{
		Mode: "on", PromptOCR: []string{"share sound", "share your microphone"},
		Shared: &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_SHARING, OutputSource: assistanceAudioOutput, MicrophoneSource: assistanceAudioMicrophone},
		Heard:  levels(35, 33), Muted: levels(1, 2), Unmuted: levels(34, 30), Stopped: levels(0, 0),
		Final: &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_STOPPED},
	}, Audit: tierThreeAudit("assistance.audio.consent", "assistance.audio.mute", "assistance.audio.stop")}
}

func completeUnattendedWitness() *assistanceTierThreeWitness {
	return &assistanceTierThreeWitness{Scenario: "unattended", Policy: assistanceTierThreePolicy(), Unattended: &assistanceUnattendedWitness{
		OptInOCR:     "allow and enable unattended",
		Enrollment:   &adminv1.AssistanceUnattendedEnrollment{Username: actionDesktopUser},
		StateFile:    "600 " + actionDesktopUser + " regular file",
		SelfApproval: &assistanceRPCRefusal{HTTPStatus: 403, Code: "permission_denied"},
		Grant:        &adminv1.AssistanceUnattendedGrant{OperatorId: "operator", ApproverId: "approver"},
		BannerOCR:    "unattended remote assistance",
		Connections: map[string]*assistanceWorkflowSessionEvidence{
			"connect": {EndCause: "user_stopped", EndDetail: "unattended_turned_off"},
		},
		PortalDialogs: map[string]bool{"connect": false},
		Refusals:      map[string]*assistanceRPCRefusal{"after-turn-off": {HTTPStatus: 400, Code: "failed_precondition", Reason: "assistance_unattended_not_enrolled"}},
		StateAfter:    "absent",
	}, Audit: tierThreeAudit("assistance.unattended.request", "assistance.unattended.approve", "assistance.unattended.authorize", "assistance.unattended.enroll", "assistance.unattended.start", "assistance.unattended.stop", "assistance.unattended.revoke")}
}

func TestTierThreeWitnessesQualify(t *testing.T) {
	lock := completeUnattendedWitness()
	lock.Scenario = "unattended-lock"
	lock.Unattended.Connections = map[string]*assistanceWorkflowSessionEvidence{
		"locked":       {EndCause: "no_eligible_session", ConsentedBefore: []string{"requested"}},
		"signed-out":   {EndCause: "no_eligible_session", ConsentedBefore: []string{"requested"}},
		"after-reboot": {EndCause: "operator_stopped"},
	}
	lock.Unattended.BootBefore, lock.Unattended.BootAfter = "a", "b"
	revoked := completeUnattendedWitness()
	revoked.Scenario = "unattended-revoked"
	revoked.Unattended.Connections = map[string]*assistanceWorkflowSessionEvidence{"connect": {EndCause: "authorization_lost"}}
	revoked.Unattended.Refusals = map[string]*assistanceRPCRefusal{
		"expired":          {HTTPStatus: 400, Reason: "assistance_unattended_outside_approval"},
		"outside-schedule": {HTTPStatus: 400, Reason: "assistance_unattended_outside_schedule"},
	}
	monitors := completeAnnotationWitness()
	monitors.Scenario = "annotation-monitors"
	monitors.Annotation.Pointer = []assistanceOverlayObservation{overlayObservation(0), overlayObservation(1)}
	declined := &assistanceTierThreeWitness{Scenario: "audio-declined", Policy: assistanceTierThreePolicy(), Audio: &assistanceAudioWitness{
		PromptOCR: []string{"share sound"}, Shared: &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED},
		Heard: &assistanceToneLevels{}, Final: &agentv1.AssistanceAudioReport{State: agentv1.AssistanceAudioState_ASSISTANCE_AUDIO_STATE_NOT_SHARED},
	}, Audit: tierThreeAudit("assistance.audio.consent")}
	for _, witness := range []*assistanceTierThreeWitness{completeElevationWitness(), completeAnnotationWitness(), monitors, completeAudioWitness(), declined, completeUnattendedWitness(), lock, revoked} {
		if err := verifyAssistanceTierThreeWitness(witness.Scenario, witness); err != nil {
			t.Errorf("%s: %v", witness.Scenario, err)
		}
	}
}

func TestTierThreeWitnessesRejectUnsafeObservations(t *testing.T) {
	for name, mutate := range map[string]func() *assistanceTierThreeWitness{
		"remote key reached the password dialog": func() *assistanceTierThreeWitness {
			w := completeElevationWitness()
			w.Elevation.PkexecExit = "127"
			return w
		},
		"paused command accepted": func() *assistanceTierThreeWitness {
			w := completeElevationWitness()
			w.Elevation.Refusals[1] = assistanceRPCRefusal{HTTPStatus: 200}
			return w
		},
		"resume without new epoch": func() *assistanceTierThreeWitness {
			w := completeElevationWitness()
			w.Elevation.Resumed.Epoch = 3
			return w
		},
		"elevation without resume audit": func() *assistanceTierThreeWitness {
			w := completeElevationWitness()
			w.Audit = w.Audit[:2]
			return w
		},
		"pointer drawn elsewhere": func() *assistanceTierThreeWitness {
			w := completeAnnotationWitness()
			w.Annotation.Pointer[0].Centroid = [2]float64{0.6, 0.3}
			return w
		},
		"pointer leaked to the other head": func() *assistanceTierThreeWitness {
			w := completeAnnotationWitness()
			w.Scenario = "annotation-monitors"
			w.Annotation.Pointer = []assistanceOverlayObservation{overlayObservation(0), overlayObservation(1)}
			w.Annotation.Pointer[1].OtherPixels = 300
			return w
		},
		"overlay intercepted the local click": func() *assistanceTierThreeWitness {
			w := completeAnnotationWitness()
			w.Annotation.LocalClick = nil
			return w
		},
		"hide was not final": func() *assistanceTierThreeWitness {
			w := completeAnnotationWitness()
			w.Annotation.ShowOffered = true
			return w
		},
		"marks survived local clear": func() *assistanceTierThreeWitness {
			w := completeAnnotationWitness()
			w.Annotation.ClearedPixels = 200
			return w
		},
		"mute left sound audible": func() *assistanceTierThreeWitness {
			w := completeAudioWitness()
			w.Audio.Muted.Levels["880"] = 25
			return w
		},
		"tone not heard": func() *assistanceTierThreeWitness {
			w := completeAudioWitness()
			w.Audio.Heard.Levels["880"] = 3
			return w
		},
		"declined sound reached the console": func() *assistanceTierThreeWitness {
			w := completeAudioWitness()
			w.Scenario = "audio-declined"
			w.Audio.PromptOCR = w.Audio.PromptOCR[:1]
			return w
		},
		"self-approved": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Unattended.SelfApproval.HTTPStatus = 200
			return w
		},
		"approver is the operator": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Unattended.Grant.ApproverId = "operator"
			return w
		},
		"portal dialog on an unattended seat": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Unattended.PortalDialogs["connect"] = true
			return w
		},
		"opt-in file readable by others": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Unattended.StateFile = "644 " + actionDesktopUser + " regular file"
			return w
		},
		"turned-off opt-in still on the device": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Unattended.StateAfter = "600 " + actionDesktopUser + " regular file"
			return w
		},
		"locked seat reached": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Scenario = "unattended-lock"
			w.Unattended.Connections = map[string]*assistanceWorkflowSessionEvidence{
				"locked":       {EndCause: "operator_stopped", ConsentedBefore: []string{"requested", "active"}},
				"signed-out":   {EndCause: "no_eligible_session"},
				"after-reboot": {EndCause: "operator_stopped"},
			}
			w.Unattended.BootBefore, w.Unattended.BootAfter = "a", "b"
			return w
		},
		"expired period connected": func() *assistanceTierThreeWitness {
			w := completeUnattendedWitness()
			w.Scenario = "unattended-revoked"
			w.Unattended.Connections = map[string]*assistanceWorkflowSessionEvidence{"connect": {EndCause: "authorization_lost"}}
			w.Unattended.Refusals = map[string]*assistanceRPCRefusal{"expired": {HTTPStatus: 200}, "outside-schedule": {HTTPStatus: 400, Reason: "assistance_unattended_outside_schedule"}}
			return w
		},
		"witness for another scenario": func() *assistanceTierThreeWitness {
			w := completeAudioWitness()
			w.Scenario = "elevation"
			return w
		},
	} {
		witness := mutate()
		scenario := witness.Scenario
		if name == "witness for another scenario" {
			scenario = "audio"
		}
		if verifyAssistanceTierThreeWitness(scenario, witness) == nil {
			t.Errorf("%s qualified", name)
		}
	}
}

func TestTierThreeRecordRequiresEveryBoundWitness(t *testing.T) {
	dir := t.TempDir()
	result := &VMAssistanceResult{}
	if completeAssistanceTierThree(result) {
		t.Fatal("empty record qualified Tier 3")
	}
	data, err := json.Marshal(completeElevationWitness())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tierthree-elevation.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	scenario := &assistanceScenarioEvidence{Name: "elevation", TierThreeWitness: "tierthree-elevation.json"}
	result.TierThreeWitnesses = []assistanceEvidenceFile{{Name: "tierthree-elevation", Path: "tierthree-elevation.json", Bytes: int64(len(data))}}
	if err := verifyTierThreeWitnessRecord(dir, result, scenario); err != nil {
		t.Fatal(err)
	}
	result.Scenarios = []*assistanceScenarioEvidence{scenario}
	if completeAssistanceTierThree(result) {
		t.Fatal("one witness qualified every Tier 3 scenario")
	}
	scenario.Name = "audio"
	if verifyTierThreeWitnessRecord(dir, result, scenario) == nil {
		t.Fatal("a witness was accepted for another scenario")
	}
}

func TestOverlayPixelsLocateOnlyChangedOverlayColour(t *testing.T) {
	reference := image.NewRGBA(image.Rect(0, 0, 200, 100))
	for i := range reference.Pix {
		reference.Pix[i] = 0x40
	}
	// The background already holds an orange patch that must not count.
	for y := 80; y < 90; y++ {
		for x := range 10 {
			reference.SetRGBA(x, y, color.RGBA{255, 153, 0, 255})
		}
	}
	current := image.NewRGBA(reference.Bounds())
	copy(current.Pix, reference.Pix)
	for y := 25; y < 35; y++ {
		for x := 55; x < 65; x++ {
			current.SetRGBA(x, y, color.RGBA{250, 150, 10, 255})
		}
	}
	count, centroid := overlayPixels(reference, current, image.Rectangle{}, overlayPointerColour)
	if count != 100 || centroid[0] < 0.29 || centroid[0] > 0.31 || centroid[1] < 0.29 || centroid[1] > 0.31 {
		t.Fatalf("overlay pixels = %d at %v", count, centroid)
	}
	if count, _ := overlayPixels(reference, current, image.Rectangle{}, overlayStrokeColour); count != 0 {
		t.Fatalf("orange ring counted as red marks: %d", count)
	}
	// A banner moving over the witness is excluded (layers-fedora44-tier3-15).
	if count, _ := overlayPixels(reference, current, image.Rect(50, 20, 70, 40), overlayPointerColour); count != 0 {
		t.Fatalf("excluded banner area counted: %d", count)
	}
	if count, _ := overlayPixels(reference, image.NewRGBA(image.Rect(0, 0, 10, 10)), image.Rectangle{}, overlayPointerColour); count != 0 {
		t.Fatal("mismatched scanout sizes were compared")
	}
}

func TestLabAudioNodesKeepsHelperOrder(t *testing.T) {
	dump := []byte(`[
{"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Audio/Sink","node.description":"Built-in"}}},
{"type":"PipeWire:Interface:Port","info":{"props":{}}},
{"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Audio/Source","node.name":"lindm-lab-microphone","node.description":"Lindm lab microphone"}}},
{"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Stream/Output/Audio","node.description":"tone"}}},
{"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Audio/Sink","node.name":"lindm-lab-output"}}}
]`)
	outputs, microphones, err := labAudioNodes(dump)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 2 || outputs[0] != "Built-in" || outputs[1] != "lindm-lab-output" || len(microphones) != 1 || microphones[0] != assistanceAudioMicrophone {
		t.Fatalf("outputs %q microphones %q", outputs, microphones)
	}
	if _, _, err := labAudioNodes([]byte("{")); err == nil {
		t.Fatal("invalid graph accepted")
	}
}

func TestOCRContainsAllFoldsGlyphConfusions(t *testing.T) {
	text := "note from assistance-operator: lab password step 5lea2e99 remote pointer ... are paused."
	if !ocrContainsAll(text, []string{"paused", "51ea2e99"}) {
		t.Fatal("glyph-confused nonce was not read")
	}
	if ocrContainsAll(text, []string{"paused", "52ea2e99"}) {
		t.Fatal("a different nonce matched")
	}
	// tesseract inserted "/" into the nonce (layers-fedora44-tier3-20).
	if !ocrContainsAll("note from assistance-operator: lab password step a9295a/7f remote ... are paused.", []string{"paused", "a9295a7f"}) {
		t.Fatal("nonce with a stray glyph was not read")
	}
}
