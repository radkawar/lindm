// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

func newTestAssistanceEvidence(t *testing.T) (*assistanceEvidence, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	evidence, err := newAssistanceEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	return evidence, dir
}

func TestAssistanceEvidenceBindsEveryArtifact(t *testing.T) {
	evidence, dir := newTestAssistanceEvidence(t)
	shot, err := evidence.write("guest control consent", "guest-control-consent-prompt.png", []byte("png bytes"))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("png bytes"))
	if shot.SHA256 != hex.EncodeToString(want[:]) || shot.Bytes != 9 || shot.Path != "guest-control-consent-prompt.png" {
		t.Fatalf("binding = %+v", shot)
	}
	info, err := os.Stat(filepath.Join(dir, shot.Path))
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("evidence file mode = %v, %v", info, err)
	}
	// The browser runner writes its own screenshots; bind adopts them.
	if err := os.WriteFile(filepath.Join(dir, "console-control-live.png"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	console, err := evidence.bind("console control live", "console-control-live.png")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := evidence.write("executor journal", "journal-executor.txt", []byte("line\n"))
	if err != nil {
		t.Fatal(err)
	}
	result := &VMAssistanceResult{
		Screenshots: []assistanceEvidenceFile{shot, console},
		Journals:    []assistanceEvidenceFile{journal},
		Scenarios:   []*assistanceScenarioEvidence{{Name: "control", Screenshots: []string{shot.Path, console.Path}}},
	}
	if err := verifyAssistanceEvidence(dir, result); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"scenarios", "screenshots", "journals", "audit", "relay", "passed", "boundaries"} {
		if _, ok := shape[key]; !ok {
			t.Fatalf("record lacks %q", key)
		}
	}
	var files []map[string]any
	if err := json.Unmarshal(shape["screenshots"], &files); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		digest, ok := file["sha256"].(string)
		if !ok || len(digest) != 64 || file["path"] == "" {
			t.Fatalf("screenshot binding incomplete: %v", file)
		}
	}
}

func TestVerifyAssistanceEvidenceRejectsTamperingAndDanglingReferences(t *testing.T) {
	evidence, dir := newTestAssistanceEvidence(t)
	shot, err := evidence.write("guest", "guest-view-sharing.png", []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	result := &VMAssistanceResult{Screenshots: []assistanceEvidenceFile{shot}, Scenarios: []*assistanceScenarioEvidence{{Name: "view", Screenshots: []string{"guest-view-missing.png"}}}}
	if err := verifyAssistanceEvidence(dir, result); err == nil {
		t.Fatal("dangling scenario screenshot accepted")
	}
	result.Scenarios[0].Screenshots = []string{shot.Path}
	path := filepath.Join(dir, shot.Path)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAssistanceEvidence(dir, result); err == nil {
		t.Fatal("tampered screenshot accepted")
	}
	result.Screenshots[0].Path = "../escape.png"
	if err := verifyAssistanceEvidence(dir, result); err == nil {
		t.Fatal("non-local evidence path accepted")
	}
}

func TestAssistanceEvidenceRejectsUnsafeNames(t *testing.T) {
	evidence, _ := newTestAssistanceEvidence(t)
	for _, name := range []string{"", "../x.png", "a/b.png", "/abs.png"} {
		if _, err := evidence.write("bad", name, nil); err == nil {
			t.Fatalf("write accepted %q", name)
		}
		if _, err := evidence.bind("bad", name); err == nil {
			t.Fatalf("bind accepted %q", name)
		}
	}
	if _, err := evidence.write("once", "once.txt", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.write("twice", "once.txt", nil); err == nil {
		t.Fatal("duplicate evidence name accepted")
	}
	if _, err := newAssistanceEvidence("relative"); err == nil {
		t.Fatal("relative evidence directory accepted")
	}
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newAssistanceEvidence(shared); err == nil {
		t.Fatal("group-readable evidence directory accepted")
	}
}

func TestSelectAssistanceScenariosKeepsLaneOrder(t *testing.T) {
	all, err := selectAssistanceScenarios(assistanceScenarios, nil)
	if err != nil || len(all) != len(assistanceScenarios) {
		t.Fatalf("nil selection = %d scenarios, %v", len(all), err)
	}
	none, err := selectAssistanceScenarios(assistanceScenarios, []string{})
	if err != nil || len(none) != 0 {
		t.Fatalf("empty selection = %d scenarios, %v", len(none), err)
	}
	picked, err := selectAssistanceScenarios(assistanceScenarios, []string{"lock", "decline"})
	if err != nil || len(picked) != 2 || picked[0].name != "decline" || picked[1].name != "lock" {
		t.Fatalf("subset = %+v, %v", picked, err)
	}
	for _, bad := range [][]string{{"decline", "decline"}, {"unknown"}, {""}} {
		if _, err := selectAssistanceScenarios(assistanceScenarios, bad); err == nil {
			t.Errorf("selection %q accepted", bad)
		}
	}
}

func TestAssistanceRespondRequiresHeldRun(t *testing.T) {
	_, dir := newTestAssistanceEvidence(t)
	if _, err := AssistanceRespond(context.Background(), dir, "screenshot"); err == nil || !strings.Contains(err.Error(), "not a held assistance run") {
		t.Fatalf("respond without held VM = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, heldVMFile), []byte("relative/vm\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := AssistanceRespond(context.Background(), dir, "allow"); err == nil || !strings.Contains(err.Error(), "clean absolute") {
		t.Fatalf("respond with relative VM directory = %v", err)
	}
}

func TestVerifyAssistanceMediaRequiresTCPRelayWhenAsked(t *testing.T) {
	media := &assistanceMediaEvidence{VideoWidth: 1280, VideoHeight: 800, DecodedFrames: 30, FramesDecoded: 30, ConnectionState: "connected", TransportPolicy: "relay", LocalCandidateType: "relay", RemoteCandidateType: "relay", LocalRelayProtocol: "udp"}
	if err := verifyAssistanceMedia(media, false, false, false, false); err != nil {
		t.Fatalf("UDP relay without TCP requirement: %v", err)
	}
	if err := verifyAssistanceMedia(media, false, false, false, true); err == nil {
		t.Fatal("UDP relay accepted when TURN over TCP was required")
	}
	media.LocalRelayProtocol = "tcp"
	if err := verifyAssistanceMedia(media, false, false, false, true); err != nil {
		t.Fatalf("TCP relay: %v", err)
	}
}

// A desktop's own scenario list bounds selection: Cinnamon offers only its
// pre-consent refusals, never the GNOME live paths.
func TestSelectAssistanceScenariosUsesDesktopList(t *testing.T) {
	refusals := unavailableScenarios("portal_screencast_unavailable", "portal_screencast_unavailable")
	if _, err := selectAssistanceScenarios(refusals, []string{"view"}); err == nil {
		t.Fatal("a live scenario was selectable on a refusal-only desktop")
	}
	picked, err := selectAssistanceScenarios(refusals, []string{"control-unavailable"})
	if err != nil || len(picked) != 1 || picked[0].detail != "portal_screencast_unavailable" || picked[0].cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE {
		t.Fatalf("refusal selection = %+v, %v", picked, err)
	}
}

// The registry and the desktop profile must agree: a refusal-only desktop
// runs only on a release whose registry gates assistance, and live scenarios
// only where it is supported.
func TestAssistanceAdmissionMatchesRegistryGate(t *testing.T) {
	supported := &platform.Release{Name: "supported", Supports: []platform.Capability{platform.Assistance}}
	gated := &platform.Release{Name: "gated", Gates: map[platform.Capability]string{platform.Assistance: "portal_screencast_unavailable"}}
	live := &labDesktop{name: "live", assistance: assistanceScenarios}
	refusing := &labDesktop{name: "refusing", assistance: unavailableScenarios("portal_screencast_unavailable", "portal_screencast_unavailable")}
	for _, test := range []struct {
		release *platform.Release
		desktop *labDesktop
		ok      bool
	}{
		{supported, live, true},
		{gated, refusing, true},
		{gated, live, false},
		{supported, refusing, false},
	} {
		if err := assistanceAdmission(test.release, test.desktop); (err == nil) != test.ok {
			t.Errorf("%s/%s admission error %v, want ok=%v", test.release.Name, test.desktop.name, err, test.ok)
		}
	}
}

func TestVerifyAssistanceMediaIndependentlyGrantsFileChannel(t *testing.T) {
	media := &assistanceMediaEvidence{VideoWidth: 1280, VideoHeight: 800, DecodedFrames: 30, FramesDecoded: 30, ConnectionState: "connected", TransportPolicy: "relay", LocalCandidateType: "relay", RemoteCandidateType: "relay", RemoteApplication: true, DataChannels: []string{"lindm-files"}}
	if err := verifyAssistanceMedia(media, false, true, false, false); err != nil {
		t.Fatalf("view with independently granted files: %v", err)
	}
	if err := verifyAssistanceMedia(media, false, false, false, false); err == nil {
		t.Fatal("ungranted file channel accepted")
	}
	media.DataChannels = []string{"lindm-files", "lindm-input"}
	if err := verifyAssistanceMedia(media, false, true, false, false); err == nil {
		t.Fatal("file grant manufactured input authority")
	}
	media.DataChannels = []string{"lindm-files", "lindm-files"}
	if err := verifyAssistanceMedia(media, false, true, false, false); err == nil {
		t.Fatal("duplicate file channels accepted")
	}
}

func TestAssistanceAuditEvidenceKeepsStructuredFields(t *testing.T) {
	audit := assistanceAuditEvidence{
		ID: "event", ActorID: "actor", Action: "assistance.clipboard",
		ResourceID: "session", TargetDeviceID: "device",
		Reason:  "Operator explanation, not machine metadata",
		Details: map[string]string{"request": "request", "result": "denied", "reason": "capability_scope_denied"},
	}
	encoded, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"actor_id": "actor", "resource_id": "session", "target_device_id": "device",
		"reason": audit.Reason,
	} {
		var got string
		if err := json.Unmarshal(shape[key], &got); err != nil || got != want {
			t.Fatalf("audit %s = %q, %v; want %q", key, got, err, want)
		}
	}
	if _, exists := shape["session_id"]; exists {
		t.Fatal("audit resource still uses the obsolete session-only alias")
	}
	var details map[string]string
	if err := json.Unmarshal(shape["details"], &details); err != nil {
		t.Fatal(err)
	}
	for key, want := range audit.Details {
		if details[key] != want {
			t.Fatalf("audit details[%q] = %q; want %q", key, details[key], want)
		}
	}
}

// This ledger exercises qualification completeness only. Its in-memory fields
// are not native artifacts and cannot pass the artifact/witness verifier.
func assistanceTierOneLedgerFixture() *VMAssistanceResult {
	result := new(VMAssistanceResult)
	for _, spec := range assistanceScenarios {
		if slices.Contains(assistanceFileScenarios, spec.name) || assistanceWorkflowScenario(spec.name) || assistanceTierThreeScenario(spec.name) {
			continue
		}
		scenario := &assistanceScenarioEvidence{Name: spec.name, Mode: "view", SessionID: "11111111-1111-4111-8111-111111111111"}
		if spec.name == "authority-view" || spec.name == "authority-control" {
			scenario = modeAuthorityFixture(spec.name)
		}
		if spec.mode == agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL {
			scenario.Mode = "control"
		}
		scenario.EndCause = assistanceCauseText(spec.cause)
		scenario.ConsoleEndCause = scenario.EndCause
		scenario.Screenshots = []string{spec.name + ".png"}
		if spec.capability == "" && spec.cause != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED {
			control := scenario.Mode == "control"
			scenario.CaptureStopped, scenario.ControlGranted = true, control
			scenario.LocalSession = &assistanceLocalEvidence{UID: 1000, LogindSessionID: "3"}
			scenario.OfferFingerprint, scenario.AnswerFingerprint = "offer", "answer"
			scenario.Media = &assistanceMediaEvidence{VideoWidth: 1280, VideoHeight: 800, DecodedFrames: 30, FramesDecoded: 30, ConnectionState: "connected", TransportPolicy: "relay", LocalCandidateType: "relay", RemoteCandidateType: "relay", ControlButton: control, RemoteApplication: control}
			if control {
				scenario.Media.DataChannels = []string{"lindm-input"}
				scenario.Nonce, scenario.NonceReceived = "0123456789ab", true
			}
		}
		if slices.Contains([]string{"clipboard", "clipboard-limited", "keyboard", "display", "message", "monitors"}, spec.name) {
			scenario.CapabilityWitness = spec.name + ".json"
			result.Witnesses = append(result.Witnesses, assistanceEvidenceFile{Path: scenario.CapabilityWitness})
		}
		for _, name := range requiredAssistanceBoundaries(spec.name) {
			scenario.BoundaryWitnesses = append(scenario.BoundaryWitnesses, name+".json")
			result.BoundaryWitnesses = append(result.BoundaryWitnesses, assistanceEvidenceFile{Name: name, Path: name + ".json"})
		}
		result.Scenarios = append(result.Scenarios, scenario)
	}
	return result
}

func TestAssistanceQualificationRequiresBaselineModeAndNativeProofs(t *testing.T) {
	if !completeAssistanceTierOne(assistanceTierOneLedgerFixture()) {
		t.Fatal("complete Tier1 ledger rejected")
	}
	for _, spec := range assistanceScenarios {
		if slices.Contains(assistanceFileScenarios, spec.name) || assistanceWorkflowScenario(spec.name) || assistanceTierThreeScenario(spec.name) {
			continue
		}
		t.Run(spec.name, func(t *testing.T) {
			result := assistanceTierOneLedgerFixture()
			result.Scenarios = slices.DeleteFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == spec.name })
			if completeAssistanceTierOne(result) {
				t.Fatal("partial ledger qualified full Tier1")
			}
			result.TierOnePassed = true
			if verifyAssistanceEvidence(t.TempDir(), result) == nil {
				t.Fatal("partial receipt claimed full Tier1")
			}
		})
	}
	for _, name := range []string{"control", "view", "authority-view", "authority-control", "lock"} {
		t.Run(name+"-without-media", func(t *testing.T) {
			result := assistanceTierOneLedgerFixture()
			index := slices.IndexFunc(result.Scenarios, func(scenario *assistanceScenarioEvidence) bool { return scenario.Name == name })
			result.Scenarios[index].Media = nil
			if completeAssistanceTierOne(result) {
				t.Fatal("baseline without native media qualified")
			}
		})
	}
	if err := verifyAssistanceEvidence(t.TempDir(), &VMAssistanceResult{Passed: true, FilesPassed: true}); err == nil {
		t.Fatal("files pass accepted without baseline and Tier1")
	}
	if completeAssistanceTierOne(&VMAssistanceResult{Passed: true}) {
		t.Fatal("zero-scenario hold qualified")
	}
	subset := assistanceTierOneLedgerFixture()
	subset.SelectedScenarios = []string{"control"}
	if completeAssistanceTierOne(subset) {
		t.Fatal("subset record qualified full Tier1")
	}
}

func TestAssistanceDefaultScenariosIncludeEveryQualificationBoundary(t *testing.T) {
	scenarios, err := selectAssistanceScenarios(assistanceScenarios, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(scenarios))
	for _, spec := range scenarios {
		names = append(names, spec.name)
	}
	want := []string{"control", "rerequest", "view", "authority-view", "authority-control", "decline", "portal-cancel", "lock", "clipboard", "clipboard-limited", "clipboard-policy", "clipboard-permission", "keyboard", "display", "message", "monitors", "files", "files-cancel", "files-limited", "files-filesystem", "files-limits", "files-interrupted", "files-policy", "files-permission",
		"recording", "recording-declined", "recording-refused", "recording-storage", "recording-permission", "recording-retention",
		"reconnect-logout", "reconnect-reboot", "reconnect-declined", "reconnect-expired", "reconnect-revoked",
		"elevation", "annotation", "annotation-monitors", "audio", "audio-declined", "unattended", "unattended-lock", "unattended-revoked"}
	if !slices.Equal(names, want) {
		t.Fatalf("default qualification scenarios = %v, want %v", names, want)
	}
}

func TestAssistanceBindingRejectsDifferentServerMode(t *testing.T) {
	for _, mode := range []agentv1.AssistanceMode{agentv1.AssistanceMode_ASSISTANCE_MODE_UNSPECIFIED, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW} {
		if err := new(assistanceRun).verifyBinding(&assistanceScenarioEvidence{Mode: "control"}, &adminv1.AssistanceSession{Mode: mode}, true); err == nil {
			t.Fatalf("server mode %s qualified requested control", mode)
		}
	}
	if err := new(assistanceRun).verifyBinding(&assistanceScenarioEvidence{Mode: "view"}, &adminv1.AssistanceSession{Mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL}, false); err == nil {
		t.Fatal("server control mode qualified requested view")
	}
}

// A VIEW session granted pointer and marks negotiates only the annotation
// channel (layers-fedora44-tier3-08 refused it as ungranted).
func TestVerifyAssistanceMediaIndependentlyGrantsAnnotationChannel(t *testing.T) {
	media := &assistanceMediaEvidence{VideoWidth: 1280, VideoHeight: 800, DecodedFrames: 30, FramesDecoded: 30, ConnectionState: "connected", TransportPolicy: "relay", LocalCandidateType: "relay", RemoteCandidateType: "relay", RemoteApplication: true, DataChannels: []string{"lindm-annotate"}}
	if err := verifyAssistanceMedia(media, false, false, true, false); err != nil {
		t.Fatalf("view with granted annotation: %v", err)
	}
	if err := verifyAssistanceMedia(media, false, false, false, false); err == nil {
		t.Fatal("ungranted annotation channel accepted")
	}
	media.DataChannels = []string{"lindm-annotate", "lindm-input"}
	if err := verifyAssistanceMedia(media, false, false, true, false); err == nil {
		t.Fatal("annotation grant manufactured input authority")
	}
}
