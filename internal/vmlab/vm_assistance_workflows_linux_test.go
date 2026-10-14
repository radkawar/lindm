// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/devlab"
)

const (
	workflowTestRecording = "6f1c1d0e-2d5c-4a4b-9e7e-1a2b3c4d5e6f"
	workflowTestPrevious  = "11111111-1111-4111-8111-111111111111"
	workflowTestNext      = "22222222-2222-4222-8222-222222222222"
	workflowTestFlow      = "33333333-3333-4333-8333-333333333333"
)

func audited(actions ...string) []assistanceAuditEvidence {
	rows := make([]assistanceAuditEvidence, len(actions))
	for i, action := range actions {
		rows[i] = assistanceAuditEvidence{Action: action}
	}
	return rows
}

func playback(nonces ...string) *assistancePlaybackEvidence {
	p := &assistancePlaybackEvidence{VideoWidth: 1280, VideoHeight: 800, Frames: 40, Complete: true}
	for i, nonce := range nonces {
		p.Seen = append(p.Seen, struct {
			Nonce string  `json:"nonce"`
			At    float64 `json:"at"`
		}{nonce, float64(i)})
	}
	return p
}

func completeRecordingWitness() *assistanceRecordingWitness {
	nonces := []string{"aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb"}
	return &assistanceRecordingWitness{
		RecordingID: workflowTestRecording, Required: true, State: "complete", Segments: 3, StoredBytes: 4096,
		CiphertextSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		PromptSummary:    "remote assistance request (recorded)", IndicatorSummary: "remote assistance in progress — recording",
		Nonces: nonces, Playback: playback(nonces...), ServerAtRest: &devlab.AssistanceRecordingAtRest{Segments: 3, Bytes: 4096, KeyRetained: true},
		Session: &assistanceWorkflowSessionEvidence{ID: workflowTestPrevious},
		Audit:   audited("assistance.recording.start", "assistance.recording.stop", "assistance.recording.read"),
	}
}

func TestRecordingWitnessRequiresDisclosureCiphertextAndOrderedPlayback(t *testing.T) {
	if err := verifyRecordingWitness("recording", completeRecordingWitness()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*assistanceRecordingWitness){
		"device plaintext": func(w *assistanceRecordingWitness) { w.DevicePlaintext = []string{"/tmp/x.webm"} },
		"server plaintext": func(w *assistanceRecordingWitness) { w.ServerAtRest.PlaintextMarkers = 1 },
		"no disclosure":    func(w *assistanceRecordingWitness) { w.PromptSummary = "remote assistance request" },
		"no indicator":     func(w *assistanceRecordingWitness) { w.IndicatorSummary = "remote assistance in progress" },
		"reordered":        func(w *assistanceRecordingWitness) { w.Playback = playback(w.Nonces[1], w.Nonces[0]) },
		"missing change":   func(w *assistanceRecordingWitness) { w.Playback = playback(w.Nonces[0]) },
		"unaudited read": func(w *assistanceRecordingWitness) {
			w.Audit = audited("assistance.recording.start", "assistance.recording.stop")
		},
		"segment mismatch":  func(w *assistanceRecordingWitness) { w.ServerAtRest.Segments = 2 },
		"truncated archive": func(w *assistanceRecordingWitness) { w.Playback.Complete = false },
	} {
		w := completeRecordingWitness()
		mutate(w)
		if verifyRecordingWitness("recording", w) == nil {
			t.Fatalf("%s qualified", name)
		}
	}
	permission := completeRecordingWitness()
	permission.Required, permission.PromptSummary = false, "remote assistance request (recording requested)"
	permission.Denial = &assistanceRecordingDenial{HTTPStatus: 403, Reason: "permission_denied", Listed: true}
	permission.ArchiveLiveDenial = &assistanceModeDenial{HTTPStatus: 403}
	permission.ArchivePlayback = playback(permission.Nonces...)
	permission.AfterDeletion = &devlab.AssistanceRecordingAtRest{}
	permission.Audit = audited("assistance.recording.start", "assistance.recording.stop", "assistance.recording.delete")
	if err := verifyRecordingWitness("recording-permission", permission); err != nil {
		t.Fatal(err)
	}
	permission.Denial.PlayOffered = true
	if verifyRecordingWitness("recording-permission", permission) == nil {
		t.Fatal("playback offered without retrieval permission qualified")
	}
	declined := &assistanceRecordingWitness{RecordingID: workflowTestRecording, State: "declined", PromptSummary: "remote assistance request (recording requested)", IndicatorSummary: "remote assistance in progress", ServerAtRest: &devlab.AssistanceRecordingAtRest{}, Session: &assistanceWorkflowSessionEvidence{}}
	if err := verifyRecordingWitness("recording-declined", declined); err != nil {
		t.Fatal(err)
	}
	declined.IndicatorSummary = "remote assistance in progress — recording"
	if verifyRecordingWitness("recording-declined", declined) == nil {
		t.Fatal("declined recording with a recording indicator qualified")
	}
}

func completeReconnectWitness() *assistanceReconnectWitness {
	return &assistanceReconnectWitness{
		WorkflowID: workflowTestFlow, Mode: "limited", Interruption: "logout",
		Previous: &assistanceWorkflowSessionEvidence{ID: workflowTestPrevious, EndCause: "session_ended", Local: &assistanceLocalEvidence{Username: "lab", LogindSessionID: "2"}},
		Waiting:  &adminv1.AssistanceReconnectWorkflow{State: adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_WAITING},
		Next:     &assistanceWorkflowSessionEvidence{ID: workflowTestNext, ReconnectOf: workflowTestPrevious, PortalDialog: true, ConsentedBefore: []string{"requested", "prompted"}, Local: &assistanceLocalEvidence{Username: "lab", LogindSessionID: "5"}},
		Final:    &adminv1.AssistanceReconnectWorkflow{State: adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ACTIVE},
		Audit:    audited("assistance.reconnect.request", "assistance.reconnect.consent"),
	}
}

func TestReconnectWitnessRequiresFreshConsentAndRealInterruption(t *testing.T) {
	if err := verifyReconnectWitness("reconnect-logout", completeReconnectWitness()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*assistanceReconnectWitness){
		"stopped not interrupted": func(w *assistanceReconnectWitness) { w.Previous.EndCause = "user_stopped" },
		"policy loss": func(w *assistanceReconnectWitness) {
			w.Previous.EndCause, w.Previous.EndDetail = "authorization_lost", "policy_changed"
		},
		"reused portal grant":  func(w *assistanceReconnectWitness) { w.Next.PortalDialog = false },
		"same login":           func(w *assistanceReconnectWitness) { w.Next.Local.LogindSessionID = "2" },
		"media before consent": func(w *assistanceReconnectWitness) { w.Next.ConsentedBefore = []string{"requested", "active"} },
		"unlinked":             func(w *assistanceReconnectWitness) { w.Next.ReconnectOf = "" },
		"unaudited consent":    func(w *assistanceReconnectWitness) { w.Audit = audited("assistance.reconnect.request") },
		"never waited": func(w *assistanceReconnectWitness) {
			w.Waiting.State = adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ENDED
		},
	} {
		w := completeReconnectWitness()
		mutate(w)
		if verifyReconnectWitness("reconnect-logout", w) == nil {
			t.Fatalf("%s qualified", name)
		}
	}
	reboot := completeReconnectWitness()
	reboot.Interruption, reboot.BootBefore, reboot.BootAfter = "reboot", "a", "a"
	if verifyReconnectWitness("reconnect-reboot", reboot) == nil {
		t.Fatal("reboot without a boot change qualified")
	}
	// An ON workflow already reissued to the observed next session after
	// the reboot qualifies; one active on another session does not.
	reboot.BootAfter = "b"
	reboot.Waiting = &adminv1.AssistanceReconnectWorkflow{State: adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ACTIVE, Reconnects: 1, OriginSessionId: workflowTestPrevious, LatestSessionId: workflowTestNext}
	if err := verifyReconnectWitness("reconnect-reboot", reboot); err != nil {
		t.Fatalf("reissued reboot workflow: %v", err)
	}
	reboot.Waiting.LatestSessionId = workflowTestPrevious
	if verifyReconnectWitness("reconnect-reboot", reboot) == nil {
		t.Fatal("a workflow active on the interrupted session qualified")
	}
	logout := completeReconnectWitness()
	logout.Waiting = &adminv1.AssistanceReconnectWorkflow{State: adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ACTIVE, Reconnects: 1, OriginSessionId: workflowTestPrevious, LatestSessionId: workflowTestNext}
	if verifyReconnectWitness("reconnect-logout", logout) == nil {
		t.Fatal("an operator-issued workflow that never waited qualified")
	}
	declined := completeReconnectWitness()
	declined.Next.EndCause, declined.Next.PortalDialog = "declined", false
	declined.Next.ConsentedBefore = []string{"requested", "prompted", "ended"}
	declined.Final = &adminv1.AssistanceReconnectWorkflow{State: adminv1.AssistanceReconnectState_ASSISTANCE_RECONNECT_STATE_ENDED}
	declined.Audit = audited("assistance.reconnect.request")
	if err := verifyReconnectWitness("reconnect-declined", declined); err != nil {
		t.Fatalf("declined reconnect: %v", err)
	}
	declined.Next.ConsentedBefore = []string{"requested", "prompted", "active", "ended"}
	if verifyReconnectWitness("reconnect-declined", declined) == nil {
		t.Fatal("a declined reconnect that reached media qualified")
	}
	ended := completeReconnectWitness()
	ended.Next.ConsentedBefore = []string{"requested", "prompted", "ended"}
	if verifyReconnectWitness("reconnect-logout", ended) == nil {
		t.Fatal("a reconnect that ended before consent qualified as resumed")
	}
	expired := completeReconnectWitness()
	expired.Next = nil
	expired.Refusal = &assistanceReconnectRefusal{HTTPStatus: 400, Code: "failed_precondition", Reason: "assistance_reconnect_expired"}
	expired.Audit = audited("assistance.reconnect.expire")
	if err := verifyReconnectWitness("reconnect-expired", expired); err != nil {
		t.Fatal(err)
	}
	expired.Refusal.Offered = true
	if verifyReconnectWitness("reconnect-expired", expired) == nil {
		t.Fatal("expired workflow still offering reconnect qualified")
	}
}

func TestWorkflowQualificationRequiresEveryBoundWitness(t *testing.T) {
	dir := t.TempDir()
	result := &VMAssistanceResult{}
	if completeAssistanceWorkflows(result) {
		t.Fatal("empty record qualified Tier 2 workflows")
	}
	data, err := json.Marshal(&assistanceWorkflowWitness{Scenario: "recording", Recording: completeRecordingWitness()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workflow-recording.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	scenario := &assistanceScenarioEvidence{Name: "recording", WorkflowWitness: "workflow-recording.json"}
	result.WorkflowWitnesses = []assistanceEvidenceFile{{Name: "workflow-recording", Path: "workflow-recording.json", Bytes: int64(len(data))}}
	if err := verifyWorkflowWitnessRecord(dir, result, scenario); err != nil {
		t.Fatal(err)
	}
	result.Scenarios = []*assistanceScenarioEvidence{scenario}
	if completeAssistanceWorkflows(result) {
		t.Fatal("one workflow witness qualified every Tier 2 scenario")
	}
	scenario.Name = "recording-retention"
	if verifyWorkflowWitnessRecord(dir, result, scenario) == nil {
		t.Fatal("a witness was accepted for another scenario")
	}
}
