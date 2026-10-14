// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// These are synthetic inputs to the evidence verifier only. They cannot enter
// the native runner or qualify a platform; only the real lane emits witnesses.
func isolationVerifierFixture(t *testing.T) (*assistanceScenarioEvidence, *assistanceFileIsolationProof) {
	t.Helper()
	const session = "11111111-1111-4111-8111-111111111111"
	const actor = "22222222-2222-4222-8222-222222222222"
	const device = "33333333-3333-4333-8333-333333333333"
	const request = "44444444-4444-4444-8444-444444444444"
	const nextRequest = "55555555-5555-4555-8555-555555555555"
	const name = "lindm-file-0123456789abcdef01234567.txt"
	const nextName = "lindm-file-1123456789abcdef01234567.txt"
	const nonce = "abcdefabcdefabcdefabcdef"
	now := time.Date(2026, 10, 11, 1, 2, 3, 0, time.UTC)
	s := &assistanceScenarioEvidence{Name: "files-interrupted", Mode: "control", SessionID: session, DeviceID: device, OperatorID: actor, OperatorDisplay: "Support Operator", ExpectedCause: "operator_stopped", ControlGranted: true, LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}, Screenshots: []string{"held.png", "fresh.png", "modal.png", "consent.png", "next-consent.png"}}
	audit := func(action, id string, details map[string]string) *assistanceAuditEvidence {
		details["request"] = id
		return &assistanceAuditEvidence{ID: id, OccurredAt: now, ActorID: actor, Action: action, ResourceID: session, TargetDeviceID: device, Details: details}
	}
	fileAudit := func(action, id, result, reason, count, reserved, remaining, digest string) *assistanceAuditEvidence {
		return audit(action, id, map[string]string{"direction": "operator_to_user", "bytes": count, "reserved_bytes": reserved, "sha256": digest, "authorized_sha256": digest, "sha256_origin": "authorized_request", "mime_type": "text/plain", "max_file_bytes": "16777216", "max_session_bytes": remaining, "allowed_mime_types": "text/plain,application/pdf,image/png,image/jpeg", "allowed_extensions": ".txt,.log,.pdf,.png,.jpg,.jpeg", "result": result, "reason": reason})
	}
	hash := strings.Repeat("a", 64)
	attempt := &assistanceFileAttempt{Source: assistanceEvidenceFile{Name: "operator file fixture", Path: name, Bytes: 16 << 20, SHA256: hash}, Before: &assistanceFileObservation{}, After: &assistanceFileObservation{}, Paused: &agentv1.AssistanceInputState{Epoch: 2, Paused: true}, Resumed: &agentv1.AssistanceInputState{Epoch: 3}, ConsentScreenshot: "consent.png", ConsentOCR: "Receive a file from your support operator Support Operator " + name + " Downloads",
		Report: &agentv1.AssistanceFileReport{RequestId: request, Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_CANCELLED, BytesTransferred: 32768, Reason: "operator_cancelled", CompletedAt: timestamppb.New(now)},
		Audit:  fileAudit("assistance.file.cancel", request, "cancelled", "operator_cancelled", "32768", "16777216", "67108864", hash),
	}
	nextHash := strings.Repeat("b", 64)
	next := &assistanceFileAttempt{Source: assistanceEvidenceFile{Name: "operator file fixture", Path: nextName, Bytes: 1024, SHA256: nextHash}, Before: &assistanceFileObservation{}, After: &assistanceFileObservation{}, Paused: &agentv1.AssistanceInputState{Epoch: 4, Paused: true}, Resumed: &agentv1.AssistanceInputState{Epoch: 5}, ConsentScreenshot: "next-consent.png", ConsentOCR: "Receive a file from your support operator Support Operator " + nextName + " Downloads",
		Report: &agentv1.AssistanceFileReport{RequestId: nextRequest, Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_DENIED, Reason: "file_declined", CompletedAt: timestamppb.New(now)},
		Audit:  fileAudit("assistance.file.deny", nextRequest, "denied", "file_declined", "0", "1024", "50331648", nextHash),
	}
	p := &assistanceFileIsolationProof{SessionID: session, Attempt: attempt, Initial: &agentv1.AssistanceInputState{Epoch: 1}, Display: "monitor-1", Generation: 1, BeforeScreenshot: "held.png", AfterScreenshot: "fresh.png", ModalScreenshot: "modal.png", ModalOCR: attempt.ConsentOCR, ApprovalX: 0.55, ApprovalY: 0.2, ProbeNonce: "0123456789abcdef01234567", Reservation: next, RetainedSessionID: session, RetainedPhase: adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE, RetainedInput: &agentv1.AssistanceInputState{Epoch: 5},
		RequestAudit:     fileAudit("assistance.file.request", request, "requested", "file_requested", "0", "16777216", "67108864", hash),
		ReservationAudit: fileAudit("assistance.file.request", nextRequest, "requested", "file_requested", "0", "1024", "50331648", nextHash),
	}
	p.ModalBefore = &agentv1.AssistanceFileReport{RequestId: request, Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_WAITING_CONSENT}
	p.ModalAfter = proto.CloneOf(p.ModalBefore)
	probe := func(frames []string) assistanceFileInputProbe {
		return assistanceFileInputProbe{Channel: "lindm-input", Ordered: true, Frames: frames}
	}
	p.Capture = probe(isolationFrames(p.Display, 1, 1, "KeyY", false))
	p.Hold = probe(isolationFrames(p.Display, 1, 1, "ShiftLeft", true))
	p.Modal = probe(isolationModalFrames(p))
	p.Replay = probe(append(slices.Clone(p.Capture.Frames), isolationFrames(p.Display, 1, 3, "KeyZ", false)...))
	p.Baseline = &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", UID: 1000, PID: 123, SessionID: "7", SessionType: "wayland", ActiveMonitors: 1, ClipboardSource: nonce, Pasted: nonce, PasteSerial: 1, Releases: []string{"y"}, Clicks: []assistancePointerWitness{{Head: 0, X: 0.5, Y: 0.6}}}
	if err := json.Unmarshal([]byte(`{"monitors":[{"head":0,"model":"lab","x":0,"y":0,"width":1280,"height":720}]}`), p.Baseline); err != nil {
		t.Fatal(err)
	}
	isolationTestKey(p.Baseline, "y")
	p.Held = isolationTestClone(t, p.Baseline)
	isolationTestKey(p.Held, "Shift_L")
	p.Paused = isolationTestClone(t, p.Held)
	p.Paused.Releases = append(p.Paused.Releases, "Shift_L")
	p.Probed = isolationTestClone(t, p.Paused)
	isolationTestKey(p.Probed, "Control_L")
	isolationTestKey(p.Probed, "v")
	p.Probed.Releases = append(p.Probed.Releases, "Control_L", "v")
	p.Probed.PasteSerial++
	p.Resumed = isolationTestClone(t, p.Probed)
	p.Resumed.Clicks = append(p.Resumed.Clicks, assistancePointerWitness{Head: 0, X: 0.5, Y: 0.5})
	p.Final = isolationTestClone(t, p.Resumed)
	isolationTestKey(p.Final, "z")
	p.Final.Releases = append(p.Final.Releases, "z")
	for i, kind := range []string{"clipboard_write", "clipboard_read", "special_keys"} {
		id := []string{"66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"}[i]
		action, direction := "assistance.clipboard", "operator_to_user"
		if kind == "clipboard_read" {
			direction = "user_to_operator"
		}
		if kind == "special_keys" {
			action, direction = "assistance.special_keys", ""
		}
		p.Refusals = append(p.Refusals, assistanceFileModalRefusal{RequestID: id, Kind: kind, Code: "failed_precondition", Reason: "assistance_input_paused", HTTPStatus: 400, Actor: &assistanceActor{ID: actor, Display: s.OperatorDisplay, Role: "owner", ObservedAt: now, Permissions: []string{"remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard", "remote_assistance.clipboard", "remote_assistance.files"}}, Audit: audit(action, id, map[string]string{"kind": kind, "direction": direction, "result": "denied", "reason": "input_paused", "chord": "close_window"})})
	}
	encode := func(frame *agentv1.AssistanceFileFrame) []byte {
		data, err := proto.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ready := encode(&agentv1.AssistanceFileFrame{RequestId: request, Body: &agentv1.AssistanceFileFrame_Ready{Ready: &agentv1.AssistanceFileReady{}}})
	for i := range 2 {
		count := uint64((i + 1) * 16384)
		prefix := strings.Repeat([]string{"c", "d"}[i], 64)
		p.Partial = append(p.Partial, assistanceFilePartial{RequestID: request, Channel: "lindm-files", Ordered: true, BytesSent: count, ReadyFrame: slices.Clone(ready), SourcePrefixSHA256: prefix, Stage: &assistanceFileStage{Name: ".lindm-transfer-0123456789abcdef0123456789abcdef", UID: 1000, Mode: 0600, Bytes: count, SHA256: prefix, Device: 1, Inode: 1234}, Report: &agentv1.AssistanceFileReport{RequestId: request, Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING, BytesTransferred: count}})
	}
	p.CancelFrame = encode(&agentv1.AssistanceFileFrame{RequestId: request, Body: &agentv1.AssistanceFileFrame_Cancel{Cancel: &agentv1.AssistanceFileCancel{Reason: "file_cancelled"}}})
	return s, p
}

func isolationTestClone(t *testing.T, state *assistanceFixtureState) *assistanceFixtureState {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var next assistanceFixtureState
	if err := json.Unmarshal(data, &next); err != nil {
		t.Fatal(err)
	}
	return &next
}

func isolationTestKey(state *assistanceFixtureState, symbol string) {
	state.Keys = append(state.Keys, struct {
		Head    int    `json:"head"`
		Symbol  string `json:"symbol"`
		Unicode uint32 `json:"unicode"`
		LayoutZ string `json:"layout_z"`
	}{Head: 0, Symbol: symbol})
}

func TestFileIsolationVerifierRequiresNativeModalAndPartialStreamEvidence(t *testing.T) {
	s, p := isolationVerifierFixture(t)
	if err := verifyFileIsolation(s, p); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*assistanceFileIsolationProof){
		"absent attempt":               func(p *assistanceFileIsolationProof) { p.Attempt = nil },
		"foreign session":              func(p *assistanceFileIsolationProof) { p.SessionID = "other" },
		"tiny upload":                  func(p *assistanceFileIsolationProof) { p.Attempt.Source.Bytes = 32768 },
		"cancel before progress":       func(p *assistanceFileIsolationProof) { p.Attempt.Report.BytesTransferred = 0 },
		"ordinary session end instead": func(p *assistanceFileIsolationProof) { p.Attempt.Report.Reason = "session_ended" },
		"failed instead of cancelled": func(p *assistanceFileIsolationProof) {
			p.Attempt.Report.State = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED
		},
		"receiver publication claim": func(p *assistanceFileIsolationProof) { p.Attempt.Report.File = &agentv1.AssistanceFileMetadata{} },
		"final file appeared":        func(p *assistanceFileIsolationProof) { p.Attempt.After.Exists = true },
		"partial staging left":       func(p *assistanceFileIsolationProof) { p.Attempt.After.Staging = []string{".lindm-transfer-left"} },
		"missing initial epoch":      func(p *assistanceFileIsolationProof) { p.Initial = nil },
		"epoch not invalidated":      func(p *assistanceFileIsolationProof) { p.Attempt.Resumed.Epoch = p.Attempt.Paused.Epoch },
		"held frame actually released": func(p *assistanceFileIsolationProof) {
			p.Hold.Frames = append(p.Hold.Frames, isolationFrames(p.Display, 1, 1, "ShiftLeft", false)[1])
		},
		"missing modal pointer probes": func(p *assistanceFileIsolationProof) { p.Modal.Frames = p.Modal.Frames[3:] },
		"missing guessed future epoch": func(p *assistanceFileIsolationProof) { p.Modal.Frames = p.Modal.Frames[:10] },
		"invalid approval point":       func(p *assistanceFileIsolationProof) { p.ApprovalX = math.NaN() },
		"remote approved modal": func(p *assistanceFileIsolationProof) {
			p.ModalAfter.State = agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_TRANSFERRING
		},
		"missing before approval state": func(p *assistanceFileIsolationProof) { p.ModalBefore = nil },
		"uncaptured replay": func(p *assistanceFileIsolationProof) {
			p.Replay.Frames[0] = isolationFrames(p.Display, 1, 3, "KeyY", false)[0]
		},
		"no replay":               func(p *assistanceFileIsolationProof) { p.Replay.Frames = p.Replay.Frames[2:] },
		"unordered input":         func(p *assistanceFileIsolationProof) { p.Replay.Ordered = false },
		"no independent guest":    func(p *assistanceFileIsolationProof) { p.Paused = nil },
		"held key never released": func(p *assistanceFileIsolationProof) { p.Paused.Releases = p.Paused.Releases[:1] },
		"replayed stale key":      func(p *assistanceFileIsolationProof) { isolationTestKey(p.Final, "y") },
		"paused pointer leaked": func(p *assistanceFileIsolationProof) {
			p.Probed.Clicks = append(p.Probed.Clicks, assistancePointerWitness{Head: 0, X: 0.5, Y: 0.6})
		},
		"special key closed fixture": func(p *assistanceFileIsolationProof) { p.Probed.Closed = []int{0} },
		"paused clipboard changed":   func(p *assistanceFileIsolationProof) { p.Probed.Pasted = p.ProbeNonce },
		"stale clipboard snapshot":   func(p *assistanceFileIsolationProof) { p.Probed.PasteSerial-- },
		"foreign GTK process":        func(p *assistanceFileIsolationProof) { p.Final.PID++ },
		"foreign seat":               func(p *assistanceFileIsolationProof) { p.Final.SessionID = "8" },
		"missing fresh marker":       func(p *assistanceFileIsolationProof) { p.Final.Keys = p.Final.Keys[:len(p.Final.Keys)-1] },
		"wrong marker head":          func(p *assistanceFileIsolationProof) { p.Final.Keys[len(p.Final.Keys)-1].Head = 1 },
		"one screenshot reused":      func(p *assistanceFileIsolationProof) { p.ModalScreenshot = p.Attempt.ConsentScreenshot },
		"no approval pixels":         func(p *assistanceFileIsolationProof) { p.ModalOCR = "" },
		"unbound screenshot":         func(p *assistanceFileIsolationProof) { p.AfterScreenshot = "unbound.png" },
		"read probe missing":         func(p *assistanceFileIsolationProof) { p.Refusals = p.Refusals[:2] },
		"unrelated refusal":          func(p *assistanceFileIsolationProof) { p.Refusals[0].Reason = "assistance_file_busy" },
		"permission failure not modal": func(p *assistanceFileIsolationProof) {
			p.Refusals[1].Actor.Permissions = []string{"remote_assistance.view", "remote_assistance.control"}
		},
		"missing refusal audit":        func(p *assistanceFileIsolationProof) { p.Refusals[2].Audit = nil },
		"wrong refusal audit kind":     func(p *assistanceFileIsolationProof) { p.Refusals[1].Audit.Details["kind"] = "clipboard_write" },
		"wrong refusal actor":          func(p *assistanceFileIsolationProof) { p.Refusals[0].Audit.ActorID = p.SessionID },
		"wrong refusal target":         func(p *assistanceFileIsolationProof) { p.Refusals[0].Audit.TargetDeviceID = p.SessionID },
		"wrong special chord":          func(p *assistanceFileIsolationProof) { p.Refusals[2].Audit.Details["chord"] = "lock_screen" },
		"no partial writes":            func(p *assistanceFileIsolationProof) { p.Partial = nil },
		"zero-byte partial":            func(p *assistanceFileIsolationProof) { p.Partial[0].Stage.Bytes = 0 },
		"partial only sender observed": func(p *assistanceFileIsolationProof) { p.Partial[1].Stage = nil },
		"source prefix differs":        func(p *assistanceFileIsolationProof) { p.Partial[0].Stage.SHA256 = strings.Repeat("e", 64) },
		"different staging inode":      func(p *assistanceFileIsolationProof) { p.Partial[1].Stage.Inode++ },
		"different staging mount":      func(p *assistanceFileIsolationProof) { p.Partial[1].Stage.Device++ },
		"unsafe staging mode":          func(p *assistanceFileIsolationProof) { p.Partial[0].Stage.Mode = 0700 },
		"root receiver":                func(p *assistanceFileIsolationProof) { p.Partial[0].Stage.UID = 0 },
		"outside staging path":         func(p *assistanceFileIsolationProof) { p.Partial[0].Stage.Name = ".lindm-transfer-../outside" },
		"invented ready":               func(p *assistanceFileIsolationProof) { p.Partial[0].ReadyFrame = []byte("ready") },
		"no native streaming report":   func(p *assistanceFileIsolationProof) { p.Partial[0].Report = nil },
		"report exceeds disk bytes":    func(p *assistanceFileIsolationProof) { p.Partial[0].Report.BytesTransferred++ },
		"unordered files":              func(p *assistanceFileIsolationProof) { p.Partial[0].Ordered = false },
		"no actual cancel frame":       func(p *assistanceFileIsolationProof) { p.CancelFrame = nil },
		"refund on cancellation":       func(p *assistanceFileIsolationProof) { p.Attempt.Audit.Details["reserved_bytes"] = "32768" },
		"cancel audit success":         func(p *assistanceFileIsolationProof) { p.Attempt.Audit.Details["result"] = "succeeded" },
		"cancel verified digest":       func(p *assistanceFileIsolationProof) { p.Attempt.Audit.Details["sha256_origin"] = "receiver_verified" },
		"no original reservation":      func(p *assistanceFileIsolationProof) { p.RequestAudit = nil },
		"no successor request":         func(p *assistanceFileIsolationProof) { p.Reservation = nil },
		"successor refunded quota":     func(p *assistanceFileIsolationProof) { p.ReservationAudit.Details["max_session_bytes"] = "67108864" },
		"successor audit other request": func(p *assistanceFileIsolationProof) {
			p.ReservationAudit.Details["request"] = p.Attempt.Report.RequestId
		},
		"retained another session": func(p *assistanceFileIsolationProof) { p.RetainedSessionID = "other" },
		"stream cancel ended session": func(p *assistanceFileIsolationProof) {
			p.RetainedPhase = adminv1.AssistanceState_ASSISTANCE_STATE_ENDED
		},
		"retained input still paused": func(p *assistanceFileIsolationProof) { p.RetainedInput.Paused = true },
	} {
		t.Run(name, func(t *testing.T) {
			s, p := isolationVerifierFixture(t)
			alter(p)
			if err := verifyFileIsolation(s, p); err == nil {
				t.Fatal("tampered isolation evidence accepted")
			}
		})
	}
}

func TestFileIsolationRequiresOrdinaryFinishAndBoundArtifacts(t *testing.T) {
	for name, alter := range map[string]func(*assistanceScenarioEvidence){
		"other scenario":       func(s *assistanceScenarioEvidence) { s.Name = "files" },
		"remote modal cancel":  func(s *assistanceScenarioEvidence) { s.ExpectedCause = "authorization_lost" },
		"ended unexpectedly":   func(s *assistanceScenarioEvidence) { s.EndCause = "connection_failed" },
		"ungranted control":    func(s *assistanceScenarioEvidence) { s.ControlGranted = false },
		"no local session":     func(s *assistanceScenarioEvidence) { s.LocalSession = nil },
		"no bound screenshots": func(s *assistanceScenarioEvidence) { s.Screenshots = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s, p := isolationVerifierFixture(t)
			alter(s)
			if err := verifyFileIsolation(s, p); err == nil {
				t.Fatal("unbound or prematurely ended isolation accepted")
			}
		})
	}
	s, p := isolationVerifierFixture(t)
	s.EndCause = "operator_stopped"
	if err := verifyFileIsolation(s, p); err != nil {
		t.Fatal(err)
	}
	if files := p.fileArtifacts(); len(files) != 2 || files[0] != p.Attempt.Source || files[1] != p.Reservation.Source {
		t.Fatal("nested sources not exposed for independent artifact rehash")
	}
	for _, path := range p.screenshotPaths() {
		if !slices.Contains(s.Screenshots, path) {
			t.Fatal("unbound nested screenshot")
		}
	}
	var absent *assistanceFileIsolationProof
	if absent.fileArtifacts() != nil || absent.screenshotPaths() != nil {
		t.Fatal("nil proof exposes evidence")
	}
}

func TestFileIsolationPrefixReplayReadsTheBoundSource(t *testing.T) {
	_, p := isolationVerifierFixture(t)
	dir := t.TempDir()
	data := bytes.Repeat([]byte("real source prefix\n"), 2048)
	data = data[:32768]
	if err := os.WriteFile(filepath.Join(dir, p.Attempt.Source.Path), data, 0600); err != nil {
		t.Fatal(err)
	}
	for i := range p.Partial {
		digest := sha256.Sum256(data[:p.Partial[i].BytesSent])
		p.Partial[i].SourcePrefixSHA256 = hex.EncodeToString(digest[:])
	}
	if err := p.verifySourcePrefixes(dir); err != nil {
		t.Fatal(err)
	}
	// Even mutually matching receiver/source claims fail when the source
	// artifact does not contain them. This test never writes native witnesses.
	p.Partial[0].SourcePrefixSHA256 = strings.Repeat("e", 64)
	p.Partial[0].Stage.SHA256 = p.Partial[0].SourcePrefixSHA256
	if err := p.verifySourcePrefixes(dir); err == nil {
		t.Fatal("self-consistent invented source prefix accepted")
	}
	if err := p.verifySourcePrefixes(t.TempDir()); err == nil {
		t.Fatal("missing source artifact accepted")
	}
}
