// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancerecording"
	"lindm/internal/rpcreason"
)

func testRecipient(t *testing.T) *assistancerecording.Recipient {
	t.Helper()
	seed := make([]byte, assistancerecording.PrivateKeySeedBytes)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	recipient, err := assistancerecording.NewRecipient(seed)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

func recordingInvitation(t *testing.T, recipient *assistancerecording.Recipient, required bool) *agentv1.AssistanceInvitation {
	t.Helper()
	inv := invitation(modeView, time.Minute, 10*time.Minute)
	mode := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if required {
		mode = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	}
	policy := &agentv1.AssistancePolicy{Recording: mode, RecordingLimits: &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 64 << 20}}
	inv.RequestedCapabilities, inv.EffectiveCapabilities = policy, policy
	inv.Recording = &agentv1.AssistanceRecordingAuthority{
		RecordingId: uuid.NewString(), Required: required, PublicKey: recipient.PublicKey(), KeyId: recipient.KeyID(), MaxBytes: 64 << 20, RetentionDays: 30,
	}
	return inv
}

// vp8Packet is one RFC 7741 packet carrying a whole frame.
func vp8Packet(sequence uint16, timestamp uint32, keyframe bool, payload byte) []byte {
	packet := make([]byte, 12, 16)
	packet[0], packet[1] = 0x80, 0x80|rtpPayloadType
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], timestamp)
	binary.BigEndian.PutUint32(packet[8:12], 7)
	frame := byte(0x01)
	if keyframe {
		frame = 0x00
	}
	return append(packet, 0x10, frame, payload, payload)
}

func (h *harness) feed(packets ...[]byte) {
	h.t.Helper()
	for _, packet := range packets {
		select {
		case h.capturer.capture.packets <- packet:
		case <-time.After(5 * time.Second):
			h.t.Fatal("capture did not accept packet")
		}
	}
}

func (h *harness) uploaded() []*agentv1.PutAssistanceRecordingRequest {
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	return slices.Clone(h.client.recordings)
}

// openRecording decrypts the uploaded segments as the server's retrieval does.
func openRecording(t *testing.T, recipient *assistancerecording.Recipient, uploads []*agentv1.PutAssistanceRecordingRequest) []byte {
	t.Helper()
	if len(uploads) == 0 || uploads[0].GetChunk().GetSequence() != 0 {
		t.Fatal("recording has no first segment")
	}
	id := uuid.MustParse(uploads[0].GetChunk().GetRecordingId())
	opener, err := recipient.Open(id, uploads[0].GetChunk().GetEncapsulatedKey())
	if err != nil {
		t.Fatal(err)
	}
	var stream []byte
	for i, upload := range uploads {
		chunk := upload.GetChunk()
		if chunk.GetSequence() != uint32(i) || chunk.GetFinal() != (i == len(uploads)-1) {
			t.Fatalf("segment %d: sequence %d final %v", i, chunk.GetSequence(), chunk.GetFinal())
		}
		plaintext, err := opener.Open(chunk.GetSequence(), chunk.GetFinal(), chunk.GetCiphertext())
		if err != nil {
			t.Fatalf("segment %d does not authenticate: %v", i, err)
		}
		stream = append(stream, plaintext...)
	}
	return stream
}

func TestOptionalRecordingIsDisclosedChosenLocallyAndSealedBeforeUpload(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.recordingFlush = 10 * time.Millisecond
	recipient := testRecipient(t)
	inv := recordingInvitation(t, recipient, false)
	h.sync(directiveFor(inv))
	prompt := h.notifier.next(t, "Remote assistance request (recording requested)")
	body := prompt.notification.Body
	if !strings.Contains(body, "asks to record this session") || !strings.Contains(body, "up to 30 days") || !strings.Contains(body, "play it back later") {
		t.Fatalf("prompt does not disclose recording and later archive access: %q", body)
	}
	var keys []string
	for _, action := range prompt.notification.Actions {
		keys = append(keys, action.Key)
	}
	if !slices.Equal(keys, []string{actionAllowRecord, actionAllow, actionDecline}) {
		t.Fatalf("optional recording actions = %v", keys)
	}
	if len(h.uploaded()) != 0 {
		t.Fatal("recording began before consent")
	}
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	prompt.result <- actionAllowRecord
	report := h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	if report.GetGrantedCapabilities().GetPolicy().GetRecording() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || report.GetRecording().GetState() != agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING {
		t.Fatalf("recording grant/report = %v %v", report.GetGrantedCapabilities(), report.GetRecording())
	}
	indicator := h.notifier.next(t, "Remote assistance in progress — recording")
	if !strings.Contains(indicator.notification.Body, "being recorded") || !slices.ContainsFunc(indicator.notification.Actions, func(a NotificationAction) bool { return a.Key == actionStopRecording }) {
		t.Fatalf("continuous indicator lacks recording disclosure or local stop: %+v", indicator.notification)
	}
	h.feed(vp8Packet(10, 9000, true, 0xA1), vp8Packet(11, 15000, false, 0xA2))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.uploaded()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for _, upload := range h.uploaded() {
		if bytes.Contains(upload.GetChunk().GetCiphertext(), []byte("V_VP8")) || bytes.Contains(upload.GetChunk().GetCiphertext(), []byte{0xA1, 0xA1}) {
			t.Fatal("a recording segment left the helper in plaintext")
		}
	}
	h.sync(&agentv1.AssistanceDirective{Invitation: inv, Terminate: true})
	h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED)
	stream := openRecording(t, recipient, h.uploaded())
	if !bytes.Contains(stream, []byte("webm")) || !bytes.Contains(stream, []byte("V_VP8")) || !bytes.Contains(stream, []byte{0xA1, 0xA1}) {
		t.Fatal("decrypted recording is not the consented WebM stream")
	}
	if state := h.report().GetRecording(); state.GetState() != agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_STOPPED {
		t.Fatalf("final recording state = %v", state)
	}
}

func TestOptionalRecordingDeclinedIsNeverCaptured(t *testing.T) {
	h := newHarness(t)
	recipient := testRecipient(t)
	report := h.offered(directiveFor(recordingInvitation(t, recipient, false)))
	if report.GetGrantedCapabilities().GetPolicy().GetRecording() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || report.GetGrantedCapabilities().GetRecordingReason() != "user_declined" || report.GetRecording() != nil {
		t.Fatalf("declined recording was granted: %v", report)
	}
	indicator := h.notifier.next(t, "Remote assistance in progress")
	if strings.Contains(indicator.notification.Body, "recorded") {
		t.Fatalf("indicator claims recording: %q", indicator.notification.Body)
	}
	h.feed(vp8Packet(10, 9000, true, 0xA1))
	time.Sleep(50 * time.Millisecond)
	if len(h.uploaded()) != 0 {
		t.Fatal("declined recording uploaded segments")
	}
}

func TestRequiredRecordingIsRefusedBeforePromptWhenItCannotBeHonoured(t *testing.T) {
	recipient := testRecipient(t)
	for name, setup := range map[string]func(*harness, *agentv1.AssistanceInvitation) string{
		"release gate": func(h *harness, _ *agentv1.AssistanceInvitation) string {
			h.helper.deps.recordingUnavailableReason = "platform_recording_unqualified"
			return "recording_unavailable"
		},
		"policy downgrade": func(_ *harness, inv *agentv1.AssistanceInvitation) string {
			inv.EffectiveCapabilities.Recording = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
			return "recording_not_permitted"
		},
		"substituted key": func(_ *harness, inv *agentv1.AssistanceInvitation) string {
			inv.Recording.KeyId = strings.Repeat("0", 64)
			return "recording_key_invalid"
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			inv := recordingInvitation(t, recipient, true)
			detail := setup(h, inv)
			h.sync(directiveFor(inv))
			if detail == "recording_key_invalid" {
				prompt := h.notifier.next(t, "Remote assistance request (recorded)")
				if !strings.Contains(prompt.notification.Body, "cannot start without recording") || prompt.notification.Actions[0].Label != "Allow (recorded)" {
					t.Fatalf("required recording prompt = %+v", prompt.notification)
				}
				h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
				prompt.result <- actionAllow
			}
			report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED)
			if report.GetEndDetail() != detail {
				t.Fatalf("detail = %q, want %q", report.GetEndDetail(), detail)
			}
			if detail != "recording_key_invalid" && h.portal.openCount() != 0 {
				t.Fatal("portal opened for a session that could not be recorded")
			}
			if len(h.capturer.requests) != 0 {
				t.Fatal("capture started without recording")
			}
		})
	}
}

func TestRequiredRecordingStorageRefusalEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.recordingFlush = 10 * time.Millisecond
	h.client.recordingErr = rpcreason.Error(connect.CodeFailedPrecondition, "recording_storage_full")
	recipient := testRecipient(t)
	h.offered(directiveFor(recordingInvitation(t, recipient, true)))
	report := h.waitEnded(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_RECORDING_FAILED)
	if report.GetEndDetail() != "recording_failed" || report.GetRecording().GetState() != agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_FAILED || report.GetRecording().GetReason() != "recording_storage_full" {
		t.Fatalf("report = %v", report)
	}
}

func TestOptionalRecordingStopIsLocalAndRepostsTheIndicator(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.recordingFlush = 10 * time.Millisecond
	recipient := testRecipient(t)
	inv := recordingInvitation(t, recipient, false)
	h.sync(directiveFor(inv))
	prompt := h.notifier.next(t, "Remote assistance request (recording requested)")
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	prompt.result <- actionAllowRecord
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	indicator := h.notifier.next(t, "Remote assistance in progress — recording")
	h.feed(vp8Packet(10, 9000, true, 0xB1))
	indicator.result <- actionStopRecording
	next := h.notifier.next(t, "Remote assistance in progress")
	if strings.Contains(next.notification.Body, "recorded") {
		t.Fatalf("indicator still claims recording after stop: %+v", next.notification)
	}
	report := h.report()
	if report.GetPhase() == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED || report.GetRecording().GetState() != agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_STOPPED || report.GetRecording().GetReason() != "user_stopped" {
		t.Fatalf("stopping optional recording ended the session or was not reported: %v", report)
	}
	uploads := h.uploaded()
	if len(uploads) == 0 || !uploads[len(uploads)-1].GetChunk().GetFinal() {
		t.Fatal("stopped recording was not sealed with a final segment")
	}
	before := len(uploads)
	h.feed(vp8Packet(11, 18000, true, 0xB2))
	time.Sleep(50 * time.Millisecond)
	if len(h.uploaded()) != before {
		t.Fatal("frames after the local stop were recorded")
	}
	openRecording(t, recipient, h.uploaded())
}

func TestReconnectPromptRequiresFreshChoice(t *testing.T) {
	h := newHarness(t)
	inv := invitation(modeView, time.Minute, 10*time.Minute)
	policy := &agentv1.AssistancePolicy{Reconnect: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, ReconnectLimits: &agentv1.AssistanceReconnectPolicy{WindowSeconds: 900, MaxReconnects: 2}}
	inv.RequestedCapabilities, inv.EffectiveCapabilities = policy, policy
	inv.ReconnectOf = uuid.NewString()
	h.sync(directiveFor(inv))
	prompt := h.notifier.next(t, "Remote assistance reconnect request")
	body := prompt.notification.Body
	if !strings.Contains(body, "Nothing you allowed before carries over") || !strings.Contains(body, "automatically for 15 minutes") || !strings.Contains(body, "You will be asked again") {
		t.Fatalf("reconnect prompt = %q", body)
	}
	if h.portal.openCount() != 0 {
		t.Fatal("a reconnect reused a portal grant before consent")
	}
	h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED)
	prompt.result <- actionAllow
	report := h.waitPhase(agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	if report.GetGrantedCapabilities().GetPolicy().GetReconnect() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON || h.portal.openCount() != 1 {
		t.Fatalf("reconnect grant = %v opens=%d", report.GetGrantedCapabilities(), h.portal.openCount())
	}
}

func TestReconnectReleaseGateWithholdsWorkflow(t *testing.T) {
	h := newHarness(t)
	h.helper.deps.reconnectUnavailableReason = "platform_reconnect_unqualified"
	inv := invitation(modeView, time.Minute, 10*time.Minute)
	policy := &agentv1.AssistancePolicy{Reconnect: agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED, ReconnectLimits: &agentv1.AssistanceReconnectPolicy{WindowSeconds: 600, MaxReconnects: 1}}
	inv.RequestedCapabilities, inv.EffectiveCapabilities = policy, policy
	report := h.offered(directiveFor(inv))
	if report.GetGrantedCapabilities().GetPolicy().GetReconnect() != agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF || report.GetGrantedCapabilities().GetReconnectReason() != "platform_reconnect_unqualified" {
		t.Fatalf("gated reconnect was granted: %v", report.GetGrantedCapabilities())
	}
}

func TestVP8AssemblerNeverRecordsIncompleteFrames(t *testing.T) {
	var a vp8Assembler
	if _, _, key, ok := a.push(vp8Packet(1, 100, true, 1)); !ok || !key {
		t.Fatal("whole keyframe not assembled")
	}
	start := vp8Packet(2, 200, false, 2)
	start[1] &^= 0x80
	if _, _, _, ok := a.push(start); ok {
		t.Fatal("frame without marker completed")
	}
	if _, _, _, ok := a.push(vp8Packet(4, 300, false, 3)); ok {
		t.Fatal("an inter frame after a sequence gap was recorded")
	}
	continuation := vp8Packet(5, 400, true, 4)
	continuation[12] = 0x00
	if _, _, _, ok := a.push(continuation); ok {
		t.Fatal("frame without its partition start was recorded")
	}
	if _, _, key, ok := a.push(vp8Packet(6, 500, true, 5)); !ok || !key {
		t.Fatal("the next keyframe did not resume recording")
	}
	start32 := uint32(0xFFFFFF00)
	clock := rtpClock{last: start32}
	if got := clock.millis(start32 + 9000); got != 100 {
		t.Fatalf("clock across wrap = %d", got)
	}
}
