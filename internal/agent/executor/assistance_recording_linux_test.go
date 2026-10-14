// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/rpcreason"
)

func brokerRecordingPolicy(mode agentv1.AssistancePolicyMode) *agentv1.AssistancePolicy {
	return &agentv1.AssistancePolicy{Recording: mode, RecordingLimits: &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 64 << 20}}
}

// recordingFixture drives one recorded VIEW session to OFFERED with the
// helper's recording grant.
func recordingFixture(t *testing.T, granted agentv1.AssistancePolicyMode) (*assistanceFixture, *agentv1.AssistanceDirective, *agentv1.SessionAssistanceReport) {
	t.Helper()
	f := newAssistanceFixture(t, true)
	on := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	f.broker.ceiling = brokerRecordingPolicy(on)
	directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
	directive.Invitation.RequestedCapabilities, directive.Invitation.EffectiveCapabilities = brokerRecordingPolicy(on), brokerRecordingPolicy(on)
	directive.Invitation.Recording = &agentv1.AssistanceRecordingAuthority{
		RecordingId: uuid.NewString(), Required: true, PublicKey: bytes.Repeat([]byte{1}, 1216),
		KeyId: "0000000000000000000000000000000000000000000000000000000000000000", MaxBytes: 64 << 20, RetentionDays: 30,
	}
	id := directive.GetInvitation().GetSessionId()
	f.network(directive)
	f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
	observation := report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_OFFERED)
	observation.RequestedCapabilities, observation.EffectiveCapabilities = brokerRecordingPolicy(on), brokerRecordingPolicy(on)
	observation.GrantedCapabilities = &agentv1.AssistanceCapabilities{Policy: brokerRecordingPolicy(granted)}
	if granted == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		observation.GrantedCapabilities.Policy = &agentv1.AssistancePolicy{}
	}
	f.mustHelper(1000, observation)
	return f, directive, observation
}

func recordingChunk(recordingID string, sequence uint32, final bool, fill byte) *agentv1.AssistanceRecordingChunk {
	chunk := &agentv1.AssistanceRecordingChunk{RecordingId: recordingID, Sequence: sequence, Final: final, Ciphertext: bytes.Repeat([]byte{fill}, 64)}
	if sequence == 0 {
		chunk.EncapsulatedKey = bytes.Repeat([]byte{9}, 1120)
	}
	return chunk
}

func (f *assistanceFixture) putRecording(uid uint32, sessionID string, chunk *agentv1.AssistanceRecordingChunk) error {
	return f.broker.putRecording(f.t.Context(), uid, &agentv1.PutAssistanceRecordingRequest{SessionId: sessionID, Chunk: chunk})
}

func wantRecordingRefusal(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if connect.CodeOf(err) != code || rpcreason.Get(err) != reason {
		t.Fatalf("got %v (%q), want %v %q", err, rpcreason.Get(err), code, reason)
	}
}

func TestAssistanceRecordingOutboxRelaysOnlyTheBoundGrantedRecordingInOrder(t *testing.T) {
	f, directive, observation := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
	id := directive.GetInvitation().GetSessionId()
	recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
	if err := f.putRecording(1001, id, recordingChunk(recordingID, 0, false, 1)); err == nil {
		t.Fatal("another local user's helper queued a segment")
	}
	wantRecordingRefusal(t, f.putRecording(1000, uuid.NewString(), recordingChunk(recordingID, 0, false, 1)), connect.CodeNotFound, "recording_not_found")
	wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(uuid.NewString(), 0, false, 1)), connect.CodePermissionDenied, "recording_not_authorized")
	wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, 1, false, 1)), connect.CodeFailedPrecondition, "recording_sequence")
	for sequence := range uint32(3) {
		if err := f.putRecording(1000, id, recordingChunk(recordingID, sequence, false, byte(sequence+1))); err != nil {
			t.Fatalf("segment %d: %v", sequence, err)
		}
	}
	if err := f.putRecording(1000, id, recordingChunk(recordingID, 1, false, 2)); err != nil {
		t.Fatalf("identical retry was refused: %v", err)
	}
	wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, 1, false, 7)), connect.CodeFailedPrecondition, "recording_sequence")
	exchange, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if exchange.GetSessionId() != id || len(exchange.GetChunks()) != 3 || exchange.GetChunks()[2].GetSequence() != 2 {
		t.Fatalf("exchange = %v", exchange)
	}
	// Without a receipt the same segments are offered again, never dropped.
	again, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{})
	if err != nil || !proto.Equal(again, exchange) {
		t.Fatalf("unacknowledged segments changed: %v", err)
	}
	stored, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{Receipts: []*agentv1.AssistanceRecordingReceipt{{RecordingId: recordingID, StoredThrough: 1, Stored: true}}})
	if err != nil || len(stored.GetChunks()) != 1 || stored.GetChunks()[0].GetSequence() != 2 {
		t.Fatalf("receipt did not release stored segments: %v %v", stored, err)
	}
	if err := f.putRecording(1000, id, recordingChunk(recordingID, 0, false, 1)); err != nil {
		t.Fatalf("retry of a durable segment was refused: %v", err)
	}
	observation.Recording = &agentv1.AssistanceRecordingReport{RecordingId: recordingID, State: agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING}
	f.mustHelper(1000, observation)
	if got := f.network(directive)[id].GetRecording(); got.GetState() != agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING || got.GetRecordingId() != recordingID {
		t.Fatalf("recording state did not reach the network consumer: %v", got)
	}
}

func TestAssistanceRecordingOutboxRefusesUngrantedUnreadyOrRejectedRecording(t *testing.T) {
	t.Run("declined", func(t *testing.T) {
		f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF)
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		wantRecordingRefusal(t, f.putRecording(1000, directive.GetInvitation().GetSessionId(), recordingChunk(recordingID, 0, false, 1)), connect.CodePermissionDenied, "recording_not_granted")
	})
	t.Run("before consent", func(t *testing.T) {
		f := newAssistanceFixture(t, true)
		on := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
		f.broker.ceiling = brokerRecordingPolicy(on)
		directive := &agentv1.AssistanceDirective{Invitation: f.invitation(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, "")}
		directive.Invitation.RequestedCapabilities, directive.Invitation.EffectiveCapabilities = brokerRecordingPolicy(on), brokerRecordingPolicy(on)
		directive.Invitation.Recording = &agentv1.AssistanceRecordingAuthority{RecordingId: uuid.NewString(), PublicKey: bytes.Repeat([]byte{1}, 1216), KeyId: "0000000000000000000000000000000000000000000000000000000000000000", MaxBytes: 1 << 20, RetentionDays: 1}
		id := directive.GetInvitation().GetSessionId()
		f.network(directive)
		f.mustHelper(1000, report(id, agentv1.AssistancePhase_ASSISTANCE_PHASE_PROMPTED))
		wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(directive.GetInvitation().GetRecording().GetRecordingId(), 0, false, 1)), connect.CodeFailedPrecondition, "recording_not_ready")
	})
	t.Run("device ceiling", func(t *testing.T) {
		f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
		f.broker.ceiling = &agentv1.AssistancePolicy{}
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		wantRecordingRefusal(t, f.putRecording(1000, directive.GetInvitation().GetSessionId(), recordingChunk(recordingID, 0, false, 1)), connect.CodePermissionDenied, "recording_not_authorized")
	})
	t.Run("server rejection is final", func(t *testing.T) {
		f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
		id := directive.GetInvitation().GetSessionId()
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		if err := f.putRecording(1000, id, recordingChunk(recordingID, 0, false, 1)); err != nil {
			t.Fatal(err)
		}
		exchange, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{Receipts: []*agentv1.AssistanceRecordingReceipt{{RecordingId: recordingID, Rejection: "recording_storage_full"}}})
		if err != nil || len(exchange.GetChunks()) != 0 {
			t.Fatalf("rejected recording still relayed: %v %v", exchange, err)
		}
		wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, 1, false, 1)), connect.CodeFailedPrecondition, "recording_storage_full")
	})
	t.Run("receipt beyond relayed", func(t *testing.T) {
		f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
		id := directive.GetInvitation().GetSessionId()
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		if err := f.putRecording(1000, id, recordingChunk(recordingID, 0, false, 1)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{Receipts: []*agentv1.AssistanceRecordingReceipt{{RecordingId: recordingID, StoredThrough: 5, Stored: true}}}); err != nil {
			t.Fatal(err)
		}
		wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, 1, false, 1)), connect.CodeFailedPrecondition, "recording_receipt_invalid")
	})
	t.Run("backpressure", func(t *testing.T) {
		f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
		id := directive.GetInvitation().GetSessionId()
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		for sequence := range uint32(assistanceRecordingSegments) {
			if err := f.putRecording(1000, id, recordingChunk(recordingID, sequence, false, 1)); err != nil {
				t.Fatal(err)
			}
		}
		wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, assistanceRecordingSegments, false, 1)), connect.CodeResourceExhausted, "recording_backpressure")
	})
	t.Run("final segment closes the stream", func(t *testing.T) {
		f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
		id := directive.GetInvitation().GetSessionId()
		recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
		if err := f.putRecording(1000, id, recordingChunk(recordingID, 0, true, 1)); err != nil {
			t.Fatal(err)
		}
		wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, 1, false, 1)), connect.CodeFailedPrecondition, "recording_sequence")
	})
}

func TestAssistanceRecordingSegmentsOutliveSessionEndOnlyWithinGrace(t *testing.T) {
	f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
	id := directive.GetInvitation().GetSessionId()
	recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
	if err := f.putRecording(1000, id, recordingChunk(recordingID, 0, false, 1)); err != nil {
		t.Fatal(err)
	}
	directive.Terminate, directive.TerminateCause = true, agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_ENDED
	f.network(directive)
	// The logout already happened: the final segment sealed before it still
	// drains for the same bound user.
	f.setLogind("2", func(session *actionprovider.LogindSession) { session.Active = false })
	if err := f.putRecording(1000, id, recordingChunk(recordingID, 1, true, 2)); err != nil {
		t.Fatalf("final segment after end: %v", err)
	}
	f.network()
	if exchange, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{}); err != nil || len(exchange.GetChunks()) != 2 {
		t.Fatalf("pending segments were forgotten with the session: %v %v", exchange, err)
	}
	f.advance(assistanceRecordingGrace + time.Second)
	wantRecordingRefusal(t, f.putRecording(1000, id, recordingChunk(recordingID, 2, false, 3)), connect.CodeFailedPrecondition, "recording_not_active")
	f.network()
	if exchange, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{}); err != nil || len(exchange.GetChunks()) != 0 {
		t.Fatalf("segments survived the grace: %v %v", exchange, err)
	}
}

func TestAssistanceRecordingReportMustNameTheGrantedRecording(t *testing.T) {
	f, directive, observation := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
	id := directive.GetInvitation().GetSessionId()
	observation.Recording = &agentv1.AssistanceRecordingReport{RecordingId: uuid.NewString(), State: agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING}
	f.mustHelper(1000, observation)
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)

	f, directive, observation = recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF)
	id = directive.GetInvitation().GetSessionId()
	observation.Recording = &agentv1.AssistanceRecordingReport{RecordingId: directive.GetInvitation().GetRecording().GetRecordingId(), State: agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING}
	f.mustHelper(1000, observation)
	wantEnded(t, f.network(directive)[id], agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST)
}

// Full-size segments are relayed within the broker's own admission bound:
// a 900 KiB exchange of two full segments failed every relay invalid_request
// (layers-fedora44-tier2-06).
func TestAssistanceRecordingExchangeOfFullSegmentsIsAdmitted(t *testing.T) {
	f, directive, _ := recordingFixture(t, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON)
	id := directive.GetInvitation().GetSessionId()
	recordingID := directive.GetInvitation().GetRecording().GetRecordingId()
	for sequence := range uint32(4) {
		chunk := recordingChunk(recordingID, sequence, false, byte(sequence+1))
		chunk.Ciphertext = bytes.Repeat([]byte{byte(sequence + 1)}, 196624)
		if err := f.putRecording(1000, id, chunk); err != nil {
			t.Fatalf("segment %d: %v", sequence, err)
		}
	}
	relayed := uint32(0)
	for relayed < 4 {
		var receipts []*agentv1.AssistanceRecordingReceipt
		if relayed > 0 {
			receipts = []*agentv1.AssistanceRecordingReceipt{{RecordingId: recordingID, StoredThrough: relayed - 1, Stored: true}}
		}
		exchange, err := f.broker.exchangeRecording(&agentv1.ExchangeAssistanceRecordingRequest{Receipts: receipts})
		if err != nil {
			t.Fatalf("exchange after %d segments: %v", relayed, err)
		}
		if len(exchange.GetChunks()) == 0 || proto.Size(exchange) > assistanceBrokerMessageBytes || exchange.GetChunks()[0].GetSequence() != relayed {
			t.Fatalf("exchange after %d segments carried %d chunks, %d bytes", relayed, len(exchange.GetChunks()), proto.Size(exchange))
		}
		relayed += uint32(len(exchange.GetChunks()))
	}
}
