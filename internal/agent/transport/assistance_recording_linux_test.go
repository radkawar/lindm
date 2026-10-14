// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/rpcreason"
)

const recordingTestID = "c7f1c35e-7d70-4a64-9b3c-3c7d52a8e0e5"

type recordingRoot struct {
	assistanceRoot
	receipts [][]*agentv1.AssistanceRecordingReceipt
	chunks   []*agentv1.AssistanceRecordingChunk
}

func (r *recordingRoot) ExchangeAssistanceRecording(_ context.Context, req *connect.Request[agentv1.ExchangeAssistanceRecordingRequest]) (*connect.Response[agentv1.ExchangeAssistanceRecordingResponse], error) {
	r.receipts = append(r.receipts, req.Msg.GetReceipts())
	response := &agentv1.ExchangeAssistanceRecordingResponse{}
	if len(r.chunks) > 0 {
		response.SessionId, response.Chunks = assistanceTestSession, r.chunks
	}
	return connect.NewResponse(response), nil
}

type recordingServer struct {
	assistanceServer
	err      error
	requests []*devicev1.PutAssistanceRecordingRequest
}

func (s *recordingServer) PutAssistanceRecording(_ context.Context, req *connect.Request[devicev1.PutAssistanceRecordingRequest]) (*connect.Response[devicev1.PutAssistanceRecordingResponse], error) {
	s.requests = append(s.requests, proto.CloneOf(req.Msg))
	if s.err != nil {
		return nil, s.err
	}
	chunks := req.Msg.GetChunks()
	return connect.NewResponse(&devicev1.PutAssistanceRecordingResponse{StoredThrough: chunks[len(chunks)-1].GetSequence()}), nil
}

func newRecordingRelay(root *recordingRoot, server *recordingServer) *recordingRelay {
	return &recordingRelay{executor: root, gate: make(authorityGate, 1), cache: connectionCache{connection: proto.CloneOf(root.connection()), servers: &connections{device: server}}}
}

// The relay acknowledges only what the server stored, retries transport
// failures without a receipt and turns an explicit refusal into a final one.
func TestRecordingRelayAcknowledgesOnlyServerOutcomes(t *testing.T) {
	chunk := &agentv1.AssistanceRecordingChunk{RecordingId: recordingTestID, Sequence: 0, EncapsulatedKey: bytes.Repeat([]byte{1}, 1120), Ciphertext: bytes.Repeat([]byte{2}, 32)}
	root := &recordingRoot{chunks: []*agentv1.AssistanceRecordingChunk{chunk}}
	server := &recordingServer{}
	relay := newRecordingRelay(root, server)
	if _, err := relay.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(server.requests) != 1 || server.requests[0].GetSessionEpoch() != 1 || server.requests[0].GetSessionId() != assistanceTestSession || !proto.Equal(server.requests[0].GetChunks()[0], chunk) {
		t.Fatalf("server received %v", server.requests)
	}
	server.err = connect.NewError(connect.CodeUnavailable, errors.New("unavailable"))
	if _, err := relay.cycle(t.Context()); err == nil {
		t.Fatal("transport failure reported success")
	}
	if got := root.receipts[1]; len(got) != 1 || !got[0].GetStored() || got[0].GetStoredThrough() != 0 {
		t.Fatalf("stored receipt = %v", got)
	}
	server.err = rpcreason.Error(connect.CodeResourceExhausted, "recording_storage_full")
	if _, err := relay.cycle(t.Context()); err == nil {
		t.Fatal("refusal reported success")
	}
	if got := root.receipts[2]; len(got) != 0 {
		t.Fatalf("transport failure produced a receipt: %v", got)
	}
	root.chunks = nil
	if _, err := relay.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := root.receipts[3]; len(got) != 1 || got[0].GetRejection() != "recording_storage_full" || got[0].GetStored() {
		t.Fatalf("refusal receipt = %v", got)
	}
}

func TestRecordingRejectionRetriesFencedAndTransientFailures(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{rpcreason.Error(connect.CodeFailedPrecondition, "recording_sequence"), "recording_sequence"},
		{rpcreason.Error(connect.CodeNotFound, "recording_not_found"), "recording_not_found"},
		{rpcreason.Error(connect.CodeFailedPrecondition, "session_fenced"), ""},
		{rpcreason.Error(connect.CodePermissionDenied, "Not A Reason"), "recording_rejected"},
		{connect.NewError(connect.CodeUnavailable, errors.New("down")), ""},
		{connect.NewError(connect.CodeDeadlineExceeded, errors.New("slow")), ""},
		{errors.New("plain"), ""},
	} {
		if got := recordingRejection(test.err); got != test.want {
			t.Fatalf("%v => %q, want %q", test.err, got, test.want)
		}
	}
}
