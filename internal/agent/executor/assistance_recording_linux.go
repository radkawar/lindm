// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/rpcreason"
)

// The executor relays sealed recording segments without seeing plaintext. Its
// outbox is bounded per session; a full outbox applies backpressure to the
// helper rather than dropping or reordering segments.
const (
	assistanceRecordingSegments = 16
	assistanceRecordingBytes    = 4 << 20
	assistanceRecordingExchange = 4
	// assistanceRecordingWire bounds one exchange's encoded chunks so the
	// response passes the broker's own admission bound with its session id:
	// at 900 KiB, two full segments exceeded it and every relay failed
	// invalid_request, so no recording completed (layers-fedora44-tier2-06).
	assistanceRecordingWire = assistanceBrokerMessageBytes - 1<<10
	// assistanceRecordingChunkFraming is a repeated field's tag and length.
	assistanceRecordingChunkFraming = 8
	// Segments sealed before a session ended may still be relayed this long.
	assistanceRecordingGrace = time.Minute
)

type assistanceRecordingOutbox struct {
	recordingID string
	next        uint32
	pending     []*agentv1.AssistanceRecordingChunk
	digests     map[uint32][32]byte
	bytes       int
	// stored is one past the highest sequence the server reported durable.
	stored    uint32
	finalSeen bool
	rejected  string
}

func recordingError(code connect.Code, reason string) error {
	return rpcreason.Error(code, reason)
}

// putRecording admits one helper segment for the caller's own bound session.
func (b *assistanceBroker) putRecording(ctx context.Context, uid uint32, req *agentv1.PutAssistanceRecordingRequest) error {
	if uid == 0 {
		return errNoGraphicalSession
	}
	if err := b.admit(req); err != nil {
		return err
	}
	found, lookupErr := b.lookup(ctx, func(_ string, owner uint32) bool { return owner == uid })
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.expire(now)
	if lookupErr != nil {
		return errLogindUnavailable
	}
	local, err := b.eligible(uid, found)
	session := b.sessions[req.GetSessionId()]
	if session == nil {
		return recordingError(connect.CodeNotFound, "recording_not_found")
	}
	if err != nil {
		// A locked, inactive or vanished login still drains segments sealed
		// before its session ended, but only for that bound login.
		if session.phase != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED || session.local == nil || session.local.GetUid() != uid {
			return err
		}
		local = session.local
	}
	chunk := req.GetChunk()
	authority := session.invitation.GetRecording()
	switch {
	case session.local == nil || !sameLocalSession(session.local, local):
		return recordingError(connect.CodePermissionDenied, "permission_denied")
	case authority == nil || authority.GetRecordingId() != chunk.GetRecordingId():
		return recordingError(connect.CodePermissionDenied, "recording_not_authorized")
	case assistancePolicyIntersection(session.invitation.GetEffectiveCapabilities(), b.ceiling).GetRecording() == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF:
		return recordingError(connect.CodePermissionDenied, "recording_not_authorized")
	case !session.capabilitiesSet:
		return recordingError(connect.CodeFailedPrecondition, "recording_not_ready")
	case assistancePolicyMode(session.granted.GetPolicy().GetRecording()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF:
		return recordingError(connect.CodePermissionDenied, "recording_not_granted")
	case session.phase == agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED && now.Sub(session.endedAt) >= assistanceRecordingGrace:
		return recordingError(connect.CodeFailedPrecondition, "recording_not_active")
	}
	outbox := session.recording
	if outbox == nil {
		outbox = &assistanceRecordingOutbox{recordingID: authority.GetRecordingId(), digests: make(map[uint32][32]byte)}
		session.recording = outbox
	}
	if outbox.rejected != "" {
		return recordingError(connect.CodeFailedPrecondition, outbox.rejected)
	}
	digest := sha256.Sum256(chunk.GetCiphertext())
	sequence := chunk.GetSequence()
	switch {
	case sequence < outbox.stored:
		// Already durable on the server: a retried put is idempotent.
		return nil
	case sequence < outbox.next:
		if old, ok := outbox.digests[sequence]; ok && old == digest {
			return nil
		}
		return recordingError(connect.CodeFailedPrecondition, "recording_sequence")
	case sequence > outbox.next || outbox.finalSeen:
		return recordingError(connect.CodeFailedPrecondition, "recording_sequence")
	case len(outbox.pending) >= assistanceRecordingSegments || outbox.bytes+len(chunk.GetCiphertext()) > assistanceRecordingBytes:
		return recordingError(connect.CodeResourceExhausted, "recording_backpressure")
	}
	outbox.pending = append(outbox.pending, proto.CloneOf(chunk))
	outbox.digests[sequence] = digest
	outbox.bytes += len(chunk.GetCiphertext())
	outbox.next++
	outbox.finalSeen = chunk.GetFinal()
	return nil
}

// exchangeRecording applies the network process's server receipts and returns
// the next contiguous segments of one session, oldest session first.
func (b *assistanceBroker) exchangeRecording(req *agentv1.ExchangeAssistanceRecordingRequest) (*agentv1.ExchangeAssistanceRecordingResponse, error) {
	if err := b.admit(req); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, receipt := range req.GetReceipts() {
		for _, session := range b.sessions {
			outbox := session.recording
			if outbox == nil || outbox.recordingID != receipt.GetRecordingId() {
				continue
			}
			if receipt.GetRejection() != "" {
				outbox.rejected = receipt.GetRejection()
				outbox.pending, outbox.bytes = nil, 0
				continue
			}
			through := receipt.GetStoredThrough() + 1
			if through > outbox.next {
				// The server cannot store what the executor never relayed.
				outbox.rejected = "recording_receipt_invalid"
				outbox.pending, outbox.bytes = nil, 0
				continue
			}
			outbox.stored = max(outbox.stored, through)
			kept := outbox.pending[:0]
			for _, chunk := range outbox.pending {
				if chunk.GetSequence() < outbox.stored {
					outbox.bytes -= len(chunk.GetCiphertext())
					delete(outbox.digests, chunk.GetSequence())
					continue
				}
				kept = append(kept, chunk)
			}
			outbox.pending = kept
		}
	}
	response := &agentv1.ExchangeAssistanceRecordingResponse{}
	for _, session := range b.ordered() {
		outbox := session.recording
		if outbox == nil || outbox.rejected != "" || len(outbox.pending) == 0 {
			continue
		}
		size := 0
		for _, chunk := range outbox.pending {
			chunkSize := proto.Size(chunk) + assistanceRecordingChunkFraming
			if len(response.Chunks) == assistanceRecordingExchange || (len(response.Chunks) > 0 && size+chunkSize > assistanceRecordingWire) {
				break
			}
			response.Chunks = append(response.Chunks, proto.CloneOf(chunk))
			size += chunkSize
		}
		response.SessionId = session.invitation.GetSessionId()
		break
	}
	if err := b.admit(response); err != nil {
		return nil, err
	}
	return response, nil
}

// recordingRetained keeps an ended session while its sealed segments are
// still being relayed within the grace.
func recordingRetained(session *assistanceSession, now time.Time) bool {
	outbox := session.recording
	return outbox != nil && outbox.rejected == "" && len(outbox.pending) > 0 && now.Sub(session.endedAt) < assistanceRecordingGrace
}

// applyRecordingReport accepts the helper's content-free recording state for
// the invitation's own recording only.
func applyRecordingReport(session *assistanceSession, report *agentv1.AssistanceRecordingReport) bool {
	if report == nil {
		return true
	}
	authority := session.invitation.GetRecording()
	if authority == nil || report.GetRecordingId() != authority.GetRecordingId() || assistancePolicyMode(session.granted.GetPolicy().GetRecording()) == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF {
		return false
	}
	previous := session.recordingReport.GetState()
	if previous == agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_FAILED && report.GetState() != previous {
		return false
	}
	session.recordingReport = proto.CloneOf(report)
	return true
}
