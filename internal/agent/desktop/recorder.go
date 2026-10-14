// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/assistancerecording"
	"lindm/internal/rpcreason"
)

// Recorder bounds. Plaintext exists only in these bounded session buffers;
// every byte handed to the executor is already sealed.
const (
	recorderPacketQueue   = 512
	recorderSegmentQueue  = 24
	recorderFlushInterval = 2 * time.Second
	// Without a stored segment for this long a recording has failed.
	recorderUploadStall = 20 * time.Second
	recorderRetry       = 250 * time.Millisecond
	recorderFinishLimit = 20 * time.Second
)

// recordingSink is the executor's SessionService upload boundary.
type recordingSink interface {
	PutAssistanceRecording(context.Context, *connect.Request[agentv1.PutAssistanceRecordingRequest]) (*connect.Response[agentv1.PutAssistanceRecordingResponse], error)
}

// recorder turns the consented, already-encoded VP8 RTP stream into a WebM
// stream sealed segment by segment before it leaves this process. It never
// records anything the session does not send to the operator, and nothing
// after it stops.
type recorder struct {
	sessionID string
	authority *agentv1.AssistanceRecordingAuthority
	sink      recordingSink
	logger    *slog.Logger
	clock     func() time.Time
	failed    func(reason string)
	timeout   time.Duration
	flush     time.Duration

	packets  chan []byte
	segments chan *agentv1.AssistanceRecordingChunk
	stop     chan bool
	abort    chan struct{}
	done     chan struct{}

	mu       sync.Mutex
	state    agentv1.AssistanceRecordingState
	reason   string
	stopping bool
}

func newRecorder(sessionID string, authority *agentv1.AssistanceRecordingAuthority, sink recordingSink, logger *slog.Logger, clock func() time.Time, timeout, flush time.Duration, failed func(string)) *recorder {
	return &recorder{
		sessionID: sessionID, authority: authority, sink: sink, logger: logger, clock: clock, failed: failed, timeout: timeout, flush: flush,
		packets:  make(chan []byte, recorderPacketQueue),
		segments: make(chan *agentv1.AssistanceRecordingChunk, recorderSegmentQueue),
		stop:     make(chan bool, 1),
		abort:    make(chan struct{}),
		done:     make(chan struct{}),
		state:    agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING,
	}
}

// start begins sealing. width and height describe the first shared display.
// The recorder outlives session cancellation until finish seals and uploads
// its final segment.
func (r *recorder) start(width, height uint32) error {
	id, err := uuid.Parse(r.authority.GetRecordingId())
	if err != nil {
		return err
	}
	sealer, err := assistancerecording.NewSealer(r.authority.GetPublicKey(), r.authority.GetKeyId(), id)
	if err != nil {
		return err
	}
	go r.upload()
	go r.assemble(sealer, width, height)
	return nil
}

// report is the content-free recording observation.
func (r *recorder) report() *agentv1.AssistanceRecordingReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &agentv1.AssistanceRecordingReport{RecordingId: r.authority.GetRecordingId(), State: r.state, Reason: r.reason}
}

func (r *recorder) recording() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state == agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING && !r.stopping
}

// write offers one consented RTP packet. A full queue is a failure, never a
// silent gap in a recording the user was told is complete.
func (r *recorder) write(packet []byte) {
	if !r.recording() {
		return
	}
	select {
	case r.packets <- append([]byte(nil), packet...):
	default:
		r.fail("recording_backpressure")
	}
}

// finish stops capture into the recording, seals the final segment and waits
// a bounded time for upload. reason is the local stop reason, if any.
func (r *recorder) finish(reason string) {
	r.mu.Lock()
	if !r.stopping {
		r.stopping = true
		if r.state == agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING && reason != "" {
			r.reason = reason
		}
		select {
		case r.stop <- true:
		default:
		}
	}
	r.mu.Unlock()
	timer := time.NewTimer(recorderFinishLimit)
	defer timer.Stop()
	select {
	case <-r.done:
	case <-timer.C:
		r.fail("recording_upload_timeout")
		<-r.done
	}
}

// fail ends the recording without a complete archive. It is final: a stopped
// recording whose final segment cannot be stored has also failed.
func (r *recorder) fail(reason string) {
	r.mu.Lock()
	if r.state == agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_FAILED {
		r.mu.Unlock()
		return
	}
	r.state, r.reason, r.stopping = agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_FAILED, reason, true
	select {
	case r.stop <- false:
	default:
	}
	close(r.abort)
	r.mu.Unlock()
	r.logger.Warn("remote assistance recording failed", "session_id", r.sessionID, "reason", reason)
	if r.failed != nil {
		r.failed(reason)
	}
}

func (r *recorder) stopped(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_RECORDING {
		r.state = agentv1.AssistanceRecordingState_ASSISTANCE_RECORDING_STATE_STOPPED
		if r.reason == "" {
			r.reason = reason
		}
	}
}

// assemble depacketizes VP8, muxes WebM and seals bounded segments.
func (r *recorder) assemble(sealer *assistancerecording.Sealer, width, height uint32) {
	defer close(r.segments)
	var (
		mux       assistancerecording.WebM
		frames    vp8Assembler
		pending   = mux.Header(width, height)
		total     uint64
		ticker    = time.NewTicker(r.flush)
		clockBase *rtpClock
	)
	defer ticker.Stop()
	// seal emits full segments, or everything when force is set. It keeps a
	// minimum final segment within max_bytes so the recording can always be
	// closed authentically.
	seal := func(final, force bool) bool {
		for len(pending) >= assistancerecording.SegmentPlaintextBytes || (force && (len(pending) > 0 || final)) {
			size := min(len(pending), assistancerecording.SegmentPlaintextBytes)
			last := final && size == len(pending)
			reserve := uint64(assistancerecording.SegmentOverhead)
			if last {
				reserve = 0
			}
			if total+uint64(size+assistancerecording.SegmentOverhead)+reserve > r.authority.GetMaxBytes() {
				r.fail("recording_size_limit")
				return false
			}
			sequence, sealed, err := sealer.Seal(last, pending[:size])
			clear(pending[:size])
			pending = pending[size:]
			if err != nil {
				r.fail("recording_seal_failed")
				return false
			}
			chunk := &agentv1.AssistanceRecordingChunk{RecordingId: r.authority.GetRecordingId(), Sequence: sequence, Final: last, Ciphertext: sealed}
			if sequence == 0 {
				chunk.EncapsulatedKey = sealer.EncapsulatedKey()
			}
			select {
			case r.segments <- chunk:
			default:
				r.fail("recording_backpressure")
				return false
			}
			total += uint64(len(sealed))
			if last {
				return true
			}
		}
		return true
	}
	for {
		select {
		case <-r.abort:
			clear(pending)
			return
		case final := <-r.stop:
			if !final {
				clear(pending)
				return
			}
			// Drain packets accepted before the stop; nothing after it.
			for drained := false; !drained; {
				select {
				case packet := <-r.packets:
					pending = r.frame(&mux, &frames, &clockBase, packet, pending)
				default:
					drained = true
				}
			}
			pending = append(pending, mux.Flush()...)
			if seal(true, true) {
				r.stopped(r.currentReason())
			}
			clear(pending)
			return
		case packet := <-r.packets:
			pending = r.frame(&mux, &frames, &clockBase, packet, pending)
			if pending == nil {
				return
			}
			if !seal(false, false) {
				clear(pending)
				return
			}
		case <-ticker.C:
			// Bound the plaintext held in memory and the data lost to a crash.
			if len(pending) > 0 && !seal(false, true) {
				clear(pending)
				return
			}
		}
	}
}

func (r *recorder) currentReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reason == "" {
		return "session_ended"
	}
	return r.reason
}

// frame adds one packet's completed frame to pending. It returns nil after
// a fatal failure.
func (r *recorder) frame(mux *assistancerecording.WebM, frames *vp8Assembler, clock **rtpClock, packet []byte, pending []byte) []byte {
	frame, timestamp, keyframe, ok := frames.push(packet)
	if !ok {
		return pending
	}
	if *clock == nil {
		if !keyframe {
			return pending
		}
		*clock = &rtpClock{last: timestamp}
	}
	closed, err := mux.Frame((*clock).millis(timestamp), keyframe, frame)
	if err != nil {
		r.fail("recording_frame_invalid")
		return nil
	}
	return append(pending, closed...)
}

// upload hands sealed segments to the executor in order with bounded retry.
func (r *recorder) upload() {
	defer close(r.done)
	for chunk := range r.segments {
		if !r.put(chunk) {
			r.drain()
			return
		}
		clear(chunk.Ciphertext)
	}
}

func (r *recorder) put(chunk *agentv1.AssistanceRecordingChunk) bool {
	started := r.clock()
	for {
		select {
		case <-r.abort:
			return false
		default:
		}
		call, cancel := context.WithTimeout(context.Background(), r.timeout)
		_, err := r.sink.PutAssistanceRecording(call, connect.NewRequest(&agentv1.PutAssistanceRecordingRequest{SessionId: r.sessionID, Chunk: chunk}))
		cancel()
		if err == nil {
			return true
		}
		switch connect.CodeOf(err) {
		case connect.CodeResourceExhausted, connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeUnknown:
		case connect.CodeFailedPrecondition:
			if rpcreason.Get(err) != "recording_not_ready" {
				r.fail(uploadReason(err))
				return false
			}
		default:
			r.fail(uploadReason(err))
			return false
		}
		if r.clock().Sub(started) >= recorderUploadStall {
			r.fail("recording_upload_stalled")
			return false
		}
		timer := time.NewTimer(recorderRetry)
		select {
		case <-timer.C:
		case <-r.abort:
			timer.Stop()
			return false
		}
	}
}

func (r *recorder) drain() {
	for chunk := range r.segments {
		clear(chunk.Ciphertext)
	}
}

func uploadReason(err error) string {
	reason := rpcreason.Get(err)
	if reason == "" || len(reason) > 64 {
		return "recording_upload_rejected"
	}
	for _, c := range reason {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "recording_upload_rejected"
		}
	}
	return reason
}

// rtpClock converts the session's continuous 90 kHz RTP clock to elapsed
// milliseconds across 32-bit wraparound.
type rtpClock struct {
	last  uint32
	ticks int64
}

func (c *rtpClock) millis(timestamp uint32) int64 {
	c.ticks += int64(int32(timestamp - c.last))
	c.last = timestamp
	return max(c.ticks, 0) / 90
}

// vp8Assembler rebuilds whole VP8 frames from RFC 7741 packets. A sequence
// gap or a frame without its marker is dropped rather than recorded corrupt,
// and later inter frames wait for the next keyframe they could decode from.
type vp8Assembler struct {
	frame     []byte
	timestamp uint32
	keyframe  bool
	valid     bool
	needKey   bool
	sequence  uint16
	sequenced bool
}

func (a *vp8Assembler) drop() {
	a.valid, a.needKey = false, true
}

func (a *vp8Assembler) push(packet []byte) ([]byte, uint32, bool, bool) {
	var header rtp.Packet
	if err := header.Unmarshal(packet); err != nil {
		a.drop()
		return nil, 0, false, false
	}
	if a.sequenced && header.SequenceNumber != a.sequence+1 {
		a.drop()
	}
	a.sequence, a.sequenced = header.SequenceNumber, true
	if a.valid && header.Timestamp != a.timestamp {
		a.drop()
	}
	var vp8 codecs.VP8Packet
	payload, err := vp8.Unmarshal(header.Payload)
	if err != nil || len(payload) == 0 {
		a.drop()
		return nil, 0, false, false
	}
	if vp8.S == 1 && vp8.PID == 0 {
		a.frame = append(a.frame[:0], payload...)
		a.timestamp, a.keyframe, a.valid = header.Timestamp, payload[0]&0x01 == 0, true
	} else if a.valid {
		if len(a.frame)+len(payload) > assistancerecording.MaxFrameBytes {
			a.drop()
			return nil, 0, false, false
		}
		a.frame = append(a.frame, payload...)
	}
	if !header.Marker || !a.valid {
		return nil, 0, false, false
	}
	a.valid = false
	if a.needKey && !a.keyframe {
		return nil, 0, false, false
	}
	a.needKey = false
	return a.frame, a.timestamp, a.keyframe, true
}
