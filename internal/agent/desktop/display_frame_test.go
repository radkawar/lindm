package desktop

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func decodeDisplayFrame(t *testing.T, message string) DisplayFrame {
	t.Helper()
	if len(message) > maxInputMessageBytes {
		t.Fatalf("oversized marker: %d", len(message))
	}
	var decoded struct {
		Type string `json:"t"`
		DisplayFrame
	}
	if err := json.Unmarshal([]byte(message), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "display-frame" {
		t.Fatalf("marker type = %q", decoded.Type)
	}
	return decoded.DisplayFrame
}

func TestDisplayFrameOpenReplayAndSourceGenerationFence(t *testing.T) {
	for _, openFirst := range []bool{false, true} {
		var frames displayFrames
		var sent []string
		send := func(message string) error { sent = append(sent, message); return nil }
		if err := frames.begin("monitor-1", 1); err != nil {
			t.Fatal(err)
		}
		if openFirst {
			if err := frames.open(send); err != nil {
				t.Fatal(err)
			}
		}
		first := DisplayFrame{Display: "monitor-1", Generation: 1, RTPTimestamp: 0xfffffff0}
		if err := frames.publish(first); err != nil {
			t.Fatal(err)
		}
		if !openFirst {
			if len(sent) != 0 {
				t.Fatal("marker sent before channel opened")
			}
			if err := frames.open(send); err != nil {
				t.Fatal(err)
			}
		}
		if len(sent) != 1 || decodeDisplayFrame(t, sent[0]) != first {
			t.Fatal("open lost cached first marker")
		}
		// A duplicate publication must not move the presentation threshold.
		if err := frames.publish(DisplayFrame{Display: "monitor-1", Generation: 1, RTPTimestamp: 12000}); err != nil {
			t.Fatal(err)
		}
		if err := frames.begin("monitor-1", 1); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 1 {
			t.Fatal("duplicate marker was sent")
		}
		if err := frames.begin("monitor-2", 2); err != nil {
			t.Fatal(err)
		}
		if err := frames.open(send); err != nil {
			t.Fatal(err)
		}
		if err := frames.publish(first); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 1 {
			t.Fatal("new source reused or replayed the old marker")
		}
		// Timestamp zero is an exact wrapped RTP value, never an unset sentinel.
		second := DisplayFrame{Display: "monitor-2", Generation: 2, RTPTimestamp: 0}
		if err := frames.publish(second); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 2 || decodeDisplayFrame(t, sent[1]) != second {
			t.Fatal("wrapped marker lost")
		}
		if err := frames.open(send); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 3 || sent[1] != sent[2] {
			t.Fatal("channel-open replay changed exact marker")
		}
		if err := frames.begin("monitor-1", 2); err == nil {
			t.Fatal("generation reused for another source")
		}
		if err := frames.begin("monitor-1", 1); err == nil {
			t.Fatal("stale generation accepted")
		}
		if err := frames.begin("monitor-1", 3); err != nil {
			t.Fatal(err)
		}
		if err := frames.publish(first); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 3 {
			t.Fatal("returning to same monitor revived first generation")
		}
		frames.close()
		if err := frames.open(send); err != nil {
			t.Fatal(err)
		}
		if err := frames.publish(DisplayFrame{Display: "monitor-1", Generation: 3, RTPTimestamp: 6000}); !errors.Is(err, errSessionEnded) {
			t.Fatal("ended peer accepted marker")
		}
		if len(sent) != 3 {
			t.Fatal("marker replayed after close")
		}
	}
}

type mediaEmissionPeer struct {
	*fakePeer
	results []struct {
		emitted bool
		err     error
	}
	timestamps []uint32
}

func (p *mediaEmissionPeer) WriteRTP(packet []byte) (bool, error) {
	p.timestamps = append(p.timestamps, binary.BigEndian.Uint32(packet[4:8]))
	result := p.results[0]
	p.results = p.results[1:]
	return result.emitted, result.err
}

func TestDisplayFrameUsesFirstEmittedPostTimelineTimestamp(t *testing.T) {
	now := time.Unix(100, 0)
	peer := &mediaEmissionPeer{fakePeer: &fakePeer{}, results: []struct {
		emitted bool
		err     error
	}{
		{false, nil}, // Encoder preroll before DTLS is not emitted.
		{false, errors.New("failed write")},
		{true, nil},
		{true, nil},
	}}
	var sent []string
	if err := peer.frames.begin("monitor-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := peer.frames.begin("monitor-2", 2); err != nil {
		t.Fatal(err)
	}
	if err := peer.frames.open(func(message string) error { sent = append(sent, message); return nil }); err != nil {
		t.Fatal(err)
	}
	capture := &fakeCapture{packets: make(chan []byte, 4), closed: make(chan struct{})}
	for i := range 4 {
		capture.packets <- timelinePacket(uint16(10+i), 500000+uint32(i)*3000, 987)
	}
	close(capture.packets)
	r := &sessionResources{peer: peer, input: &inputControl{display: "monitor-2", generation: 2}, captureDone: make(chan error, 1)}
	if err := r.timeline.rewrite(timelinePacket(65535, 0xfffffff0, 123), true, now); err != nil {
		t.Fatal(err)
	}
	s := &session{deps: &sessionDeps{clock: func() time.Time { return now.Add(time.Second) }}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	first, done := make(chan struct{}), make(chan struct{})
	s.forwardMedia(t.Context(), r, capture, "monitor-2", 2, first, done)
	select {
	case <-first:
	default:
		t.Fatal("capture readiness not announced")
	}
	select {
	case <-done:
	default:
		t.Fatal("forwarder did not terminate")
	}
	wantTimestamp := uint32(0xfffffff0)
	wantTimestamp += 90000 + 6000
	if len(sent) != 1 {
		t.Fatalf("markers = %v", sent)
	}
	marker := decodeDisplayFrame(t, sent[0])
	if s.frame != marker {
		t.Fatal("typed report and control channel used different media witnesses")
	}
	if marker != (DisplayFrame{Display: "monitor-2", Generation: 2, RTPTimestamp: wantTimestamp}) || marker.RTPTimestamp != peer.timestamps[2] {
		t.Fatalf("marker %+v does not identify first emitted mapped packet %v", marker, peer.timestamps)
	}
}

func TestDisplayFrameCancelledForwarderCannotPublish(t *testing.T) {
	peer := &fakePeer{}
	if err := peer.frames.begin("monitor-1", 1); err != nil {
		t.Fatal(err)
	}
	capture := newFakeCapturer().capture
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := &session{}
	r := &sessionResources{peer: peer, captureDone: make(chan error, 1)}
	s.forwardMedia(ctx, r, capture, "monitor-1", 1, make(chan struct{}), make(chan struct{}))
	if peer.frames.marker != "" || peer.written != 0 {
		t.Fatal("cancelled capture published media")
	}
}

func TestDisplayFrameReportUsesLiveExactWitnessAndEndRevokesReplay(t *testing.T) {
	peer := &fakePeer{}
	input := newInputControl(&fakeGrant{}, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF, "monitor-1")
	r := &sessionResources{peer: peer, input: input}
	_, cancel := context.WithCancelCause(t.Context())
	s := &session{invitation: tierOneInvitation(modeView), phase: agentv1.AssistancePhase_ASSISTANCE_PHASE_ACTIVE,
		selected: "monitor-1", generation: 1, mediaPeer: peer, cancel: cancel}
	if err := peer.BeginDisplay("monitor-1", 1); err != nil {
		t.Fatal(err)
	}
	before, _ := s.report()
	if before.GetDisplayFrame() != nil {
		t.Fatal("selection alone manufactured a media witness")
	}
	first := DisplayFrame{Display: "monitor-1", Generation: 1, RTPTimestamp: 0}
	if err := s.publishDisplayFrame(r, first); err != nil {
		t.Fatal(err)
	}
	if err := s.publishDisplayFrame(r, DisplayFrame{Display: "monitor-1", Generation: 1, RTPTimestamp: 6000}); err != nil {
		t.Fatal(err)
	}
	report, _ := s.report()
	frame := report.GetDisplayFrame()
	if frame == nil || frame.GetDisplayId() != first.Display || frame.GetGeneration() != first.Generation || frame.GetRtpTimestamp() != first.RTPTimestamp {
		t.Fatal("VIEW report lost or replaced the first exact wrapped marker")
	}
	s.end(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED, "local_stop")
	ended, _ := s.report()
	if ended.GetDisplayFrame() != nil || s.frame.Generation != 0 {
		t.Fatal("end retained media authority")
	}
	if err := peer.frames.open(func(string) error { t.Fatal("ended session replayed cached marker"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.publishDisplayFrame(r, first); !errors.Is(err, errSessionEnded) {
		t.Fatal("end allowed late frame publication")
	}
}

func TestPionPrerollDoesNotClaimRTPEmission(t *testing.T) {
	peer := &pionPeer{connected: make(chan struct{})}
	// There is deliberately no track; preroll must be discarded before WriteRTP.
	emitted, err := peer.WriteRTP(timelinePacket(1, 0, 1))
	if emitted || err != nil {
		t.Fatalf("pre-connection packet claimed emission: %t %v", emitted, err)
	}
}
