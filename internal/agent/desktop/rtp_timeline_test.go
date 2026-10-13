package desktop

import (
	"encoding/binary"
	"testing"
	"time"
)

func timelinePacket(sequence uint16, timestamp, ssrc uint32) []byte {
	packet := make([]byte, 13)
	packet[0], packet[1], packet[12] = 0x80, 96, 0x10
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], timestamp)
	binary.BigEndian.PutUint32(packet[8:12], ssrc)
	return packet
}

func TestRTPSelectedCaptureKeepsSequenceTimestampAndSSRC(t *testing.T) {
	var timeline rtpTimeline
	now := time.Unix(100, 0)
	first := timelinePacket(65534, 0xfffffff0, 123)
	if err := timeline.rewrite(first, true, now); err != nil {
		t.Fatal(err)
	}
	// Two packets in one frame retain their timestamp across sequence wrap.
	second := timelinePacket(65535, 0xfffffff0, 123)
	if err := timeline.rewrite(second, false, now); err != nil {
		t.Fatal(err)
	}
	// A fresh payloader's random values must not reset the same peer track.
	switched := timelinePacket(100, 500000, 987)
	if err := timeline.rewrite(switched, true, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(switched[2:4]); got != 0 {
		t.Fatalf("sequence after switch = %d", got)
	}
	wantTimestamp := uint32(0xfffffff0)
	wantTimestamp += 90000
	if got := binary.BigEndian.Uint32(switched[4:8]); got != wantTimestamp {
		t.Fatalf("timestamp after switch = %d, want %d", got, wantTimestamp)
	}
	if got := binary.BigEndian.Uint32(switched[8:12]); got != 123 {
		t.Fatalf("SSRC changed to %d", got)
	}
	next := timelinePacket(101, 506000, 987)
	if err := timeline.rewrite(next, false, now.Add(time.Second+time.Second/15)); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(next[4:8]); got != wantTimestamp+6000 {
		t.Fatalf("new encoder clock lost: %d", got)
	}
	if err := timeline.rewrite([]byte{0x80}, true, now); err == nil {
		t.Fatal("truncated RTP admitted")
	}
}
