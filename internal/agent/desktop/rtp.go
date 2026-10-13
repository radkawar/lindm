package desktop

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// maxRTPPacket bounds one RFC 4571 frame. The encoder pipeline uses
// rtpvp8pay mtu=1200, so anything larger is a framing error.
const maxRTPPacket = 1500

// minRTPPacket is the fixed RTP header length.
const minRTPPacket = 12

var errRTPFraming = errors.New("rtp_framing")

// rtpStreamReader reads RFC 4571 framed RTP (16-bit big-endian length
// prefix, then the packet) as produced by GStreamer's rtpstreampay.
type rtpStreamReader struct {
	reader *bufio.Reader
	header [2]byte
}

func newRTPStreamReader(reader io.Reader) *rtpStreamReader {
	return &rtpStreamReader{reader: bufio.NewReaderSize(reader, 64<<10)}
}

// ReadPacket reads one framed packet into buf, which must hold at least
// maxRTPPacket bytes. A clean end of stream between frames returns io.EOF;
// a truncated frame returns io.ErrUnexpectedEOF.
func (r *rtpStreamReader) ReadPacket(buf []byte) (int, error) {
	if len(buf) < maxRTPPacket {
		return 0, errors.New("rtp buffer too small")
	}
	if _, err := io.ReadFull(r.reader, r.header[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(r.header[:]))
	if size < minRTPPacket || size > maxRTPPacket {
		return 0, fmt.Errorf("%w: frame length %d", errRTPFraming, size)
	}
	if _, err := io.ReadFull(r.reader, buf[:size]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, err
	}
	if buf[0]>>6 != 2 {
		return 0, fmt.Errorf("%w: rtp version", errRTPFraming)
	}
	return size, nil
}

// rtpTimeline belongs to the session, not to an encoder instance. A selected
// monitor starts a new encoder with arbitrary RTP offsets; the single WebRTC
// track must retain sequence, SSRC and a forward-moving 90 kHz clock.
type rtpTimeline struct {
	started                 bool
	sequence                uint16
	timestamp, offset, ssrc uint32
	last                    time.Time
}

func (t *rtpTimeline) rewrite(packet []byte, newSource bool, now time.Time) error {
	if len(packet) < minRTPPacket || packet[0]>>6 != 2 {
		return errRTPFraming
	}
	input := binary.BigEndian.Uint32(packet[4:8])
	if !t.started {
		t.started = true
		t.sequence = binary.BigEndian.Uint16(packet[2:4])
		t.ssrc = binary.BigEndian.Uint32(packet[8:12])
	} else {
		t.sequence++
		if newSource {
			gap := max(int64(90000/captureFramerate), now.Sub(t.last).Nanoseconds()*90000/int64(time.Second))
			t.offset = t.timestamp + uint32(gap) - input
		}
	}
	t.timestamp, t.last = input+t.offset, now
	binary.BigEndian.PutUint16(packet[2:4], t.sequence)
	binary.BigEndian.PutUint32(packet[4:8], t.timestamp)
	binary.BigEndian.PutUint32(packet[8:12], t.ssrc)
	return nil
}
