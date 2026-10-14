// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func rtpFrame(payload int) []byte {
	packet := make([]byte, minRTPPacket+payload)
	packet[0] = 0x80
	packet[1] = 96
	for i := minRTPPacket; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	return append(frame, packet...)
}

func TestRTPStreamReaderFrames(t *testing.T) {
	var stream bytes.Buffer
	sizes := []int{0, 1, 500, 1200, maxRTPPacket - minRTPPacket}
	for _, payload := range sizes {
		stream.Write(rtpFrame(payload))
	}
	// One byte per Read exercises reassembly across partial reads.
	reader := newRTPStreamReader(iotest.OneByteReader(&stream))
	buf := make([]byte, maxRTPPacket)
	for _, payload := range sizes {
		n, err := reader.ReadPacket(buf)
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
		if n != minRTPPacket+payload || buf[0] != 0x80 || (payload > 0 && buf[n-1] != byte(n-1)) {
			t.Fatalf("packet n=%d header=%x", n, buf[:2])
		}
	}
	if _, err := reader.ReadPacket(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("clean end = %v, want EOF", err)
	}
}

func TestRTPStreamReaderRejects(t *testing.T) {
	oversize := binary.BigEndian.AppendUint16(nil, maxRTPPacket+1)
	undersize := binary.BigEndian.AppendUint16(nil, minRTPPacket-1)
	badVersion := rtpFrame(4)
	badVersion[2] = 0x40
	for name, tc := range map[string]struct {
		stream []byte
		want   error
	}{
		"oversize":    {append(oversize, make([]byte, maxRTPPacket+1)...), errRTPFraming},
		"undersize":   {append(undersize, make([]byte, minRTPPacket)...), errRTPFraming},
		"version":     {badVersion, errRTPFraming},
		"truncated":   {rtpFrame(100)[:50], io.ErrUnexpectedEOF},
		"half-length": {[]byte{0x01}, io.ErrUnexpectedEOF},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newRTPStreamReader(bytes.NewReader(tc.stream)).ReadPacket(make([]byte, maxRTPPacket))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := newRTPStreamReader(bytes.NewReader(rtpFrame(1))).ReadPacket(make([]byte, 100)); err == nil {
		t.Fatal("short buffer accepted")
	}
}
