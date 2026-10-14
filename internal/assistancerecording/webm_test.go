// SPDX-License-Identifier: Apache-2.0

package assistancerecording

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

type ebmlElement struct {
	id      uint32
	payload []byte
	unknown bool
}

// readElements parses one EBML level. It is a test oracle, not a demuxer.
func readElements(t *testing.T, data []byte) []ebmlElement {
	t.Helper()
	var out []ebmlElement
	for len(data) > 0 {
		width := 1
		for width <= 4 && data[0]&(0x80>>(width-1)) == 0 {
			width++
		}
		var id uint32
		for _, b := range data[:width] {
			id = id<<8 | uint32(b)
		}
		data = data[width:]
		length := 1
		for length <= 8 && data[0]&(0x80>>(length-1)) == 0 {
			length++
		}
		size := uint64(data[0] & (0xFF >> length))
		unknown := size == uint64(0xFF>>length)
		for _, b := range data[1:length] {
			size = size<<8 | uint64(b)
			unknown = unknown && b == 0xFF
		}
		data = data[length:]
		if unknown {
			out = append(out, ebmlElement{id: id, payload: data, unknown: true})
			return out
		}
		out = append(out, ebmlElement{id: id, payload: data[:size]})
		data = data[size:]
	}
	return out
}

func TestWebMStreamIsProgressiveAndKeyframeClustered(t *testing.T) {
	var w WebM
	if _, err := w.Frame(0, false, []byte{1}); !errors.Is(err, ErrFrame) {
		t.Fatalf("stream may not start without a keyframe: %v", err)
	}
	stream := w.Header(1280, 720)
	frames := []struct {
		at  int64
		key bool
	}{{0, true}, {66, false}, {133, false}, {2000, true}, {2066, false}}
	for i, frame := range frames {
		closed, err := w.Frame(frame.at, frame.key, bytes.Repeat([]byte{byte(i + 1)}, 300))
		if err != nil {
			t.Fatal(err)
		}
		stream = append(stream, closed...)
	}
	if _, err := w.Frame(10, false, []byte{1}); !errors.Is(err, ErrFrame) {
		t.Fatalf("time may not go back: %v", err)
	}
	stream = append(stream, w.Flush()...)
	top := readElements(t, stream)
	if len(top) != 2 || top[0].id != idEBML || top[1].id != idSegment || !top[1].unknown {
		t.Fatalf("top level = %+v", top)
	}
	segment := readElements(t, top[1].payload)
	var clusters [][]ebmlElement
	for _, child := range segment {
		if child.id == idCluster {
			clusters = append(clusters, readElements(t, child.payload))
		}
	}
	if len(segment) != 4 || segment[0].id != idInfo || segment[1].id != idTracks || len(clusters) != 2 {
		t.Fatalf("segment = %d children, %d clusters", len(segment), len(clusters))
	}
	if !bytes.Contains(segment[1].payload, []byte("V_VP8")) {
		t.Fatal("track is not VP8")
	}
	want := [][]int64{{0, 66, 133}, {0, 66}}
	for i, cluster := range clusters {
		if cluster[0].id != idTimecode {
			t.Fatalf("cluster %d lacks a timecode", i)
		}
		blocks := cluster[1:]
		if len(blocks) != len(want[i]) {
			t.Fatalf("cluster %d has %d blocks", i, len(blocks))
		}
		for j, block := range blocks {
			if block.id != idSimpleBlock || block.payload[0] != 0x81 || int64(int16(binary.BigEndian.Uint16(block.payload[1:3]))) != want[i][j] {
				t.Fatalf("cluster %d block %d = %x", i, j, block.payload[:4])
			}
			if keyframe := block.payload[3]&0x80 != 0; keyframe != (j == 0) {
				t.Fatalf("cluster %d block %d keyframe flag %v", i, j, keyframe)
			}
		}
	}
	if _, err := w.Frame(3000, true, make([]byte, MaxFrameBytes+1)); !errors.Is(err, ErrFrame) {
		t.Fatalf("oversized frame: %v", err)
	}
}
