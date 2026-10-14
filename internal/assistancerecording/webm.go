// SPDX-License-Identifier: Apache-2.0

package assistancerecording

import (
	"encoding/binary"
	"errors"
)

// WebM element identifiers (Matroska specification).
const (
	idEBML               = 0x1A45DFA3
	idEBMLVersion        = 0x4286
	idEBMLReadVersion    = 0x42F7
	idEBMLMaxIDLength    = 0x42F2
	idEBMLMaxSizeLength  = 0x42F3
	idDocType            = 0x4282
	idDocTypeVersion     = 0x4287
	idDocTypeReadVersion = 0x4285
	idSegment            = 0x18538067
	idInfo               = 0x1549A966
	idTimecodeScale      = 0x2AD7B1
	idMuxingApp          = 0x4D80
	idWritingApp         = 0x5741
	idTracks             = 0x1654AE6B
	idTrackEntry         = 0xAE
	idTrackNumber        = 0xD7
	idTrackUID           = 0x73C5
	idTrackType          = 0x83
	idFlagLacing         = 0x9C
	idCodecID            = 0x86
	idVideo              = 0xE0
	idPixelWidth         = 0xB0
	idPixelHeight        = 0xBA
	idCluster            = 0x1F43B675
	idTimecode           = 0xE7
	idSimpleBlock        = 0xA3

	// A cluster closes at the next keyframe, after 30 s or at this size, so a
	// SimpleBlock's signed 16-bit relative timestamp never overflows.
	maxClusterBytes    = 4 << 20
	maxClusterDuration = 30000
	// MaxFrameBytes bounds one encoded frame.
	MaxFrameBytes = 2 << 20
)

var ErrFrame = errors.New("recording_frame_invalid")

// WebM writes one VP8 video track as a progressive WebM stream: an EBML
// header, a live (unknown-size) Segment with Info and Tracks, then sized
// Clusters. Any whole-cluster prefix of the stream is itself playable.
type WebM struct {
	cluster      []byte
	clusterStart int64
	open         bool
	last         int64
	started      bool
}

// Header returns the stream prefix for a width x height video track.
func (w *WebM) Header(width, height uint32) []byte {
	var header []byte
	header = appendElement(header, idEBML, concat(
		uintElement(idEBMLVersion, 1),
		uintElement(idEBMLReadVersion, 1),
		uintElement(idEBMLMaxIDLength, 4),
		uintElement(idEBMLMaxSizeLength, 8),
		stringElement(idDocType, "webm"),
		uintElement(idDocTypeVersion, 4),
		uintElement(idDocTypeReadVersion, 2),
	))
	header = appendID(header, idSegment)
	header = append(header, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	header = appendElement(header, idInfo, concat(
		uintElement(idTimecodeScale, 1000000),
		stringElement(idMuxingApp, "lindm"),
		stringElement(idWritingApp, "lindm-agent session"),
	))
	header = appendElement(header, idTracks, element(idTrackEntry, concat(
		uintElement(idTrackNumber, 1),
		uintElement(idTrackUID, 1),
		uintElement(idTrackType, 1),
		uintElement(idFlagLacing, 0),
		stringElement(idCodecID, "V_VP8"),
		element(idVideo, concat(uintElement(idPixelWidth, uint64(width)), uintElement(idPixelHeight, uint64(height)))),
	)))
	return header
}

// Frame adds one encoded frame at a millisecond timestamp. It returns the
// previous cluster when this frame starts a new one. Timestamps never go back.
func (w *WebM) Frame(timestamp int64, keyframe bool, frame []byte) ([]byte, error) {
	if len(frame) == 0 || len(frame) > MaxFrameBytes || timestamp < 0 || (w.started && timestamp < w.last) {
		return nil, ErrFrame
	}
	if !w.started && !keyframe {
		return nil, ErrFrame
	}
	var closed []byte
	if w.open && (keyframe || timestamp-w.clusterStart > maxClusterDuration || len(w.cluster)+len(frame) > maxClusterBytes) {
		closed = w.Flush()
	}
	if !w.open {
		w.open, w.clusterStart = true, timestamp
		w.cluster = append(w.cluster[:0], uintElement(idTimecode, uint64(timestamp))...)
	}
	block := make([]byte, 0, len(frame)+4)
	block = append(block, 0x81)
	block = binary.BigEndian.AppendUint16(block, uint16(int16(timestamp-w.clusterStart)))
	if keyframe {
		block = append(block, 0x80)
	} else {
		block = append(block, 0)
	}
	block = append(block, frame...)
	w.cluster = appendElement(w.cluster, idSimpleBlock, block)
	w.started, w.last = true, timestamp
	return closed, nil
}

// Flush closes the open cluster, if any, and returns it.
func (w *WebM) Flush() []byte {
	if !w.open {
		return nil
	}
	w.open = false
	return element(idCluster, w.cluster)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func element(id uint32, payload []byte) []byte {
	return appendElement(nil, id, payload)
}

func appendElement(out []byte, id uint32, payload []byte) []byte {
	out = appendID(out, id)
	out = appendSize(out, uint64(len(payload)))
	return append(out, payload...)
}

func appendID(out []byte, id uint32) []byte {
	switch {
	case id >= 1<<24:
		return append(out, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	case id >= 1<<16:
		return append(out, byte(id>>16), byte(id>>8), byte(id))
	case id >= 1<<8:
		return append(out, byte(id>>8), byte(id))
	default:
		return append(out, byte(id))
	}
}

// appendSize writes the shortest EBML variable-length size. The all-ones
// value of each width is reserved for "unknown" and never produced here; the
// bounded frame and cluster sizes are far below the 8-byte limit.
func appendSize(out []byte, size uint64) []byte {
	length := 8
	for candidate := 1; candidate < 8; candidate++ {
		if size < (uint64(1)<<(7*candidate))-1 {
			length = candidate
			break
		}
	}
	value := size | uint64(1)<<(7*length)
	for i := length - 1; i >= 0; i-- {
		out = append(out, byte(value>>(8*i)))
	}
	return out
}

func uintElement(id uint32, value uint64) []byte {
	var payload []byte
	for shift := 56; shift >= 0; shift -= 8 {
		if b := byte(value >> shift); b != 0 || len(payload) > 0 || shift == 0 {
			payload = append(payload, b)
		}
	}
	return element(id, payload)
}

func stringElement(id uint32, value string) []byte {
	return element(id, []byte(value))
}
