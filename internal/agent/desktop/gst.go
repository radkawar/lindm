// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Encoder contract: VP8 at 15 fps, CBR 2.5 Mbit/s, keyframe at least every
// 2 s, RTP payload type 96 with 1200-byte MTU, width at most 1920.
const (
	captureMaxWidth  = 1920
	captureFramerate = 15
	rtpPayloadType   = 96
	gstBusLineLimit  = 4 << 10
)

// gstElements are the GStreamer elements the capture pipeline requires.
var gstElements = []string{
	"pipewiresrc", "tee", "bin", "fakesink", "imagefreeze", "videoconvert", "videoscale",
	"vp8enc", "rtpvp8pay", "rtpstreampay", "fdsink",
}

// gstExistsArguments asks gst-inspect-1.0 whether element exists in any
// version. Without --atleast-version, GStreamer 1.22 requires the element's
// plugin version to reach the GStreamer core version, so it reports
// PipeWire's pipewiresrc (plugin 0.3.65) missing on Debian 12.
func gstExistsArguments(element string) []string {
	return []string{"--exists", "--atleast-version=0.0.0", element}
}

// scaledSize returns the encoded size for a stream of logical width x
// height: at most captureMaxWidth wide, the aspect ratio kept (rounded) and
// both dimensions even and at least 2. ok is false for an unknown size.
func scaledSize(width, height int) (int, int, bool) {
	if width <= 0 || height <= 0 {
		return 0, 0, false
	}
	if width > captureMaxWidth {
		height = int((int64(height)*captureMaxWidth + int64(width)/2) / int64(width))
		width = captureMaxWidth
	}
	return max(width&^1, 2), max(height&^1, 2), true
}

// gstArguments builds the gst-launch-1.0 argv (without argv[0]) that reads
// PipeWire node nodeID through the portal remote inherited as fd 3 and
// writes RFC 4571 framed VP8 RTP to inherited fd 4. Stdout is the separate
// GStreamer bus channel. When the portal did not report the stream size the
// frame is not rescaled.
//
// pipewiresrc timestamps are not used. A compositor that attaches no
// SPA_META_Header (Mutter 40) gets the same stale graph-cycle time on every
// damage frame, and before PipeWire 1.6 a keepalive resend carries the
// absolute clock, on which GstBaseSrc then waits far past running time. So
// keepalive stays off and imagefreeze, live, re-stamps instead: it keeps the
// newest frame and emits it at captureFramerate in clock running time, also
// while an idle damage-driven desktop sends nothing.
//
// imagefreeze deliberately consumes input EOS after its first buffer. A
// zero-copy tee observes source EOS through a dedicated forwarding bin whose
// only child is a non-async fakesink. It cannot post async/segment completion:
// this pipeline never seeks, so its GstBinForwarded message means source EOS.
// The lifecycle observer then stops the entire encoder, on every compositor.
func gstArguments(nodeID uint32, width, height int, disconnectErrors bool) []string {
	caps := fmt.Sprintf("video/x-raw,framerate=%d/1", captureFramerate)
	if w, h, ok := scaledSize(width, height); ok {
		caps += ",width=" + strconv.Itoa(w) + ",height=" + strconv.Itoa(h)
	}
	capacity := 45
	if disconnectErrors {
		capacity++
	}
	args := make([]string, 0, capacity)
	args = append(args, "-m", "pipewiresrc", "fd=3", "path="+strconv.FormatUint(uint64(nodeID), 10))
	if disconnectErrors {
		args = append(args, "on-disconnect=error")
	}
	return append(args,
		"!", "tee", "name=lindm-source",
		"lindm-source.", "!", "imagefreeze", "is-live=true", "allow-replace=true",
		"!", "videoconvert",
		"!", "videoscale",
		"!", caps,
		"!", "vp8enc", "deadline=1", "cpu-used=8", "end-usage=cbr", "target-bitrate=2500000",
		"keyframe-max-dist=30", "error-resilient=default",
		"!", "rtpvp8pay", "mtu=1200", "pt="+strconv.Itoa(rtpPayloadType),
		"!", "rtpstreampay",
		"!", "fdsink", "fd=4",
		"lindm-source.", "!", "bin.(", "name=lindm-source-end", "message-forward=true",
		"fakesink", "sync=false", "async=false", "enable-last-sample=false", ")",
	)
}

var errGstSourceEOS = errors.New("capture_source_eos")

// waitGstSourceEnd reads only bounded native-tool bus messages, never RTP or
// device text. Unrecognized messages are discarded; loss/overflow of this
// lifecycle channel must stop capture rather than leave frozen media alive.
func waitGstSourceEnd(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, gstBusLineLimit), gstBusLineLimit)
	for scanner.Scan() {
		line, ok := bytes.CutPrefix(scanner.Bytes(), []byte("Got message #"))
		if !ok {
			continue
		}
		sequence, event, ok := bytes.Cut(line, []byte(" from element "))
		if !ok || len(sequence) == 0 || len(sequence) > 10 {
			continue
		}
		if _, err := strconv.ParseUint(string(sequence), 10, 32); err != nil {
			continue
		}
		if bytes.Equal(event, []byte(`"lindm-source-end" (element): GstBinForwarded, message=(GstMessage)NULL;`)) {
			return errGstSourceEOS
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("capture_bus_failed: %w", err)
	}
	return io.EOF
}
