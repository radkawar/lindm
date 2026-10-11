package desktop

import (
	"fmt"
	"strconv"
)

// Encoder contract: VP8 at 15 fps, CBR 2.5 Mbit/s, keyframe at least every
// 2 s, RTP payload type 96 with 1200-byte MTU, width at most 1920.
const (
	captureMaxWidth  = 1920
	captureFramerate = 15
	rtpPayloadType   = 96
)

// gstElements are the GStreamer elements the capture pipeline requires.
var gstElements = []string{
	"pipewiresrc", "videorate", "videoconvert", "videoscale",
	"vp8enc", "rtpvp8pay", "rtpstreampay", "fdsink",
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
// writes RFC 4571 framed VP8 RTP to stdout. When the portal did not report
// the stream size the frame is not rescaled.
func gstArguments(nodeID uint32, width, height int) []string {
	caps := fmt.Sprintf("video/x-raw,framerate=%d/1", captureFramerate)
	if w, h, ok := scaledSize(width, height); ok {
		caps += ",width=" + strconv.Itoa(w) + ",height=" + strconv.Itoa(h)
	}
	return []string{
		"-q",
		"pipewiresrc", "fd=3", "path=" + strconv.FormatUint(uint64(nodeID), 10), "keepalive-time=500",
		"!", "videorate",
		"!", "videoconvert",
		"!", "videoscale",
		"!", caps,
		"!", "vp8enc", "deadline=1", "cpu-used=8", "end-usage=cbr", "target-bitrate=2500000",
		"keyframe-max-dist=30", "error-resilient=default",
		"!", "rtpvp8pay", "mtu=1200", "pt=" + strconv.Itoa(rtpPayloadType),
		"!", "rtpstreampay",
		"!", "fdsink", "fd=1",
	}
}
