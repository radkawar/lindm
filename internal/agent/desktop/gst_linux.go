//go:build linux

package desktop

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"lindm/internal/agent/nativeexec"
)

const (
	gstLaunch          = "/usr/bin/gst-launch-1.0"
	gstInspect         = "/usr/bin/gst-inspect-1.0"
	gstInspectTimeout  = 10 * time.Second
	gstInspectStdout   = 4 << 10
	gstStderrTail      = 4 << 10
	gstElementsTimeout = 30 * time.Second
	// gstLifetime is a backstop: the session closes the capture when the
	// invitation ends, consent is withdrawn or the peer is lost. Assistance
	// sessions last at most 30 minutes (admin.v1 max_duration_seconds), so an
	// hour never cuts a legitimate session short yet bounds a leaked pipeline.
	gstLifetime = time.Hour
)

// GStreamer runs the gst-launch-1.0 encoder pipeline from its fixed /usr/bin
// path, verified on each start so a later package install takes effect.
type GStreamer struct {
	logger *slog.Logger
}

var _ Capturer = (*GStreamer)(nil)

// NewGStreamer returns the production capturer.
func NewGStreamer(logger *slog.Logger) (*GStreamer, error) {
	if logger == nil {
		return nil, errors.New("desktop: missing capturer logger")
	}
	return &GStreamer{logger: logger}, nil
}

// Start checks the required elements and launches the pipeline in its own
// process group with the portal PipeWire remote as fd 3 and stdout carrying
// RFC 4571 framed RTP. Missing tools or elements are UNAVAILABLE.
func (g *GStreamer) Start(ctx context.Context, request CaptureRequest) (Capture, error) {
	if request.PipeWire == nil {
		return nil, errors.New("missing pipewire remote")
	}
	if _, err := nativeexec.Executable(gstLaunch); err != nil {
		return nil, unavailable("gst_launch_missing", err)
	}
	if err := checkGstElements(ctx); err != nil {
		return nil, err
	}
	process, err := nativeexec.Start(ctx, nativeexec.Command{
		Path:        gstLaunch,
		Args:        gstArguments(request.Stream.NodeID, request.Stream.Width, request.Stream.Height),
		Files:       []*os.File{request.PipeWire},
		Timeout:     gstLifetime,
		StderrLimit: gstStderrTail,
	})
	if err != nil {
		return nil, unavailable("gst_start_failed", err)
	}
	g.logger.Info("capture pipeline started", "node", request.Stream.NodeID)
	return &gstCapture{process: process, reader: newRTPStreamReader(process.Stdout()), logger: g.logger}, nil
}

// checkGstElements requires gst-inspect-1.0 (packaged with gst-launch-1.0
// on the supported distributions) to report every pipeline element.
func checkGstElements(ctx context.Context) error {
	if _, err := nativeexec.Executable(gstInspect); err != nil {
		return unavailable("gst_inspect_missing", err)
	}
	ctx, cancel := context.WithTimeout(ctx, gstElementsTimeout)
	defer cancel()
	for _, element := range gstElements {
		_, err := nativeexec.Run(ctx, nativeexec.Command{
			Path:        gstInspect,
			Args:        []string{"--exists", element},
			Timeout:     gstInspectTimeout,
			StdoutLimit: gstInspectStdout,
			StderrLimit: gstStderrTail,
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return unavailable("gst_element_missing:"+element, err)
		}
	}
	return nil
}

type gstCapture struct {
	process *nativeexec.Process
	reader  *rtpStreamReader
	logger  *slog.Logger
	once    sync.Once
	err     error
}

func (c *gstCapture) ReadPacket(buf []byte) (int, error) {
	return c.reader.ReadPacket(buf)
}

// Close kills the whole process group and reaps the pipeline.
func (c *gstCapture) Close() error {
	c.once.Do(func() {
		var result nativeexec.Result
		result, c.err = c.process.Close()
		if len(result.Stderr) != 0 {
			c.logger.Info("capture pipeline stopped", "exit_code", result.ExitCode, "stderr", string(result.Stderr))
		}
	})
	return c.err
}
