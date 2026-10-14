// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
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
	gstPropertiesLimit = 64 << 10
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
// process group with the portal PipeWire remote as fd 3, framed RTP as fd 4,
// and a separately bounded lifecycle observer on stdout.
// Missing tools or elements are UNAVAILABLE.
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
	properties, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: gstInspect, Args: []string{"pipewiresrc"}, Timeout: gstInspectTimeout,
		StdoutLimit: gstPropertiesLimit, StderrLimit: gstStderrTail,
	})
	if err != nil {
		return nil, unavailable("gst_source_properties_failed", err)
	}
	disconnectErrors := bytes.Contains(properties.Stdout, []byte("\n  on-disconnect "))
	rtpRead, rtpWrite, err := os.Pipe()
	if err != nil {
		return nil, unavailable("gst_rtp_pipe_failed", err)
	}
	captureContext, cancel := context.WithCancel(ctx)
	process, startErr := nativeexec.Start(captureContext, nativeexec.Command{
		Path:        gstLaunch,
		Args:        gstArguments(request.Stream.NodeID, request.Stream.Width, request.Stream.Height, disconnectErrors),
		Files:       []*os.File{request.PipeWire, rtpWrite},
		Timeout:     gstLifetime,
		StderrLimit: gstStderrTail,
	})
	closeErr := rtpWrite.Close()
	if startErr != nil || closeErr != nil {
		cancel()
		var processErr error
		if process != nil {
			_, processErr = process.Close()
		}
		return nil, unavailable("gst_start_failed", errors.Join(startErr, closeErr, processErr, rtpRead.Close()))
	}
	g.logger.Info("capture pipeline started", "node", request.Stream.NodeID, "disconnect_errors", disconnectErrors)
	capture := &gstCapture{
		process: process, reader: newRTPStreamReader(rtpRead), rtp: rtpRead,
		logger: g.logger, cancel: cancel, busDone: make(chan struct{}),
	}
	go capture.watchBus(captureContext)
	return capture, nil
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
			Args:        gstExistsArguments(element),
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
	rtp     *os.File
	cancel  context.CancelFunc
	busDone chan struct{}
	once    sync.Once
	err     error
}

func (c *gstCapture) ReadPacket(buf []byte) (int, error) {
	return c.reader.ReadPacket(buf)
}

func (c *gstCapture) watchBus(ctx context.Context) {
	defer close(c.busDone)
	err := waitGstSourceEnd(c.process.Stdout())
	if errors.Is(err, errGstSourceEOS) {
		c.logger.Info("capture source ended", "reason", "source_eos")
	} else if ctx.Err() == nil {
		c.logger.Warn("capture lifecycle channel ended", "err", err)
	}
	c.cancel()
}

// Close kills the whole process group and reaps the pipeline.
func (c *gstCapture) Close() error {
	c.once.Do(func() {
		c.cancel()
		var result nativeexec.Result
		result, c.err = c.process.Close()
		c.err = errors.Join(c.err, c.rtp.Close())
		<-c.busDone
		if len(result.Stderr) != 0 {
			c.logger.Info("capture pipeline stopped", "exit_code", result.ExitCode, "stderr", string(result.Stderr))
		}
	})
	return c.err
}
