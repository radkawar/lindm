//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	gstLaunch          = "gst-launch-1.0"
	gstInspect         = "gst-inspect-1.0"
	gstInspectTimeout  = 10 * time.Second
	gstStderrTail      = 4 << 10
	gstWaitDelay       = 2 * time.Second
	gstElementsTimeout = 30 * time.Second
)

// GStreamer runs the gst-launch-1.0 encoder pipeline. Binaries are resolved
// from PATH at each start so a later package install takes effect.
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
	launch, err := exec.LookPath(gstLaunch)
	if err != nil {
		return nil, unavailable("gst_launch_missing", err)
	}
	if err := checkGstElements(ctx); err != nil {
		return nil, err
	}
	cmd := exec.Command(launch, gstArguments(request.Stream.NodeID, request.Stream.Width, request.Stream.Height)...)
	cmd.ExtraFiles = []*os.File{request.PipeWire}
	stderr := &tailBuffer{limit: gstStderrTail}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = gstWaitDelay
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, unavailable("gst_pipe_failed", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, unavailable("gst_start_failed", err)
	}
	g.logger.Info("capture pipeline started", "pid", cmd.Process.Pid, "node", request.Stream.NodeID)
	return &gstCapture{cmd: cmd, reader: newRTPStreamReader(stdout), stderr: stderr, logger: g.logger}, nil
}

// checkGstElements requires gst-inspect-1.0 (packaged with gst-launch-1.0
// on the supported distributions) to report every pipeline element.
func checkGstElements(ctx context.Context) error {
	inspect, err := exec.LookPath(gstInspect)
	if err != nil {
		return unavailable("gst_inspect_missing", err)
	}
	ctx, cancel := context.WithTimeout(ctx, gstElementsTimeout)
	defer cancel()
	for _, element := range gstElements {
		check, cancelCheck := context.WithTimeout(ctx, gstInspectTimeout)
		cmd := exec.CommandContext(check, inspect, "--exists", element)
		cmd.WaitDelay = gstWaitDelay
		err := cmd.Run()
		cancelCheck()
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
	cmd    *exec.Cmd
	reader *rtpStreamReader
	stderr *tailBuffer
	logger *slog.Logger
	once   sync.Once
	err    error
}

func (c *gstCapture) ReadPacket(buf []byte) (int, error) {
	return c.reader.ReadPacket(buf)
}

// Close kills the whole process group and reaps the pipeline.
func (c *gstCapture) Close() error {
	c.once.Do(func() {
		pid := c.cmd.Process.Pid
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			c.err = fmt.Errorf("kill capture process group: %w", err)
		}
		waitErr := c.cmd.Wait()
		var exitErr *exec.ExitError
		if waitErr != nil && !errors.As(waitErr, &exitErr) {
			c.err = errors.Join(c.err, fmt.Errorf("wait capture: %w", waitErr))
		}
		if tail := c.stderr.String(); tail != "" {
			c.logger.Info("capture pipeline stopped", "state", c.cmd.ProcessState.String(), "stderr", tail)
		}
	})
	return c.err
}

// tailBuffer keeps the last limit bytes written.
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

var _ io.Writer = (*tailBuffer)(nil)

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	if len(p) >= b.limit {
		p = p[len(p)-b.limit:]
		b.data = b.data[:0]
	}
	if overflow := len(b.data) + len(p) - b.limit; overflow > 0 {
		b.data = append(b.data[:0], b.data[overflow:]...)
	}
	b.data = append(b.data, p...)
	return written, nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data)
}
