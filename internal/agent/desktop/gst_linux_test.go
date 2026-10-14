// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"lindm/internal/agent/nativeexec"
)

// This is a real finite video source, not a portal/removal qualification. It
// verifies that source EOS terminates the live replacing encoder, that bus text
// cannot enter the RTP descriptor, and that the process/observer are reaped.
func TestGStreamerSourceEOSEndsLiveCapture(t *testing.T) {
	if _, err := os.Stat(gstLaunch); errors.Is(err, os.ErrNotExist) {
		t.Skip("GStreamer is not installed on the test host")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	remote, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = remote.Close() }()
	rtpRead, rtpWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rtpRead.Close() }()
	defer func() { _ = rtpWrite.Close() }()
	args := gstArguments(1, 320, 240, false)
	args = slices.Concat(args[:1], []string{"videotestsrc", "is-live=true", "num-buffers=30"}, args[4:])
	life, stop := context.WithCancel(ctx)
	defer stop()
	process, err := nativeexec.Start(life, nativeexec.Command{
		Path: gstLaunch, Args: args, Files: []*os.File{remote, rtpWrite},
		Timeout: 10 * time.Second, StderrLimit: gstStderrTail,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rtpWrite.Close(); err != nil {
		_, _ = process.Close()
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	capture := &gstCapture{
		process: process, reader: newRTPStreamReader(rtpRead), rtp: rtpRead,
		logger: slog.New(slog.NewTextHandler(&diagnostic, nil)), cancel: stop, busDone: make(chan struct{}),
	}
	defer func() { _ = capture.Close() }()
	go capture.watchBus(life)
	packet := make([]byte, maxRTPPacket)
	packets := 0
	for {
		n, err := capture.ReadPacket(packet)
		if err != nil {
			break
		}
		if n == 0 || packet[0]>>6 != 2 {
			t.Fatalf("control text or invalid packet reached RTP descriptor: %q", packet[:n])
		}
		packets++
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || packets == 0 || !bytes.Contains(diagnostic.Bytes(), []byte("reason=source_eos")) {
		t.Fatalf("finite source did not end live capture: context=%v packets=%d diagnostic=%s", ctx.Err(), packets, diagnostic.Bytes())
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// The sound pipeline streams RTP on stdout with no separate descriptor or
// lifecycle bus; closing it crashed the helper on local Mute
// (layers-ubuntu24-tier3-25).
func TestStdoutCaptureClosesWithoutVideoLifecycle(t *testing.T) {
	process, err := nativeexec.Start(t.Context(), nativeexec.Command{Path: "/bin/sleep", Args: []string{"30"}, Timeout: 10 * time.Second, StderrLimit: gstStderrTail})
	if err != nil {
		t.Fatal(err)
	}
	capture := &gstCapture{process: process, reader: newRTPStreamReader(process.Stdout()), logger: slog.New(slog.DiscardHandler)}
	done := make(chan error, 1)
	go func() { done <- capture.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closing a stdout capture waited for a lifecycle bus it does not have")
	}
}
