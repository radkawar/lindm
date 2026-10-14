// SPDX-License-Identifier: Apache-2.0

package labexec

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/nativeexec"
)

// firstLine delivers the first line a child writes, e.g. a descendant's PID.
type firstLine struct {
	data []byte
	sent bool
	line chan string
}

func newFirstLine() *firstLine { return &firstLine{line: make(chan string, 1)} }

func (w *firstLine) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	if i := strings.IndexByte(string(w.data), '\n'); i >= 0 && !w.sent {
		w.line <- string(w.data[:i])
		w.sent = true
	}
	return len(p), nil
}

func (w *firstLine) pid(t *testing.T) int {
	t.Helper()
	select {
	case text := <-w.line:
		pid, err := strconv.Atoi(text)
		if err != nil {
			t.Fatalf("descendant pid %q: %v", text, err)
		}
		return pid
	case <-time.After(10 * time.Second):
		t.Fatal("child never reported its descendant")
		return 0
	}
}

func awaitGone(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		// The orphaned descendant is reaped by init; a zombie is also gone.
		data, err := readStat(pid)
		if err != nil || strings.Contains(data, ") Z ") {
			return
		}
	}
	t.Fatalf("descendant %d survived its group", pid)
}

func readStat(pid int) (string, error) {
	var buf [512]byte
	fd, err := unix.Open("/proc/"+strconv.Itoa(pid)+"/stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	n, err := unix.Read(fd, buf[:])
	return string(buf[:max(n, 0)]), err
}

func TestRunCapturesBoundedOutputAndExitStatus(t *testing.T) {
	stdout, stderr := nativeexec.NewBuffer(4), nativeexec.NewBuffer(64)
	err := Run(t.Context(), Command{Path: "sh", Args: []string{"-c", "echo 123456; echo diagnostic >&2; exit 3"}, Stdout: stdout, Stderr: stderr})
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 || strings.Contains(err.Error(), "diagnostic") {
		t.Fatalf("exit error = %v", err)
	}
	if stdout.String() != "1234" || !stdout.Truncated() || stderr.String() != "diagnostic\n" {
		t.Fatalf("captured %q (truncated %t) and %q", stdout, stdout.Truncated(), stderr)
	}
}

func TestSharedSinkReceivesBothStreams(t *testing.T) {
	output := nativeexec.NewBuffer(64)
	if err := Run(t.Context(), Command{Path: "sh", Args: []string{"-c", "echo out; echo err >&2"}, Stdout: output, Stderr: output}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "out\nerr\n" {
		t.Fatalf("shared sink = %q", output)
	}
}

func TestCancellationKillsWholeGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	stdout := newFirstLine()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Command{Path: "sh", Args: []string{"-c", "sleep 60 & echo $!; wait"}, Stdout: stdout})
	}()
	pid := stdout.pid(t)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run = %v", err)
	}
	awaitGone(t, pid)
}

func TestTimeoutKillsWholeGroup(t *testing.T) {
	stdout := newFirstLine()
	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), Command{Path: "sh", Args: []string{"-c", "sleep 60 & echo $!; wait"}, Stdout: stdout, Timeout: 200 * time.Millisecond})
	}()
	pid := stdout.pid(t)
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out run = %v", err)
	}
	awaitGone(t, pid)
}

func TestInterruptAllowsCleanupThenKillsSurvivors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	stdout := newFirstLine()
	done := make(chan error, 1)
	// The leader exits gracefully on TERM; its descendant ignores TERM.
	script := `(trap "" TERM; exec sleep 60) & echo $!; trap "exit 0" TERM; wait`
	go func() {
		done <- Run(ctx, Command{Path: "sh", Args: []string{"-c", script}, Stdout: stdout, Interrupt: syscall.SIGTERM, Grace: time.Minute})
	}()
	pid := stdout.pid(t)
	started := time.Now()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted run = %v", err)
	}
	if time.Since(started) > 30*time.Second {
		t.Fatal("waited for the grace period after the leader exited")
	}
	awaitGone(t, pid)
}

func TestInterruptGraceExpiryKillsGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	stdout := newFirstLine()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Command{Path: "sh", Args: []string{"-c", `trap "" TERM; sleep 60 & echo $!; wait`}, Stdout: stdout, Interrupt: syscall.SIGTERM, Grace: 100 * time.Millisecond})
	}()
	pid := stdout.pid(t)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted run = %v", err)
	}
	awaitGone(t, pid)
}

func TestOutputHeldPastLeaderIsKilled(t *testing.T) {
	stdout := newFirstLine()
	done := make(chan error, 1)
	go func() {
		done <- Run(t.Context(), Command{Path: "sh", Args: []string{"-c", "sleep 60 & echo $!"}, Stdout: stdout})
	}()
	pid := stdout.pid(t)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(drainDelay + 10*time.Second):
		t.Fatal("descendant holding output kept the call open")
	}
	awaitGone(t, pid)
}

func TestCloseKillsGroupWithoutError(t *testing.T) {
	stdout := newFirstLine()
	p, err := Start(t.Context(), Command{Path: "sh", Args: []string{"-c", "sleep 60 & echo $!; wait"}, Stdout: stdout})
	if err != nil {
		t.Fatal(err)
	}
	pid := stdout.pid(t)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	awaitGone(t, pid)
}

func TestSignalReachesGroupUntilReaped(t *testing.T) {
	stdout := newFirstLine()
	p, err := Start(t.Context(), Command{Path: "sh", Args: []string{"-c", "sleep 60 & echo $!; wait"}, Stdout: stdout})
	if err != nil {
		t.Fatal(err)
	}
	pid := stdout.pid(t)
	if p.Pid() <= 0 || p.Pid() == pid {
		t.Fatalf("leader pid %d", p.Pid())
	}
	p.Signal(syscall.SIGTERM)
	var exit *exec.ExitError
	if err := p.Wait(); !errors.As(err, &exit) || !strings.Contains(err.Error(), "terminated") {
		t.Fatalf("signalled leader = %v", err)
	}
	awaitGone(t, pid)
	p.Signal(syscall.SIGKILL) // reaped: a no-op, never a recycled group
}
