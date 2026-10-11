package nativeexec

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const shell = "/usr/bin/sh"

func run(t *testing.T, timeout time.Duration, script string) (Result, error) {
	t.Helper()
	return Run(t.Context(), Command{Path: shell, Args: []string{"-c", script}, Timeout: timeout, StdoutLimit: 4096, StderrLimit: 4096})
}

func TestRunRejectsUntrustedExecutable(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	if err := os.WriteFile(tool, []byte("#!/usr/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(tool, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{tool, link, "relative/tool", "/usr/bin/../bin/sh"} {
		_, err := Run(t.Context(), Command{Path: path, Timeout: time.Second, StdoutLimit: 1, StderrLimit: 1})
		if !errors.Is(err, ErrUntrustedExecutable) {
			t.Errorf("%s: %v, want untrusted executable", path, err)
		}
	}
}

func TestRunUsesCleanAllowlistedEnvironment(t *testing.T) {
	t.Setenv("LINDM_NATIVEEXEC_SECRET", "leak")
	result, err := Run(t.Context(), Command{Path: "/usr/bin/env", Env: []string{"TZ=UTC"}, Timeout: 5 * time.Second, StdoutLimit: 4096, StderrLimit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result.Stdout), "PATH=/usr/sbin:/usr/bin\nLANG=C\nLC_ALL=C\nTZ=UTC\n"; got != want {
		t.Fatalf("environment %q, want %q", got, want)
	}
	for _, env := range []string{"LD_PRELOAD=/tmp/x.so", "PATH=/tmp", "TZ"} {
		if _, err := Run(t.Context(), Command{Path: "/usr/bin/env", Env: []string{env}, Timeout: time.Second, StdoutLimit: 1, StderrLimit: 1}); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("%s accepted: %v", env, err)
		}
	}
}

func TestRunRequiresDeadlineAndLimits(t *testing.T) {
	for _, c := range []Command{
		{Path: shell, StdoutLimit: 1, StderrLimit: 1},
		{Path: shell, Timeout: time.Second, StderrLimit: 1},
		{Path: shell, Timeout: time.Second, StdoutLimit: 1},
		{Path: shell, Timeout: time.Second, StdoutLimit: MaxOutputLimit + 1, StderrLimit: 1},
	} {
		if _, err := Run(t.Context(), c); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("%+v accepted: %v", c, err)
		}
	}
}

func TestRunRedactsStderrFromErrors(t *testing.T) {
	result, err := run(t, 5*time.Second, "echo 'token=hunter2' >&2; echo out; exit 3")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("error %v, want exit 3", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks stderr: %v", err)
	}
	if string(result.Stdout) != "out\n" || result.Diagnostic() != "token=hunter2" {
		t.Fatalf("result %+v diagnostic %q", result, result.Diagnostic())
	}
}

func TestRunBoundsStreamsSeparately(t *testing.T) {
	result, err := Run(t.Context(), Command{Path: shell, Args: []string{"-c", "head -c 100000 /dev/zero; printf 'e\\001\\n' >&2"}, Timeout: 5 * time.Second, StdoutLimit: 1000, StderrLimit: 64})
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("error %v, want output limit", err)
	}
	if len(result.Stdout) != 1000 || !result.StdoutTruncated || result.StderrTruncated || result.Diagnostic() != "e?" || result.ExitCode != 0 {
		t.Fatalf("result stdout=%d truncated=%t/%t diagnostic=%q exit=%d", len(result.Stdout), result.StdoutTruncated, result.StderrTruncated, result.Diagnostic(), result.ExitCode)
	}
}

// A native tool's descendants must not outlive the deadline: the whole process
// group is killed, not just the direct child.
func TestRunDeadlineKillsProcessGroup(t *testing.T) {
	started := time.Now()
	result, err := run(t, 500*time.Millisecond, "sleep 30 & echo $!; wait")
	if !errors.Is(err, ErrDeadline) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v, want deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("deadline took %s", elapsed)
	}
	awaitGone(t, result.Stdout)
}

func TestRunCancellationKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(300*time.Millisecond, cancel)
	result, err := Run(ctx, Command{Path: shell, Args: []string{"-c", "sleep 30 & echo $!; wait"}, Timeout: time.Minute, StdoutLimit: 64, StderrLimit: 64})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want cancellation", err)
	}
	awaitGone(t, result.Stdout)
}

// Package-database steps are terminated, never SIGKILLed: the tool's own
// SIGTERM cleanup must be allowed to finish after the deadline.
func TestRunTerminateOnlyLetsCleanupFinish(t *testing.T) {
	result, err := Run(t.Context(), Command{Path: shell, Args: []string{"-c", "trap 'sleep 0.5; echo graceful; exit 0' TERM; while :; do sleep 0.1; done"}, Timeout: 300 * time.Millisecond, StdoutLimit: 64, StderrLimit: 64, TerminateOnly: true})
	if !errors.Is(err, ErrDeadline) {
		t.Fatalf("error %v, want deadline", err)
	}
	if string(result.Stdout) != "graceful\n" || result.ExitCode != 0 {
		t.Fatalf("stdout %q exit %d: cleanup was cut short", result.Stdout, result.ExitCode)
	}
}

func TestRunStreamStopKillsProducer(t *testing.T) {
	var head []byte
	result, err := Run(t.Context(), Command{Path: "/usr/bin/yes", Timeout: 30 * time.Second, StderrLimit: 64, Stream: func(r io.Reader) {
		head = make([]byte, 4)
		_, _ = io.ReadFull(r, head)
	}})
	if !result.Stopped || string(head) != "y\ny\n" {
		t.Fatalf("stopped=%t head=%q err=%v", result.Stopped, head, err)
	}
	var exit *ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != -1 {
		t.Fatalf("error %v, want killed exit", err)
	}
}

func TestStartCloseKillsGroupAndKeepsStderrTail(t *testing.T) {
	p, err := Start(t.Context(), Command{Path: shell, Args: []string{"-c", "echo first >&2; echo last >&2; sleep 30 & echo $!; wait"}, Timeout: time.Minute, StderrLimit: 5})
	if err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 0, 32)
	buf := make([]byte, 1)
	for len(line) == 0 || line[len(line)-1] != '\n' {
		if _, err := p.Stdout().Read(buf); err != nil {
			t.Fatal(err)
		}
		line = append(line, buf[0])
	}
	result, err := p.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stderr) != "last\n" || !result.StderrTruncated {
		t.Fatalf("stderr %q truncated=%t", result.Stderr, result.StderrTruncated)
	}
	awaitGone(t, line)
}

func TestBufferHeadAndTail(t *testing.T) {
	head, tail := NewBuffer(4), NewTailBuffer(4)
	for _, chunk := range []string{"ab", "cde", "f"} {
		for _, b := range []*Buffer{head, tail} {
			if n, err := b.Write([]byte(chunk)); n != len(chunk) || err != nil {
				t.Fatalf("write %q: %d %v", chunk, n, err)
			}
		}
	}
	if head.String() != "abcd" || !head.Truncated() || tail.String() != "cdef" || !tail.Truncated() {
		t.Fatalf("head %q tail %q", head.String(), tail.String())
	}
}

// awaitGone polls until the descendant whose PID the script printed is gone.
func awaitGone(t *testing.T, stdout []byte) {
	t.Helper()
	pid, err := strconv.Atoi(strings.TrimSpace(string(stdout)))
	if err != nil {
		t.Fatalf("descendant pid %q: %v", stdout, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		state, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if errors.Is(err, os.ErrNotExist) || (err == nil && strings.Contains(string(state), ") Z ")) {
			return
		}
		if time.Now().After(deadline) {
			_ = unix.Kill(pid, unix.SIGKILL)
			t.Fatalf("descendant %d survived", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunValidatesSessionBusAddress(t *testing.T) {
	bus := func(env string, credential *syscall.Credential) error {
		_, err := Run(t.Context(), Command{Path: "/usr/bin/env", Env: []string{env}, Credential: credential, Timeout: 5 * time.Second, StdoutLimit: 4096, StderrLimit: 4096})
		return err
	}
	self := uint32(os.Getuid())
	own := "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + strconv.FormatUint(uint64(self), 10) + "/bus"
	if err := bus(own, nil); err != nil {
		t.Fatalf("own session bus refused: %v", err)
	}
	for _, env := range []string{
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/bus",
		"DBUS_SESSION_BUS_ADDRESS=unix:abstract=/run/user/1000/bus",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/01000/bus",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=x",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/../0/bus",
		"DBUS_SESSION_BUS_ADDRESS=tcp:host=localhost,port=1",
	} {
		if err := bus(env, nil); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("%s accepted: %v", env, err)
		}
	}
	// With a credential the bus must be that user's.
	if err := bus(own, &syscall.Credential{Uid: self + 1, Gid: uint32(os.Getgid())}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("another user's bus accepted: %v", err)
	}
	if _, err := Run(t.Context(), Command{Path: "/usr/bin/env", Env: []string{"NEEDRESTART_MODE=a"}, Timeout: 5 * time.Second, StdoutLimit: 4096, StderrLimit: 4096}); err != nil {
		t.Fatalf("NEEDRESTART_MODE refused: %v", err)
	}
}

func TestRunWithCredentialDropsToThatUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing credentials requires root")
	}
	const uid, gid = 65534, 65534
	result, err := Run(t.Context(), Command{
		Path: shell, Args: []string{"-c", "id -u; id -g; id -G"},
		Env:        []string{"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/65534/bus"},
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
		Timeout:    5 * time.Second, StdoutLimit: 4096, StderrLimit: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Stdout); got != "65534\n65534\n65534\n" {
		t.Fatalf("child identity %q", got)
	}
}
