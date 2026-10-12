// Package nativeexec is the agent's only native process runner. Every caller
// gets the same policy: argv only (never a shell), an absolute executable that
// passes a custody check, a fixed clean environment plus explicitly allowlisted
// keys, its own process group killed as a whole on deadline or cancellation,
// separately bounded stdout and stderr, an explicit per-call deadline and
// limits, and errors that never carry stderr, argv or the environment.
//
// Non-goals: choosing tools or arguments (callers own their closed command
// sets), privilege dropping, namespaces, or interpreting native output.
package nativeexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

// Bounds every caller shares. A deadline or limit outside them is a caller bug.
const (
	MaxTimeout     = 24 * time.Hour
	MaxOutputLimit = 64 << 20
	// waitDelay bounds how long output may keep flowing from descendants that
	// still hold the pipes after the leader exits; then the group is killed.
	waitDelay = 2 * time.Second
	// diagnosticBytes bounds the opt-in sanitized stderr line.
	diagnosticBytes = 256
)

// basePath is the only PATH a native tool sees: merged-/usr distributions
// resolve /sbin and /bin through these directories.
const basePath = "PATH=/usr/sbin:/usr/bin"

// allowedEnv are the only keys a caller may add to the fixed C-locale base.
// Each is a native tool's documented non-interactive or reproducibility knob.
var allowedEnv = map[string]bool{
	"HOME":                 true, // pin to / so no per-user tool configuration is read
	"TZ":                   true, // stable timestamps in parsed output
	"DEBIAN_FRONTEND":      true, // noninteractive apt/dpkg
	"APT_CONFIG":           true, // private staged APT configuration
	"DPKG_FRONTEND_LOCKED": true, // dpkg invoked under the caller's frontend lock
	// libzypp's documented EnvironmentVariables/zypp.conf inputs. Preparation
	// uses a private lock root; live apply deliberately omits that override.
	"ZYPP_CONF":          true, // sole private staged zypp configuration
	"ZYPP_LOGFILE":       true, // private caller-owned diagnostic destination
	"ZYPP_LOCK_TIMEOUT":  true, // fail immediately when the native lock is busy
	"ZYPP_LOCKFILE_ROOT": true, // isolate preparation's frontend lock only
	"ZYPPTMPDIR":         true, // private temporary tree holding zypper's hard link to a command-line RPM
	"SYSTEMD_COLORS":     true,
	"SYSTEMD_PAGER":      true,
	"SYSTEMD_UNIT_PATH":  true, // private staged unit verification
	"SOURCE_DATE_EPOCH":  true, // reproducible recovery image builds
	"NEEDRESTART_MODE":   true, // needrestart's dpkg hook restarts services without prompting
	// The caller's own user session bus, validated by sessionBusAddress: only
	// unix:path=/run/user/<uid>/bus, and with Credential set only that UID's.
	"DBUS_SESSION_BUS_ADDRESS": true,
}

var (
	ErrUntrustedExecutable = errors.New("nativeexec: untrusted_executable")
	ErrInvalidCommand      = errors.New("nativeexec: invalid_command")
	ErrOutputLimit         = errors.New("nativeexec: output_limit")
	ErrDeadline            = errors.New("nativeexec: deadline_exceeded")
)

// Command is one native invocation. Path, Timeout and both limits are required.
type Command struct {
	// Path is the absolute executable; argv[0] is Path as given.
	Path string
	Args []string
	// Env adds KEY=VALUE pairs from the allowlist to PATH, LANG=C and LC_ALL=C.
	Env []string
	// Dir defaults to /.
	Dir   string
	Stdin []byte
	// Files are inherited as descriptors 3, 4, ...
	Files       []*os.File
	Timeout     time.Duration
	StdoutLimit int
	StderrLimit int
	// Stream, when set, consumes stdout instead of buffering it. Returning
	// before EOF kills the process group and sets Result.Stopped.
	Stream func(io.Reader)
	// StdoutTee and StderrTee observe every byte before bounding, for callers
	// that keep their own bounded diagnostics (a tail, a redaction latch).
	StdoutTee, StderrTee io.Writer
	// TerminateOnly sends SIGTERM instead of SIGKILL to the group on deadline,
	// cancellation or a stopped Stream, then waits for the tool to exit however
	// long it takes. It exists only for package-manager steps that mutate the
	// package database: SIGKILL could leave dpkg/rpm half-configured. The
	// caller's service unit timeout bounds such a run instead.
	TerminateOnly bool
	// Credential runs the child as another user (UID, primary GID and exactly
	// the listed supplementary groups) for a root caller acting on a user's
	// behalf, such as a desktop notification on that user's session bus.
	Credential *syscall.Credential
}

// Result is the structured outcome of a completed run.
type Result struct {
	Stdout, Stderr                   []byte
	StdoutTruncated, StderrTruncated bool
	// ExitCode is -1 when the process did not exit normally.
	ExitCode int
	// Stopped reports that Stream returned before EOF and the group was killed.
	Stopped bool
}

// Diagnostic returns stderr's first line with non-printable bytes replaced and
// bounded. It is the only opt-in way to surface stderr: callers use it only for
// tools whose diagnostics cannot echo secrets they were given.
func (r Result) Diagnostic() string {
	line, _, _ := strings.Cut(string(r.Stderr), "\n")
	line = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, line)
	if len(line) > diagnosticBytes {
		line = line[:diagnosticBytes]
	}
	return line
}

// ExitError reports a non-zero exit or a signal. It carries no output.
type ExitError struct {
	Program string
	Code    int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("nativeexec: %s exited with status %d", e.Program, e.Code)
}

// ExitCode is the exit status, or -1 when the process was signalled.
func (e *ExitError) ExitCode() int { return e.Code }

// Executable resolves path and requires the target to live under /usr/, to be
// reached through root-owned directories that no group or other user can write,
// and itself to be a root-owned, non-writable, executable regular file. A
// protected regular file without execute bits is reported as fs.ErrPermission,
// as execve's EACCES would be (systemd InaccessiblePaths= masks a tool so).
func Executable(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%w: %s", ErrUntrustedExecutable, path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(resolved, "/usr/") {
		return "", fmt.Errorf("%w: %s", ErrUntrustedExecutable, path)
	}
	file, stat, err := custody.OpenRoot(resolved, unix.O_PATH)
	if err != nil {
		return "", errors.Join(ErrUntrustedExecutable, err)
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := leafError(stat.Mode, path); err != nil {
		return "", err
	}
	return resolved, nil
}

// leafError classifies a custody-checked leaf: anything but a regular file is
// untrusted, and a regular file without execute bits is an access failure.
func leafError(mode uint32, path string) error {
	switch {
	case mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: %s", ErrUntrustedExecutable, path)
	case mode&0o111 == 0:
		return fmt.Errorf("%w: %s", fs.ErrPermission, path)
	default:
		return nil
	}
}

// sessionBusAddress accepts only a user's runtime-directory session bus, in
// canonical decimal form, owned by the credential's UID when one is set.
func sessionBusAddress(value string, credential *syscall.Credential) bool {
	uid, ok := strings.CutPrefix(value, "unix:path=/run/user/")
	if !ok {
		return false
	}
	uid, ok = strings.CutSuffix(uid, "/bus")
	if !ok {
		return false
	}
	n, err := strconv.ParseUint(uid, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != uid {
		return false
	}
	return credential == nil || credential.Uid == uint32(n)
}

func (c *Command) prepare() (*exec.Cmd, error) {
	if c.Timeout <= 0 || c.Timeout > MaxTimeout || c.StderrLimit <= 0 || c.StderrLimit > MaxOutputLimit {
		return nil, ErrInvalidCommand
	}
	env := []string{basePath, "LANG=C", "LC_ALL=C"}
	for _, entry := range c.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !allowedEnv[key] || strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("%w: environment key %q", ErrInvalidCommand, key)
		}
		if key == "DBUS_SESSION_BUS_ADDRESS" && !sessionBusAddress(value, c.Credential) {
			return nil, fmt.Errorf("%w: session bus address", ErrInvalidCommand)
		}
		env = append(env, entry)
	}
	for _, arg := range c.Args {
		if strings.ContainsRune(arg, 0) {
			return nil, ErrInvalidCommand
		}
	}
	resolved, err := Executable(c.Path)
	if err != nil {
		return nil, err
	}
	dir := c.Dir
	if dir == "" {
		dir = "/"
	}
	// The verified target runs; argv[0] stays the requested name for tools that
	// dispatch on it.
	cmd := exec.Command(resolved, c.Args...)
	cmd.Args[0] = c.Path
	cmd.Env, cmd.Dir, cmd.ExtraFiles = env, dir, c.Files
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if c.Credential != nil {
		credential := *c.Credential
		credential.Groups = append([]uint32{}, c.Credential.Groups...)
		cmd.SysProcAttr.Credential = &credential
	}
	cmd.WaitDelay = waitDelay
	return cmd, nil
}

// group signals a process group whose leader has not been reaped yet. An
// unreaped leader, even a zombie, keeps its PGID from being reused, so the
// numeric group can never name an unrelated process.
type group struct {
	mu     sync.Mutex
	pid    int
	signal unix.Signal
	reaped bool
}

func (g *group) kill() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.reaped {
		// ESRCH only means every member has already gone.
		_ = unix.Kill(-g.pid, g.signal)
	}
}

func (g *group) reap(cmd *exec.Cmd) error {
	g.mu.Lock()
	g.reaped = true
	g.mu.Unlock()
	return cmd.Wait()
}

// awaitExit blocks until the leader exits without reaping it.
func awaitExit(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// drained records whether the consumer read stdout to EOF.
type drained struct {
	reader io.Reader
	eof    bool
}

func (d *drained) Read(p []byte) (int, error) {
	n, err := d.reader.Read(p)
	if errors.Is(err, io.EOF) {
		d.eof = true
	}
	return n, err
}

// Run executes c to completion under c.Timeout. It returns the result together
// with: the parent context's error if the caller cancelled; ErrDeadline (which
// also matches context.DeadlineExceeded) if c.Timeout expired; *ExitError for a
// non-zero exit; ErrOutputLimit if either stream was truncated. The result is
// populated whenever the process started.
func Run(ctx context.Context, c Command) (Result, error) {
	result := Result{ExitCode: -1}
	if c.Stream == nil && (c.StdoutLimit <= 0 || c.StdoutLimit > MaxOutputLimit) {
		return result, ErrInvalidCommand
	}
	cmd, err := c.prepare()
	if err != nil {
		return result, err
	}
	call, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return result, err
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		return result, errors.Join(err, stdoutRead.Close(), stdoutWrite.Close())
	}
	cmd.Stdout, cmd.Stderr = stdoutWrite, stderrWrite
	startErr := cmd.Start()
	closeErr := errors.Join(stdoutWrite.Close(), stderrWrite.Close())
	if startErr != nil {
		return result, errors.Join(startErr, closeErr, stdoutRead.Close(), stderrRead.Close())
	}
	g := &group{pid: cmd.Process.Pid, signal: unix.SIGKILL}
	if c.TerminateOnly {
		g.signal = unix.SIGTERM
	}
	stdout, stderr := NewBuffer(c.StdoutLimit), NewBuffer(c.StderrLimit)
	var copies sync.WaitGroup
	copies.Go(func() { _, _ = io.Copy(tee(stderr, c.StderrTee), stderrRead) })
	copies.Go(func() {
		if c.Stream == nil {
			_, _ = io.Copy(tee(stdout, c.StdoutTee), stdoutRead)
			return
		}
		reader := &drained{reader: io.TeeReader(stdoutRead, tee(io.Discard, c.StdoutTee))}
		c.Stream(reader)
		if !reader.eof {
			result.Stopped = true
			g.kill()
		}
	})
	stop := context.AfterFunc(call, g.kill)
	exitErr := awaitExit(g.pid)
	outputs := make(chan struct{})
	go func() { copies.Wait(); close(outputs) }()
	// Drain what the group already wrote even after a deadline; the deadline
	// itself was enforced by the AfterFunc signal.
	timer := time.NewTimer(waitDelay)
	select {
	case <-outputs:
		// A clean finish leaves no pipe holders; detached descendants that
		// closed their output are not this call's to kill.
	case <-timer.C:
		// Descendants still hold the pipes after the leader exited.
		g.kill()
	}
	timer.Stop()
	stop()
	// Group members are dead or about to be. Closing our ends also unblocks
	// copies from any descendant that escaped the group with an inherited pipe.
	closeErr = errors.Join(closeErr, stdoutRead.Close(), stderrRead.Close())
	<-outputs
	waitErr := g.reap(cmd)
	if exitErr != nil {
		closeErr = errors.Join(closeErr, exitErr)
	}
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	result.StdoutTruncated, result.StderrTruncated = stdout.Truncated(), stderr.Truncated()
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	return result, classify(ctx, call, filepath.Base(c.Path), result, waitErr, closeErr)
}

// Process is a long-lived native process from Start. The caller reads its
// stdout; stderr keeps only the most recent StderrLimit bytes.
type Process struct {
	cmd     *exec.Cmd
	group   *group
	stdout  *os.File
	stderr  *os.File
	tail    *Buffer
	copied  chan struct{}
	stop    func() bool
	cancel  context.CancelFunc
	once    sync.Once
	result  Result
	program string
	err     error
}

// Start launches c for a caller that streams stdout itself, e.g. a media
// pipeline. Stream, StdoutLimit and StdoutTee do not apply. c.Timeout bounds
// the whole lifetime: at expiry or ctx cancellation the group is killed. The
// child also receives SIGKILL if the starting thread dies. Close is required.
func Start(ctx context.Context, c Command) (*Process, error) {
	if c.Stream != nil || c.StdoutTee != nil || c.TerminateOnly {
		return nil, ErrInvalidCommand
	}
	cmd, err := c.prepare()
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, stdoutRead.Close(), stdoutWrite.Close())
	}
	cmd.Stdout, cmd.Stderr = stdoutWrite, stderrWrite
	startErr := cmd.Start()
	closeErr := errors.Join(stdoutWrite.Close(), stderrWrite.Close())
	if startErr != nil || closeErr != nil {
		if startErr == nil {
			_ = cmd.Process.Kill() // the descriptor failure is reported instead
			_ = cmd.Wait()
		}
		return nil, errors.Join(startErr, closeErr, stdoutRead.Close(), stderrRead.Close())
	}
	life, cancel := context.WithTimeout(ctx, c.Timeout)
	p := &Process{cmd: cmd, group: &group{pid: cmd.Process.Pid, signal: unix.SIGKILL}, stdout: stdoutRead, stderr: stderrRead, tail: NewTailBuffer(c.StderrLimit), copied: make(chan struct{}), cancel: cancel, program: filepath.Base(c.Path)}
	go func() {
		defer close(p.copied)
		_, _ = io.Copy(tee(p.tail, c.StderrTee), stderrRead)
	}()
	p.stop = context.AfterFunc(life, p.group.kill)
	return p, nil
}

// Stdout is the child's standard output.
func (p *Process) Stdout() io.Reader { return p.stdout }

// Close kills the whole group, reaps the leader and returns the final result
// with the stderr tail. A signal exit caused by Close is not an error.
func (p *Process) Close() (Result, error) {
	p.once.Do(func() {
		p.stop()
		p.group.kill()
		p.cancel()
		timer := time.NewTimer(waitDelay)
		select {
		case <-p.copied:
		case <-timer.C:
		}
		timer.Stop()
		closeErr := errors.Join(p.stdout.Close(), p.stderr.Close())
		<-p.copied
		waitErr := p.group.reap(p.cmd)
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) || errors.Is(waitErr, exec.ErrWaitDelay) {
			waitErr = nil
		}
		p.result = Result{Stderr: p.tail.Bytes(), StderrTruncated: p.tail.Truncated(), ExitCode: -1}
		if p.cmd.ProcessState != nil {
			p.result.ExitCode = p.cmd.ProcessState.ExitCode()
		}
		if waitErr != nil {
			waitErr = fmt.Errorf("nativeexec: wait %s: %w", p.program, waitErr)
		}
		p.err = errors.Join(waitErr, closeErr)
	})
	return p.result, p.err
}

func classify(parent, call context.Context, program string, result Result, waitErr, closeErr error) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if call.Err() != nil {
		return fmt.Errorf("%w: %s: %w", ErrDeadline, program, context.DeadlineExceeded)
	}
	var err error
	var exit *exec.ExitError
	switch {
	case errors.As(waitErr, &exit):
		err = &ExitError{Program: program, Code: exit.ExitCode()}
	case waitErr != nil && !errors.Is(waitErr, exec.ErrWaitDelay):
		err = fmt.Errorf("nativeexec: wait %s: %w", program, waitErr)
	}
	if result.StdoutTruncated || result.StderrTruncated {
		err = errors.Join(fmt.Errorf("%w: %s", ErrOutputLimit, program), err)
	}
	return errors.Join(err, closeErr)
}

func tee(w io.Writer, observer io.Writer) io.Writer {
	if observer == nil {
		return w
	}
	return io.MultiWriter(w, observer)
}
