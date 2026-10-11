// Package labexec runs host tools for the lab, development-fixture, packaging
// and release harnesses. Every child gets its own process group. Cancellation
// or a deadline kills the whole group, optionally after a graceful signal and a
// bounded grace period. The group is signalled only while its leader is
// unreaped, so a recycled PGID never names an unrelated process. Output that
// outlives the leader is drained for a bounded delay, then the group is killed.
// Errors never carry the child's output, argv or environment.
//
// Non-goals: the agent's native-tool policy (custody-checked /usr executables
// and a fixed environment belong to internal/agent/nativeexec), choosing output
// bounds (callers pass nativeexec.Buffer or their own sinks), privilege or
// namespace changes, and children that must outlive their caller.
package labexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// drainDelay bounds how long output that outlives the leader, or a stdin copy
// the child abandoned, may hold the call open before the group is killed.
const drainDelay = 5 * time.Second

// Command is one host tool invocation.
type Command struct {
	// Path is an absolute path or a name looked up in the caller's PATH.
	Path string
	Args []string
	// Env nil inherits the caller's environment, as with os/exec.
	Env []string
	Dir string
	// Stdin nil reads from the null device.
	Stdin io.Reader
	// Stdout and Stderr nil discard. A writer that fails is still drained so
	// the child never blocks; the write error is returned.
	Stdout, Stderr io.Writer
	Files          []*os.File
	// Timeout, when positive, bounds the call in addition to ctx.
	Timeout time.Duration
	// Interrupt, when set, is sent to the group first on cancellation; the
	// group is killed once the leader exits or after Grace, whichever is first.
	Interrupt syscall.Signal
	Grace     time.Duration
}

// Process is a started Command. Wait or Close is required.
type Process struct {
	cmd     *exec.Cmd
	program string
	call    context.Context
	cancel  context.CancelFunc
	stop    func() bool
	readers []*os.File
	sinks   []io.Writer
	copies  sync.WaitGroup

	mu      sync.Mutex // guards the fields below
	reaped  bool
	closing bool
	grace   *time.Timer
	copyErr error

	once sync.Once
	err  error
}

// Run executes c to completion. It returns ctx's (or Timeout's) error if the
// call was cancelled, the *exec.ExitError for a non-zero exit, and any error
// from a caller's writer.
func Run(ctx context.Context, c Command) error {
	p, err := start(ctx, c, false)
	if err != nil {
		return err
	}
	return p.Wait()
}

// Start launches c for a caller that outlives this call's goroutine, e.g. a
// browser it drives. ctx and c.Timeout bound its whole lifetime. As with
// nativeexec.Start, the child also receives SIGKILL if the starting thread
// (in practice, the lab process) dies.
func Start(ctx context.Context, c Command) (*Process, error) {
	return start(ctx, c, true)
}

func start(ctx context.Context, c Command, parentDeath bool) (*Process, error) {
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env, cmd.Dir, cmd.Stdin, cmd.ExtraFiles = c.Env, c.Dir, c.Stdin, c.Files
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if parentDeath {
		cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	}
	cmd.WaitDelay = drainDelay
	p := &Process{cmd: cmd, program: filepath.Base(c.Path)}
	var writers []*os.File
	stdout, err := p.pipe(c.Stdout, &writers)
	stderr := stdout
	if err == nil && !sameWriter(c.Stdout, c.Stderr) {
		// A shared sink keeps one pipe, so one goroutine writes to it.
		stderr, err = p.pipe(c.Stderr, &writers)
	}
	if err == nil {
		cmd.Stdout, cmd.Stderr = stdout, stderr
		err = cmd.Start()
	}
	// The child holds its own copies of the write ends.
	err = errors.Join(err, closeAll(writers))
	if err != nil {
		if cmd.Process != nil {
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL) // the descriptor failure is reported instead
			_ = cmd.Wait()
		}
		return nil, errors.Join(err, closeAll(p.readers))
	}
	if c.Timeout > 0 {
		p.call, p.cancel = context.WithTimeout(ctx, c.Timeout)
	} else {
		p.call, p.cancel = context.WithCancel(ctx)
	}
	for i, r := range p.readers {
		p.copies.Go(func() { p.drain(p.sinks[i], r) })
	}
	p.stop = context.AfterFunc(p.call, func() { p.interrupt(c.Interrupt, c.Grace) })
	return p, nil
}

// pipe returns the child's end for w: nil for the null device, w itself for a
// file, otherwise a pipe that a goroutine drains into w.
func (p *Process) pipe(w io.Writer, writers *[]*os.File) (io.Writer, error) {
	if w == nil {
		return nil, nil
	}
	if f, ok := w.(*os.File); ok {
		return f, nil
	}
	r, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	p.readers, p.sinks = append(p.readers, r), append(p.sinks, w)
	*writers = append(*writers, pw)
	return pw, nil
}

func closeAll(files []*os.File) error {
	var err error
	for _, f := range files {
		err = errors.Join(err, f.Close())
	}
	return err
}

// drain copies until the child's side closes or Wait closes ours. A failing
// sink is reported but never stops the drain, so the child cannot block.
func (p *Process) drain(w io.Writer, r io.Reader) {
	s := &sink{w: w}
	_, _ = io.Copy(s, r)
	if s.err != nil {
		p.mu.Lock()
		p.copyErr = errors.Join(p.copyErr, fmt.Errorf("labexec: %s output: %w", p.program, s.err))
		p.mu.Unlock()
	}
}

// sink keeps the first write error and discards later output. As a plain
// Writer it also stops io.Copy from bypassing a bounded sink's Write.
type sink struct {
	w   io.Writer
	err error
}

func (s *sink) Write(p []byte) (int, error) {
	if s.err == nil {
		var n int
		if n, s.err = s.w.Write(p); s.err == nil && n < len(p) {
			s.err = io.ErrShortWrite
		}
	}
	return len(p), nil
}

// sameWriter reports whether a and b are the same comparable writer, as
// os/exec does for a shared Stdout and Stderr.
func sameWriter(a, b io.Writer) (same bool) {
	if a == nil || b == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

// signal signals the group while its leader is unreaped: an unreaped leader,
// even a zombie, keeps the PGID from being reused.
func (p *Process) signal(sig syscall.Signal) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.reaped {
		// ESRCH only means every member has already gone.
		_ = unix.Kill(-p.cmd.Process.Pid, sig)
	}
}

func (p *Process) interrupt(sig syscall.Signal, grace time.Duration) {
	if sig == 0 || sig == syscall.SIGKILL {
		p.signal(syscall.SIGKILL)
		return
	}
	p.signal(sig)
	p.mu.Lock()
	if !p.reaped {
		p.grace = time.AfterFunc(grace, func() { p.signal(syscall.SIGKILL) })
	}
	p.mu.Unlock()
}

// Wait waits for the leader, drains its output and reaps it.
func (p *Process) Wait() error {
	p.once.Do(func() { p.err = p.wait() })
	return p.err
}

// Close kills the whole group and waits. An exit caused by that kill is not an
// error; a result the process already reached is returned unchanged.
func (p *Process) Close() error {
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
	p.signal(syscall.SIGKILL)
	return p.Wait()
}

func (p *Process) wait() error {
	exitErr := awaitExit(p.cmd.Process.Pid)
	outputs := make(chan struct{})
	go func() { p.copies.Wait(); close(outputs) }()
	timer := time.NewTimer(drainDelay)
	select {
	case <-outputs:
		// Detached descendants that closed their output are not this call's.
	case <-p.call.Done():
	case <-timer.C:
		// Descendants still hold the output after the leader exited.
		p.signal(syscall.SIGKILL)
	}
	timer.Stop()
	p.stop()
	ctxErr := p.call.Err()
	if ctxErr != nil {
		// Also stops descendants that survived a graceful Interrupt.
		p.signal(syscall.SIGKILL)
	}
	var closeErr error
	for _, r := range p.readers {
		// Unblocks copies from a descendant that escaped the group.
		closeErr = errors.Join(closeErr, r.Close())
	}
	<-outputs
	p.mu.Lock()
	p.reaped = true
	if p.grace != nil {
		p.grace.Stop()
	}
	closing, copyErr := p.closing, p.copyErr
	p.mu.Unlock()
	waitErr := p.cmd.Wait()
	p.cancel()
	if ctxErr != nil {
		return fmt.Errorf("labexec: %s: %w", p.program, ctxErr)
	}
	var exit *exec.ExitError
	if errors.Is(waitErr, exec.ErrWaitDelay) || closing && errors.As(waitErr, &exit) && killed(exit) {
		waitErr = nil
	}
	return errors.Join(waitErr, copyErr, exitErr, closeErr)
}

func killed(exit *exec.ExitError) bool {
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
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
