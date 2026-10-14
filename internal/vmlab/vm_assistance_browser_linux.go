// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/labexec"
)

// assistanceBrowser drives one real headless Chromium through the maintained
// Playwright runner (web/acceptance/assistance.mjs) with a line-oriented
// private protocol. The operator signs in through the console UI. Negative
// probes use that creator's real RPC cookie/CSRF authority; the lane never
// injects cookies, product data-channel frames or alternate application code.
type assistanceBrowser struct {
	process *labexec.Process
	stdin   *os.File
	stdout  *os.File
	replies chan assistanceBrowserReply
	done    chan struct{}
	waitErr error
	next    int
	// version is the Chromium build Playwright launched.
	version   string
	accountID string
}

type assistanceBrowserConfig struct {
	Origin            string `json:"origin"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	EnrollmentSecret  string `json:"enrollmentSecret"`
	EvidenceDirectory string `json:"evidenceDirectory"`
	ActionTimeoutMS   int    `json:"actionTimeoutMs"`
	TURNTCPOnly       bool   `json:"turnTcpOnly"`
	ForwardedTURNURL  string `json:"forwardedTurnUrl,omitempty"`
}

type assistanceBrowserReply struct {
	ID           int             `json:"id"`
	OK           bool            `json:"ok"`
	Result       json.RawMessage `json:"result"`
	Error        json.RawMessage `json:"error"`
	StartupStage string          `json:"startupStage"`
}

// maxAssistanceBrowserReply bounds one protocol line; replies carry only
// small JSON observations, never screenshots.
const maxAssistanceBrowserReply = 64 << 10

// startAssistanceBrowser writes the secret-bearing configuration to a private
// file that is removed once the runner has read it, and starts the runner in
// its own process group so cleanup reaches Chromium too.
func startAssistanceBrowser(ctx context.Context, repository, private string, cfg assistanceBrowserConfig) (_ *assistanceBrowser, err error) {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	path := filepath.Join(private, "assistance-browser.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.Remove(path)) }()
	childStdin, stdin, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, childStdin.Close(), stdin.Close())
	}
	// Framework diagnostics can echo filled credentials, so raw stderr remains
	// discarded. The bootstrap catches module-load failures before the runner's
	// command loop and emits only bounded, allowlisted startup classifications.
	process, err := labexec.Start(context.WithoutCancel(ctx), labexec.Command{Path: "node", Args: []string{filepath.Join(repository, "web/acceptance/assistance-bootstrap.mjs"), path}, Dir: repository, Stdin: childStdin, Stdout: childStdout})
	if closeErr := errors.Join(childStdin.Close(), childStdout.Close()); err != nil || closeErr != nil {
		if err == nil {
			err = errors.Join(closeErr, process.Close())
		}
		return nil, errors.Join(fmt.Errorf("start assistance browser runner: %w", err), stdin.Close(), stdout.Close())
	}
	b := &assistanceBrowser{process: process, stdin: stdin, stdout: stdout, replies: make(chan assistanceBrowserReply, 1), done: make(chan struct{})}
	go b.read(stdout)
	defer func() {
		if err != nil {
			err = errors.Join(err, b.Close())
		}
	}()
	// The runner reads its configuration before the first command; starting
	// sign-in proves it did, after which the private file is removed.
	var started struct {
		Version string `json:"version"`
	}
	if err := b.call(ctx, "start", nil, &started, 3*time.Minute); err != nil {
		return nil, err
	}
	b.version = started.Version
	return b, nil
}

// read owns stdout until the runner exits; its lifetime ends with the process.
func (b *assistanceBrowser) read(stdout io.Reader) {
	defer close(b.done)
	defer close(b.replies)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 4096), maxAssistanceBrowserReply)
	for scanner.Scan() {
		var reply assistanceBrowserReply
		if err := json.Unmarshal(scanner.Bytes(), &reply); err != nil {
			b.waitErr = errors.New("assistance browser runner wrote an invalid reply")
			return
		}
		b.replies <- reply
	}
	b.waitErr = scanner.Err()
}

// call sends one command and waits for its reply. A missed deadline kills the
// runner: a half-executed browser step is never reused.
func (b *assistanceBrowser) call(ctx context.Context, op string, args map[string]any, result any, timeout time.Duration) error {
	b.next++
	id := b.next
	line, err := json.Marshal(map[string]any{"id": id, "op": op, "args": args})
	if err != nil {
		return err
	}
	_, sendErr := b.stdin.Write(append(line, '\n'))
	if sendErr != nil {
		sendErr = fmt.Errorf("send browser command %s: %w", op, sendErr)
		if op != "start" {
			return sendErr
		}
		// A failed import/configuration may close stdin before the first write.
		// Still drain its bounded diagnostic replies rather than losing the cause.
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	phase, step := op, 0
	if op == "start" {
		phase = "start/node_start"
	}
	for {
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("browser command %s: %w", phase, ctx.Err()), sendErr, b.Close())
		case reply, ok := <-b.replies:
			if !ok {
				// EOF is not a process exit status. Close reaps the actual child
				// and retains its nonzero outcome while stopping its descendants.
				return errors.Join(fmt.Errorf("browser runner closed replies during %s", phase), sendErr, b.waitErr, b.Close())
			}
			if reply.StartupStage != "" {
				next := assistanceBrowserStartupStep(reply.StartupStage)
				if op != "start" || reply.ID != 0 || reply.OK || len(reply.Error) != 0 || len(reply.Result) != 0 || next <= step {
					return errors.New("browser runner wrote an invalid startup stage")
				}
				// Strictly increasing known steps bound this stream to eight
				// messages; arbitrary strings never become evidence.
				step, phase = next, "start/"+reply.StartupStage
				continue
			}
			if reply.ID != id && (op != "start" || reply.ID != 0 || reply.OK) {
				return fmt.Errorf("browser runner replied out of order during %s", phase)
			}
			if !reply.OK {
				return errors.Join(fmt.Errorf("browser command %s failed: %s", phase, reply.Error), sendErr)
			}
			if sendErr != nil {
				return sendErr
			}
			if result == nil {
				return nil
			}
			if err := json.Unmarshal(reply.Result, result); err != nil {
				return fmt.Errorf("browser command %s returned invalid result: %w", phase, err)
			}
			return nil
		}
	}
}

func assistanceBrowserStartupStep(stage string) int {
	switch stage {
	case "module_load":
		return 1
	case "configuration":
		return 2
	case "chromium_launch":
		return 3
	case "browser_setup":
		return 4
	case "navigation":
		return 5
	case "authenticator":
		return 6
	case "enrollment":
		return 7
	case "sign_in":
		return 8
	default:
		return 0
	}
}

// Close asks the runner to close Chromium, waits a bounded grace period for it
// to finish, then kills whatever remains of its process group and reaps it.
func (b *assistanceBrowser) Close() error {
	if b.process == nil {
		return nil
	}
	process := b.process
	b.process = nil
	_, _ = b.stdin.Write([]byte(`{"op":"close"}` + "\n"))
	_ = b.stdin.Close()
	// Drain stray replies so the reader can observe EOF and finish.
	graceCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	replies, grace, killed := b.replies, graceCtx.Done(), false
	var err error
	for waiting := true; waiting; {
		select {
		case <-b.done:
			waiting = false
		case _, ok := <-replies:
			if !ok {
				replies = nil
			}
		case <-grace:
			err = process.Close()
			grace, killed = nil, true
		}
	}
	if !killed {
		// EOF can precede the runner's exit(1). Observe the leader without
		// reaping it, then stop descendants while its PGID cannot be recycled.
		if exitErr := waitAssistanceBrowserExit(graceCtx, process.Pid()); exitErr != nil {
			killed = true
			err = errors.Join(exitErr, process.Close())
		} else {
			// Unlike forced Close, Wait must retain even a natural SIGKILL.
			process.Signal(syscall.SIGKILL)
			err = process.Wait()
		}
	}
	err = errors.Join(err, b.stdout.Close())
	if killed {
		return errors.Join(errors.New("assistance browser runner required forced shutdown"), err)
	}
	return err
}

func waitAssistanceBrowserExit(ctx context.Context, pid int) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("observe browser runner exit: %w", err)
		}
		if err == nil && info.Signo != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for browser runner exit: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
