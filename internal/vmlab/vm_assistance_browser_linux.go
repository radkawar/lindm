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
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// assistanceBrowser drives one real headless Chromium through the maintained
// Playwright runner (web/acceptance/assistance.mjs) with a line-oriented
// private protocol. The operator signs in through the console UI; the lane
// never injects cookies, RPCs or alternate application code into the page.
type assistanceBrowser struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	replies chan assistanceBrowserReply
	done    chan struct{}
	waitErr error
	next    int
	// version is the Chromium build Playwright launched.
	version string
}

type assistanceBrowserConfig struct {
	Origin            string `json:"origin"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	EnrollmentSecret  string `json:"enrollmentSecret"`
	EvidenceDirectory string `json:"evidenceDirectory"`
	ActionTimeoutMS   int    `json:"actionTimeoutMs"`
}

type assistanceBrowserReply struct {
	ID     int             `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
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
	cmd := exec.Command("node", filepath.Join(repository, "web/acceptance/assistance.mjs"), path)
	cmd.Dir = repository
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	// Framework diagnostics can echo filled credentials; replies are the only
	// channel the lane reads.
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start assistance browser runner: %w", err)
	}
	b := &assistanceBrowser{cmd: cmd, stdin: stdin, replies: make(chan assistanceBrowserReply, 1), done: make(chan struct{})}
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
	if _, err := b.stdin.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("send browser command %s: %w", op, err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return errors.Join(fmt.Errorf("browser command %s: %w", op, ctx.Err()), b.Close())
	case reply, ok := <-b.replies:
		if !ok {
			return fmt.Errorf("browser runner exited during %s: %v", op, b.waitErr)
		}
		if reply.ID != id {
			return fmt.Errorf("browser runner replied out of order during %s", op)
		}
		if !reply.OK {
			return fmt.Errorf("browser command %s failed: %s", op, reply.Error)
		}
		if result == nil {
			return nil
		}
		if err := json.Unmarshal(reply.Result, result); err != nil {
			return fmt.Errorf("browser command %s returned invalid result: %w", op, err)
		}
		return nil
	}
}

// Close asks the runner to close Chromium, then kills the process group if it
// has not exited within a bounded grace period.
func (b *assistanceBrowser) Close() error {
	if b.cmd == nil {
		return nil
	}
	cmd := b.cmd
	b.cmd = nil
	_, _ = b.stdin.Write([]byte(`{"op":"close"}` + "\n"))
	_ = b.stdin.Close()
	// Drain stray replies so the reader can observe EOF and finish.
	replies, grace, killed := b.replies, time.After(20*time.Second), false
	for waiting := true; waiting; {
		select {
		case <-b.done:
			waiting = false
		case _, ok := <-replies:
			if !ok {
				replies = nil
			}
		case <-grace:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			grace, killed = nil, true
		}
	}
	err := cmd.Wait()
	if killed {
		return errors.Join(errors.New("assistance browser runner required forced shutdown"), err)
	}
	return err
}
