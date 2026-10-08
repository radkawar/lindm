//go:build linux

package packaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	toolOutputLimit = 1 << 20
	toolDeadline    = 3 * time.Minute
)

var lookupTool = defaultLookupTool

type toolCmd struct {
	Name     string
	Path     string
	Args     []string
	Dir      string
	ExtraEnv []string
	Stdin    io.Reader
	Stdout   io.Writer
	Timeout  time.Duration
}

func defaultLookupTool(name string) (string, error) {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, "tool name")
	}
	for _, dir := range []string{"/usr/bin", "/bin"} {
		candidate := dir + "/" + name
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(resolved, "/usr/bin/") && !strings.HasPrefix(resolved, "/bin/") {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%w: %s", ErrToolMissing, name)
}

func baseEnv(work string) []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"LC_ALL=C",
		"TZ=UTC",
		"HOME=" + work,
		"TMPDIR=" + filepath.Join(work, "tmp"),
		"TEMP=" + filepath.Join(work, "tmp"),
		"TMP=" + filepath.Join(work, "tmp"),
	}
}

func runTool(ctx context.Context, work string, cmd toolCmd) (stdout, stderr []byte, err error) {
	path := cmd.Path
	if path == "" {
		path, err = lookupTool(cmd.Name)
		if err != nil {
			return nil, nil, err
		}
	}
	timeout := cmd.Timeout
	if timeout <= 0 {
		timeout = toolDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	proc := exec.CommandContext(ctx, path, cmd.Args...)
	proc.Dir = cmd.Dir
	if proc.Dir == "" {
		proc.Dir = work
	}
	proc.Env = append(baseEnv(work), cmd.ExtraEnv...)
	proc.Env = append(proc.Env, "TMPDIR="+filepath.Join(work, "tmp"), "TEMP="+filepath.Join(work, "tmp"), "TMP="+filepath.Join(work, "tmp"))
	proc.Stdin = cmd.Stdin
	proc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	proc.WaitDelay = 2 * time.Second
	proc.Cancel = func() error {
		if proc.Process == nil {
			return os.ErrProcessDone
		}
		killErr := syscall.Kill(-proc.Process.Pid, syscall.SIGKILL)
		if errors.Is(killErr, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return killErr
	}
	outBuf := &limitedWriter{limit: toolOutputLimit}
	errBuf := &limitedWriter{limit: toolOutputLimit}
	if cmd.Stdout != nil {
		proc.Stdout = cmd.Stdout
	} else {
		proc.Stdout = outBuf
	}
	proc.Stderr = errBuf
	runErr := proc.Run()
	stdout = outBuf.buf.Bytes()
	stderr = errBuf.buf.Bytes()
	if outBuf.exceeded || errBuf.exceeded {
		return stdout, stderr, fmt.Errorf("%w: %s output exceeded limit", ErrArtifact, cmd.Name)
	}
	if runErr != nil {
		detail := redact(sanitize(stderr), work)
		if len(detail) > 512 {
			detail = detail[:512]
		}
		return stdout, stderr, fmt.Errorf("%s failed: %w; %s", filepath.Base(path), runErr, detail)
	}
	return stdout, stderr, nil
}

func redact(text, work string) string {
	if work == "" {
		return text
	}
	return strings.ReplaceAll(text, work, "<work>")
}

func sanitize(data []byte) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, string(data))
}

type limitedWriter struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.limit {
		w.exceeded = true
		return len(p), nil
	}
	remain := w.limit - w.buf.Len()
	if len(p) > remain {
		w.exceeded = true
		_, _ = w.buf.Write(p[:remain])
		return len(p), nil
	}
	return w.buf.Write(p)
}

func toolVersion(ctx context.Context, work, name string, args ...string) ToolVersion {
	path, err := lookupTool(name)
	if err != nil {
		return ToolVersion{Name: name, Version: "not-installed"}
	}
	stdout, stderr, err := runTool(ctx, work, toolCmd{Path: path, Args: args, Timeout: 15 * time.Second})
	text := string(stdout)
	if text == "" {
		text = string(stderr)
	}
	line := strings.TrimSpace(text)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if err != nil || line == "" {
		line = "unknown"
	}
	if len(line) > 200 {
		line = line[:200]
	}
	return ToolVersion{Name: name, Path: path, Version: line}
}
