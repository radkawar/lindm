package labhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

// baselineCommand always sends the program over stdin. No user-controlled value
// is interpolated into the SSH login shell (which need not be a POSIX shell).
func baselineCommand(ctx context.Context, host *labv1.LabHost, script string, timeout time.Duration, diagnostics io.Writer) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var cmd *exec.Cmd
	switch host.GetTransport() {
	case "local":
		cmd = exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc", "-s")
	case "ssh":
		if !baselineAlias(host.GetSshAlias()) {
			return nil, errors.New("labhost: baseline requires a plain SSH alias, not SSH options, a user@host or a command")
		}
		cmd = exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none", "--", host.GetSshAlias(), "/bin/bash --noprofile --norc -s")
	default:
		return nil, fmt.Errorf("labhost: unsupported baseline transport %q", host.GetTransport())
	}
	cmd.Stdin = strings.NewReader("set -euo pipefail\nexport LC_ALL=C\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n" + script)
	cmd.WaitDelay = 2 * time.Second
	stdout, stderr := &baselineOutput{limit: 4 << 20}, &baselineOutput{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if diagnostics != nil {
		cmd.Stderr = io.MultiWriter(stderr, diagnostics)
	}
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		err = errors.Join(err, errors.New("baseline command output exceeded its evidence limit"))
	}
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("labhost: baseline command: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type baselineOutput struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *baselineOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.limit-b.buffer.Len() {
		p = p[:b.limit-b.buffer.Len()]
		b.exceeded = true
	}
	_, err := b.buffer.Write(p)
	return n, err
}

func (b *baselineOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *baselineOutput) String() string { return b.buffer.String() }

func baselineAlias(alias string) bool {
	if alias == "" || alias[0] == '-' || len(alias) > 253 {
		return false
	}
	for _, c := range alias {
		if !aliasRune(c) {
			return false
		}
	}
	return true
}

func aliasRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// baselineQuote is used only inside the explicit Bash program, never by the
// remote login shell. It also protects package versions, usernames and paths.
func baselineQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
