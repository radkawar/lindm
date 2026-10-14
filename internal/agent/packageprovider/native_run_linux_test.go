// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"lindm/internal/agent/nativeexec"
)

func TestRunNativeErrorOmitsRawStderr(t *testing.T) {
	result, err := runNative(context.Background(), "/usr/bin/sh", []string{"-c", `printf 'first\033[31m line\nsecret second line\n' >&2; exit 3`}, "/", nil)
	var exit *nativeexec.ExitError
	if !errors.As(err, &exit) || exit.Code != 3 {
		t.Fatalf("err = %v, want exit status 3", err)
	}
	if message := err.Error(); strings.Contains(message, "secret") || strings.ContainsAny(message, "\x1b\n") {
		t.Fatalf("error copies raw stderr: %q", message)
	}
	if !strings.Contains(string(result.stderr), "secret second line") {
		t.Fatalf("stderr not retained for classification: %q", result.stderr)
	}
}

func TestRunNativeTruncatedOutputFails(t *testing.T) {
	_, err := runNative(context.Background(), "/usr/bin/sh", []string{"-c", "head -c 70000 /dev/zero >&2"}, "/", nil)
	if !errors.Is(err, nativeexec.ErrOutputLimit) {
		t.Fatalf("err = %v, want output limit", err)
	}
}

func TestCommitNativeTerminatesInsteadOfKilling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := commitNative(ctx, "/usr/bin/sh", []string{"-c", `trap 'echo terminated; exit 0' TERM; echo ready; /usr/bin/sleep 30 & wait`}, "/", nil)
	if !strings.Contains(string(result.stdout), "terminated") {
		t.Fatalf("mutating step was not given SIGTERM: stdout %q, err %v", result.stdout, err)
	}
}
