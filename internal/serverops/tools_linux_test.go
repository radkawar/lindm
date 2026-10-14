// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestToolFailureRetainsSafeContextCause(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[deadline], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cause := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				cause = context.DeadlineExceeded
			} else {
				cancel()
			}
			defer cancel()
			err := runTool(ctx, "/bin/sh", []string{"-c", "printf test-private-password >&2"}, cleanEnvironment(), nil, io.Discard)
			if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "operations: sh_failed:") || strings.Contains(err.Error(), "test-private-password") {
				t.Fatalf("safe cancellation classification lost: %v", err)
			}
		})
	}
}

func TestToolFailureRedactsStderrAndArguments(t *testing.T) {
	var output bytes.Buffer
	err := runTool(t.Context(), "/bin/sh", []string{"-c", "printf test-private-password >&2; exit 2"}, cleanEnvironment(), nil, &output)
	if err == nil || err.Error() != "operations: sh_failed" || output.Len() != 0 {
		t.Fatal("subprocess failure exposed private stderr or arguments")
	}
}

func TestToolPrivateDiagnosticUsesSameRedactedRunner(t *testing.T) {
	var output, diagnostic bytes.Buffer
	err := runToolWithStderr(t.Context(), "/bin/sh", []string{"-c", "printf test-private-password >&2; exit 2"}, cleanEnvironment(), nil, &output, &diagnostic)
	if err == nil || err.Error() != "operations: sh_failed" || output.Len() != 0 || diagnostic.String() != "test-private-password" {
		t.Fatal("explicit diagnostic sink changed public failure redaction")
	}
}
