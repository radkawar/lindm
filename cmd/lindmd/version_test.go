// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"os"
	"testing"

	"lindm/internal/agent/buildinfo"
)

func TestVersionNeedsNoConfiguration(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = original
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	commandErr := run(ctx, []string{"version"})
	closeErr := writer.Close()
	os.Stdout = original
	if commandErr != nil || closeErr != nil {
		t.Fatalf("version: %v; close output: %v", commandErr, closeErr)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != buildinfo.Line() {
		t.Fatalf("version output %q, want %q", output, buildinfo.Line())
	}
	for _, args := range [][]string{{"version", "extra"}, {"version", "-config", "missing.json"}} {
		if err := run(context.Background(), args); err == nil {
			t.Fatalf("version accepted arguments: %v", args)
		}
	}
}
