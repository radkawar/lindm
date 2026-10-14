// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestCappedWriterBoundsInstallerLogButKeepsDraining(t *testing.T) {
	var log bytes.Buffer
	writer := &cappedWriter{w: &log, remaining: 10}
	written, err := io.Copy(writer, strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil || written != 4096 {
		t.Fatalf("console drain stopped at %d bytes: %v", written, err)
	}
	if log.Len() != 10 {
		t.Fatalf("installer log kept %d bytes, want 10", log.Len())
	}
}
