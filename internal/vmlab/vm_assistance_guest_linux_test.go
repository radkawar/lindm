// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Ptyxis forwards the launching client's directory to its session service.
// A client inherited the SSH user's private home on Rocky 10.2, so the
// terminal could not start its reader despite appearing on the screen.
func TestAssistanceTerminalUsesDesktopHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "desktop home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "/bin/sh", "-eu", "-c", assistanceTerminalAtHome, "sh", "/bin/pwd", "-P")
	command.Dir = t.TempDir()
	command.Env = []string{"HOME=" + home}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("launch from desktop home: %v: %s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != home {
		t.Fatalf("terminal inherited directory %q, want desktop home %q", got, home)
	}
}
