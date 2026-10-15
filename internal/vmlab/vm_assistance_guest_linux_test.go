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

func TestAssistanceHostsFilePrecedesSyntheticLocalhost(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
	}{
		{"omarchy", "passwd: files systemd\nhosts: mymachines mdns_minimal [NOTFOUND=return] resolve files myhostname dns\n",
			"passwd: files systemd\nhosts: files mymachines mdns_minimal [NOTFOUND=return] resolve myhostname dns\n"},
		{"already first", "hosts: files myhostname resolve [!UNAVAIL=return] dns\n",
			"hosts: files myhostname resolve [!UNAVAIL=return] dns\n"},
		{"files actions", "hosts: resolve [!UNAVAIL=return] files [NOTFOUND=continue SUCCESS=return] dns\n",
			"hosts: files [NOTFOUND=continue SUCCESS=return] resolve [!UNAVAIL=return] dns\n"},
		{"missing files", "hosts: myhostname dns # files is absent\n",
			"hosts: files myhostname dns # files is absent\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			for range 2 {
				command := exec.CommandContext(t.Context(), "/bin/sh", "-eu", "-c", assistanceNSSHostsFilesFirst)
				command.Stdin = strings.NewReader(input)
				output, err := command.CombinedOutput()
				if err != nil || string(output) != test.want {
					t.Fatalf("NSS hosts ordering = %q, %v; want %q", output, err, test.want)
				}
				input = string(output)
			}
		})
	}
	command := exec.CommandContext(t.Context(), "/bin/sh", "-eu", "-c", assistanceNSSHostsFilesFirst)
	command.Stdin = strings.NewReader("passwd: files systemd\n")
	if err := command.Run(); err == nil {
		t.Fatal("accepted NSS configuration without a hosts entry")
	}
}
