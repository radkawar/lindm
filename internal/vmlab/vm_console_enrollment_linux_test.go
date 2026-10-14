// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/platform"
)

// A changed newline or shell quote changes the command the console authenticated.
func TestReadConsoleCommandPreservesClipboardBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command")
	want := []byte("sudo sh <<'LINDM_ENROLL'\nprintf '%s' 'private-credential'\nLINDM_ENROLL\n")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readConsoleCommand(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if !bytes.Equal(got, want) {
		t.Fatal("clipboard command bytes changed")
	}
}

func TestReadConsoleCommandRejectsUnsafeCapture(t *testing.T) {
	for _, kind := range []string{"public", "symlink", "directory", "empty", "oversized", "nul"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "command")
			data := []byte("private-credential")
			mode := os.FileMode(0600)
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".target"
				if err := os.WriteFile(target, data, mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			default:
				switch kind {
				case "public":
					mode = 0644
				case "empty":
					data = nil
				case "oversized":
					data = bytes.Repeat([]byte("x"), (1<<20)+1)
				case "nul":
					data = append(data, 0)
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			got, err := readConsoleCommand(path)
			if err == nil || len(got) != 0 {
				t.Fatal("unsafe captured credential was accepted")
			}
			if strings.Contains(err.Error(), "private-credential") {
				t.Fatal("error disclosed credential")
			}
		})
	}
}

// The same native query must refuse a preinstalled package and later attest
// the package installed by the copied console command. Zypper is not DNF, but
// both use the RPM database; pacman must never fall through to a missing RPM.
func TestConsoleEnrollmentQueriesNativePackageDatabase(t *testing.T) {
	for _, test := range []struct {
		backend     platform.Backend
		tool, query string
	}{
		{platform.BackendAPT, "dpkg-query", "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n' lindm-agent"},
		{platform.BackendDNF4, "rpm", "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' lindm-agent"},
		{platform.BackendDNF5, "rpm", "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' lindm-agent"},
		{platform.BackendZypper, "rpm", "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' lindm-agent"},
		{platform.BackendPacman, "pacman", "pacman --query lindm-agent"},
	} {
		tool, query, err := consoleEnrollmentPackageQuery(test.backend)
		if err != nil || tool != test.tool || query != test.query {
			t.Fatalf("%s: wrong native database: %q %q %v", test.backend, tool, query, err)
		}
	}
	if _, _, err := consoleEnrollmentPackageQuery(platform.BackendNone); err == nil {
		t.Fatal("unregistered backend inherited a package database")
	}
}
