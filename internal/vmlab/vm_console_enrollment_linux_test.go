//go:build linux

package vmlab

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
