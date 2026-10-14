// SPDX-License-Identifier: Apache-2.0

//go:build linux

package accountprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A shadow tool that rewrites /etc/passwd under --prefix replaces the file
// (and its backup) with new inodes that carry no label; both get the label the
// database had before the command, and an untouched database keeps its own.
func TestNativeCommandsKeepDatabaseLabels(t *testing.T) {
	const attribute = "user.lindm-test-label"
	etc := t.TempDir()
	passwdLabel, shadowLabel := []byte("system_u:object_r:passwd_file_t:s0\x00"), []byte("system_u:object_r:shadow_t:s0\x00")
	for name, label := range map[string][]byte{"passwd": passwdLabel, "shadow": shadowLabel, "group": passwdLabel} {
		path := filepath.Join(etc, name)
		if err := os.WriteFile(path, []byte(name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Lsetxattr(path, attribute, label, 0); errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skipf("user xattrs unavailable: %v", err)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	rewrite := func(context.Context, []byte, string, ...string) ([]byte, error) {
		for _, name := range []string{"passwd", "passwd-"} {
			path := filepath.Join(etc, name)
			if err := os.WriteFile(path+".cio", []byte("rewritten\n"), 0600); err != nil {
				return nil, err
			}
			if err := os.Rename(path+".cio", path); err != nil {
				return nil, err
			}
		}
		return nil, errors.New("native failure after the rewrite")
	}
	if _, err := labeledRun(rewrite, etc, attribute)(t.Context(), nil, "/usr/sbin/useradd"); err == nil {
		t.Fatal("native failure was hidden by label restoration")
	}
	for name, want := range map[string][]byte{"passwd": passwdLabel, "passwd-": passwdLabel, "shadow": shadowLabel, "group": passwdLabel} {
		got, err := fileLabel(filepath.Join(etc, name), attribute)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s label = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := fileLabel(filepath.Join(etc, "gshadow"), attribute); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent gshadow: %v", err)
	}
}
