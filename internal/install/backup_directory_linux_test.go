// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrepareBackupDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected installation directories require root")
	}
	if root := os.Getenv("LINDM_BACKUP_DIRECTORY_TEST_ROOT"); root != "" {
		if err := syscall.Chroot(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		syscall.Umask(0022)
		testPreparedBackupDirectory(t, os.Getenv("LINDM_BACKUP_DIRECTORY_TEST_CASE"))
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "existing", "private", "writable", "linked", "file", "unsafe_var"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "var"), 0755); err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(root, "var", "backups")
			switch name {
			case "existing", "private", "writable":
				mode := os.FileMode(0755)
				switch name {
				case "private":
					mode = 0700
				case "writable":
					mode = 0777
				}
				if err := os.Mkdir(backup, mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(backup, mode); err != nil {
					t.Fatal(err)
				}
			case "linked":
				if err := os.Mkdir(filepath.Join(root, "other"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/other", backup); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(backup, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe_var":
				if err := os.Chmod(filepath.Join(root, "var"), 0777); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestPrepareBackupDirectory$")
			cmd.Env = append(os.Environ(), "LINDM_BACKUP_DIRECTORY_TEST_ROOT="+root, "LINDM_BACKUP_DIRECTORY_TEST_CASE="+name)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated backup directory %s: %v\n%s", name, err, output)
			}
		})
	}
}

func testPreparedBackupDirectory(t *testing.T, name string) {
	t.Helper()
	err := prepareBackupDirectory()
	wantMode, good := map[string]os.FileMode{"missing": 0755, "existing": 0755, "private": 0700}[name]
	if !good {
		if err == nil {
			t.Fatal("unsafe backup parent was accepted")
		}
		if name == "linked" {
			if _, err := os.Lstat("/other/lindm"); !os.IsNotExist(err) {
				t.Fatal("linked backup parent was modified")
			}
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{"/var/backups": wantMode, "/var/backups/lindm": 0700} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != mode || stat.Uid != 0 {
			t.Fatalf("unprotected or widened directory %s", path)
		}
	}
}
