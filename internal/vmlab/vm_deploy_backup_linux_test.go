// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestDeployBackupCreatesPrivateDirectoryBeforeCommand(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(strconv.FormatBool(fenced), func(t *testing.T) {
			private := t.TempDir()
			directory := filepath.Join(private, "backup 'with spaces'")
			arguments := filepath.Join(private, "arguments")
			binary := filepath.Join(private, "lindmd")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\nset -eu\nprintf '%s\\n' \"$@\" > \"$LINDM_TEST_BACKUP_ARGUMENTS\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			run := func() error {
				command := exec.Command("sh", "-eu", "-c", deployBackupCommand(directory, fenced))
				command.Env = append(os.Environ(), "PATH="+private+":"+os.Getenv("PATH"), "LINDM_TEST_BACKUP_ARGUMENTS="+arguments)
				return command.Run()
			}
			if err := run(); err != nil {
				t.Fatalf("new private backup directory was not created before the command: %v", err)
			}
			info, err := os.Stat(directory)
			if err != nil {
				t.Fatal(err)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
				t.Fatal("backup output directory does not belong privately to the command's effective user")
			}
			want := []string{"backup", "-config", "/etc/lindm/server.json", "-output-dir", directory, "-recipient-file", "/root/lindm-deploy-input/backup-recipient"}
			if fenced {
				want = append(want, "-confirm-fenced")
			}
			got, err := os.ReadFile(arguments)
			if err != nil || string(got) != strings.Join(want, "\n")+"\n" {
				t.Fatalf("backup arguments were changed or the output directory was not shell-quoted: %q (%v)", got, err)
			}
			if err := os.Remove(arguments); err != nil {
				t.Fatal(err)
			}
			if err := run(); err == nil {
				t.Fatal("existing output directory was silently reused")
			}
			if _, err := os.Stat(arguments); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("backup command ran despite directory creation failing")
			}
			if err := os.Remove(directory); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(private, directory); err != nil {
				t.Fatal(err)
			}
			if err := run(); err == nil {
				t.Fatal("symlink output directory was accepted")
			}
			if _, err := os.Stat(arguments); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("backup command ran despite a symlink output directory")
			}
		})
	}
}
