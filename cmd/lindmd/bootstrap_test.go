// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func setupOutputDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// TempDir creates its numbered child with 0777 before applying the umask.
	// A developer's group-writable umask must not define this protected fixture.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSetupOutputIsPrivateAndCreateOnly(t *testing.T) {
	path := filepath.Join(setupOutputDirectory(t), "setup-code")
	file, err := createSetupOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file permissions: %v %v", info, err)
	}
	if _, err := createSetupOutput(path); err == nil {
		t.Fatal("existing secret was overwritten")
	}
}

func TestSetupOutputRejectsSymlinkAndWritableAncestry(t *testing.T) {
	dir := setupOutputDirectory(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := createSetupOutput(link); err == nil {
		t.Fatal("symlink target was admitted")
	}
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := createSetupOutput(filepath.Join(unsafe, "code")); err == nil {
		t.Fatal("replaceable output directory was admitted")
	}
}
