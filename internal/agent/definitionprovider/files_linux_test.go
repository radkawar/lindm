// SPDX-License-Identifier: Apache-2.0

//go:build linux

package definitionprovider

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests exercise actual kernel directory/link custody, not host unit
// installation. They never write /etc/systemd or contact the system manager.
func protectedFixtureDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root required for native directory custody")
	}
	path, err := os.MkdirTemp("/run", "lindm-definition-custody-")
	if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EROFS) {
		t.Skipf("private runtime fixture unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return path
}
func TestDirectoryIdentityIgnoresOnlyOwnedChildChanges(t *testing.T) {
	path := protectedFixtureDirectory(t)
	fd, before, err := directory(path)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("filesystem lacks required birth-time evidence")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("public data"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, after, err := directory(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("child changes invalidated retained directory identity")
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	fd, after, err = directory(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("directory permission drift hidden")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if fd, _, err := directory(path); err == nil {
		_ = unix.Close(fd)
		t.Fatal("replaceable directory accepted")
	}
}
func TestDirectoryAndInstallLinkCustodyRejectSubstitution(t *testing.T) {
	root := protectedFixtureDirectory(t)
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if fd, _, err := directory(alias); err == nil {
		_ = unix.Close(fd)
		t.Fatal("directory symlink accepted")
	}
	path := filepath.Join(real, "example.timer")
	target := filepath.Join(root, "example.timer")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	first, err := captureLink(path, target)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("filesystem lacks required symlink birth time")
	}
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the old inode under an unrelated private fixture name, ensuring
	// replacement cannot accidentally receive that inode number from reuse.
	if err := os.Rename(path, path+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	second, err := captureLink(path, target)
	if err != nil {
		t.Fatal(err)
	}
	if first.GetInode() == second.GetInode() && bytes.Equal(first.GetAncestrySha256(), second.GetAncestrySha256()) {
		t.Fatal("same-target link replacement retained ownership identity")
	}
	if _, err := captureLink(path, target+".other"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unrelated link target accepted: %v", err)
	}
}
