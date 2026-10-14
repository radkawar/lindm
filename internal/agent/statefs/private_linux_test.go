// SPDX-License-Identifier: Apache-2.0

package statefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDiagnosticDirectoryOwnerIsFinalOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create directories owned by another UID")
	}
	const networkUID = 65534
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	directory := filepath.Join(parent, "spool")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, networkUID, -1); err != nil {
		t.Fatal(err)
	}
	fd, err := OpenDiagnosticDirectory(directory, networkUID)
	if err != nil {
		t.Fatalf("read-only diagnostic directory: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		t.Fatal(err)
	}
	if info.Uid != networkUID || info.Mode&07777 != 0700 || info.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatalf("unexpected diagnostic descriptor: %+v", info)
	}
	if fd, err := OpenDirectory(directory); !errors.Is(err, ErrUnsafe) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("mutable state accepted another owner's final directory: %v", err)
	}
	if err := os.Chown(parent, networkUID, -1); err != nil {
		t.Fatal(err)
	}
	if fd, err := OpenDiagnosticDirectory(directory, networkUID); !errors.Is(err, ErrUnsafe) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("diagnostics trusted the final owner's ancestor: %v", err)
	}
	if err := os.Chown(directory, 0, -1); err != nil {
		t.Fatal(err)
	}
	if fd, err := OpenDirectory(directory); !errors.Is(err, ErrUnsafe) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("mutable state accepted an untrusted ancestor: %v", err)
	}
}

func TestTemporaryParentOwnershipBoundary(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   os.FileMode
		unsafe bool
	}{
		{name: "protected", mode: 0755},
		{name: "sticky-shared", mode: os.ModeSticky | 0777},
		{name: "replaceable-shared", mode: 0777, unsafe: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, test.mode); err != nil {
				t.Fatal(err)
			}
			fd, err := OpenTemporaryParent(parent)
			if fd >= 0 {
				defer func() { _ = unix.Close(fd) }()
			}
			if test.unsafe {
				if !errors.Is(err, ErrUnsafe) || fd >= 0 {
					t.Fatalf("replaceable parent was admitted: fd=%d err=%v", fd, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var expected, actual unix.Stat_t
			if err := unix.Stat(parent, &expected); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fstat(fd, &actual); err != nil {
				t.Fatal(err)
			}
			if expected.Dev != actual.Dev || expected.Ino != actual.Ino || actual.Mode&unix.S_IFMT != unix.S_IFDIR {
				t.Fatal("temporary parent descriptor does not identify the checked directory")
			}
		})
	}
}

func TestDirectoryRejectsSymlinkComponents(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(map[bool]string{false: "ancestor", true: "final"}[final], func(t *testing.T) {
			root := t.TempDir()
			real := filepath.Join(root, "real")
			if err := os.MkdirAll(filepath.Join(real, "state"), 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			target := real
			if final {
				target = filepath.Join(real, "state")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			path := link
			if !final {
				path = filepath.Join(link, "state")
			}
			fd, err := OpenDirectory(path)
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			if err == nil {
				t.Fatal("accepted symlink directory component")
			}
		})
	}
}
