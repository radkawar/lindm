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
