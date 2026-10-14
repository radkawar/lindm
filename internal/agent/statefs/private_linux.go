// SPDX-License-Identifier: Apache-2.0

// Package statefs checks filesystem boundaries shared by the privileged identity
// journal and the separately owned, unprivileged observation spool.
package statefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

var ErrUnsafe = errors.New("unsafe agent state filesystem boundary")

// OpenDirectory returns a caller-owned descriptor for a current-UID 0700 directory
// whose ancestors cannot be replaced by another unprivileged UID. SQLite resolves
// proc-fd names to ordinary paths, so descriptor pinning alone is insufficient.
// This does not defend against this UID or root changing its own state.
func OpenDirectory(directory string) (int, error) {
	return openDirectory(directory, uint32(os.Geteuid()))
}

// OpenDiagnosticDirectory returns a caller-owned descriptor for a 0700 directory
// with the specified owner, for read-only diagnostic access. Only the final
// directory may have a different owner; the ancestor checks match OpenDirectory.
// Do not use this boundary for mutable state or SQLite.
func OpenDiagnosticDirectory(directory string, owner uint32) (int, error) {
	return openDirectory(directory, owner)
}

func walkDirectory(directory string) (int, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		if err := checkAncestor(fd); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// OpenTemporaryParent checks the directory and its ancestry before a caller
// creates private temporary children. Root/caller ownership and trusted sticky
// shared parents are accepted; symlinks and replaceable ancestry are not.
// The caller owns the descriptor. The same UID, root and filesystem are trusted.
func OpenTemporaryParent(directory string) (int, error) {
	fd, err := walkDirectory(directory)
	if err != nil {
		return -1, err
	}
	if err := checkAncestor(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openDirectory(directory string, owner uint32) (int, error) {
	fd, err := walkDirectory(directory)
	if err != nil {
		return -1, err
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if info.Uid != owner || info.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return -1, ErrUnsafe
	}
	return fd, nil
}

func checkAncestor(fd int) error {
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return err
	}
	if custody.TrustedDirectory(&info) {
		return nil
	}
	// Sticky trusted parents (notably /tmp) cannot rename an entry owned
	// by this UID/root. Diagnostics alone may accept another final owner.
	if info.Uid != 0 && info.Uid != uint32(os.Geteuid()) || info.Mode&0022 != 0 && info.Mode&unix.S_ISVTX == 0 {
		return ErrUnsafe
	}
	return nil
}

// CheckFile rejects symlinks, special files, hardlinks, other owners and modes
// other than 0600. The caller must retain the checked private directory boundary.
func CheckFile(directoryFD int, name string) (bool, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return false, ErrUnsafe
	}
	var stat unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return false, ErrUnsafe
	}
	return true, nil
}
