// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrUnsafe reports a path whose traversal or leaf fails the custody policy.
var ErrUnsafe = errors.New("custody: unsafe_path")

// RootProtected reports whether an object can be replaced or modified only by
// root: owned by UID 0 with neither group nor other write permission. It is the
// strict native-provider rule for every walked directory and the opened leaf;
// unlike TrustedDirectory it admits no group-zero exception.
func RootProtected(stat *unix.Stat_t) bool {
	return stat.Uid == 0 && stat.Mode&0022 == 0
}

// OpenRoot opens a clean absolute path one component at a time from /, each
// with O_NOFOLLOW, so no symlink is followed anywhere. Every directory,
// including /, and the leaf itself must be RootProtected. flags select the leaf
// access (O_RDONLY, O_PATH, O_DIRECTORY); O_NOFOLLOW, O_CLOEXEC and O_NONBLOCK
// are always added. The leaf's type is the caller's to check via the stat.
// systemd RestrictSUIDSGID= fails openat2 with ENOSYS, so the walk uses openat.
func OpenRoot(path string, flags int) (_ *os.File, _ unix.Stat_t, err error) {
	var stat unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, stat, ErrUnsafe
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	defer func() {
		if err != nil && fd >= 0 {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, stat, err
	}
	if !RootProtected(&stat) {
		return nil, stat, fmt.Errorf("%w: replaceable ancestry of %s", ErrUnsafe, path)
	}
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		mode := unix.O_PATH | unix.O_DIRECTORY
		if i == len(parts)-1 {
			mode = flags
		}
		next, openErr := unix.Openat(fd, part, mode|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		closeErr := unix.Close(fd)
		fd = next
		if openErr != nil {
			fd = -1
			return nil, stat, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return nil, stat, closeErr
		}
		if err = unix.Fstat(fd, &stat); err != nil {
			return nil, stat, err
		}
		if !RootProtected(&stat) {
			return nil, stat, fmt.Errorf("%w: replaceable ancestry of %s", ErrUnsafe, path)
		}
	}
	return os.NewFile(uintptr(fd), path), stat, nil
}

// ReadRoot reads a bounded regular file opened by OpenRoot. Unless hardlinks is
// set the file must have exactly one link; a root-owned, non-writable vendor
// file that a distribution build hardlinked is safe only where a caller says so.
// The file must keep its identity and timestamps while it is read.
func ReadRoot(path string, limit int64, hardlinks bool) (data []byte, err error) {
	file, before, err := OpenRoot(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if before.Mode&unix.S_IFMT != unix.S_IFREG || (!hardlinks && before.Nlink != 1) || before.Size > limit {
		return nil, fmt.Errorf("%w: unprotected native file %s", ErrUnsafe, path)
	}
	return readStable(file, before, limit, path)
}

// ReadResolvedRoot reads a bounded root-owned vendor file through
// OpenResolvedRoot's pinned symlink traversal, for files a distribution ships
// as a symlink chain (Pop!_OS: /usr/lib/os-release -> /etc/pop-os/os-release).
// The file must keep its identity and timestamps while it is read.
func ReadResolvedRoot(path string, limit int64) (data []byte, err error) {
	file, _, before, err := OpenResolvedRoot(path, limit, unix.PathMax, 40)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return readStable(file, before, limit, path)
}

func readStable(file *os.File, before unix.Stat_t, limit int64, path string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &after); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit || before.Dev != after.Dev || before.Ino != after.Ino || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, fmt.Errorf("%w: native file changed or exceeds bound: %s", ErrUnsafe, path)
	}
	return data, nil
}

// PrivateDirectory requires a root-protected ancestry (OpenRoot) and a leaf
// directory owned by the effective user with no group or other permissions.
func PrivateDirectory(path string) error {
	file, stat, err := OpenRoot(path, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return fmt.Errorf("%w: private directory required: %s", ErrUnsafe, path)
	}
	return nil
}

// Owned checks only the leaf, for unprivileged tools whose ancestry is a user's
// home or checkout: it must not be a symlink, must be a directory or regular
// file as requested, owned by the effective user, with no group or other
// permissions. It is not a substitute for OpenRoot on privileged paths.
func Owned(path string, directory bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return stat, err
	}
	err = unix.Fstat(fd, &stat)
	if closeErr := unix.Close(fd); err != nil || closeErr != nil {
		return stat, errors.Join(err, closeErr)
	}
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	if stat.Mode&unix.S_IFMT != kind || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return stat, fmt.Errorf("%w: %s must be a non-symlink owned by the current user with no group/other permissions", ErrUnsafe, path)
	}
	return stat, nil
}
