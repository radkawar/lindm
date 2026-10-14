// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Lab inputs are custodied by the invoking operator rather than root-only
// product custody. Match custody.OpenRoot's descriptor walk, allowing only root
// or this operator to own any component; no group/world-writable ancestry.
func openDeployAuditProtected(path string, flags int) (_ *os.File, _ unix.Stat_t, err error) {
	var stat unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, stat, errors.New("historical trust input needs a clean absolute path")
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
	if !deployAuditProtectedStat(stat) {
		return nil, stat, errors.New("unprotected historical trust input ancestry")
	}
	parts := strings.Split(path[1:], "/")
	for index, part := range parts {
		mode := unix.O_PATH | unix.O_DIRECTORY
		if index == len(parts)-1 {
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
		if !deployAuditProtectedStat(stat) {
			return nil, stat, errors.New("unprotected historical trust input component")
		}
	}
	return os.NewFile(uintptr(fd), path), stat, nil
}

func deployAuditProtectedStat(stat unix.Stat_t) bool {
	return stat.Mode&0022 == 0 && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) && stat.Mode&unix.S_IFMT != unix.S_IFLNK
}

func deployAuditDescriptorPath(file *os.File) string {
	return fmt.Sprintf("/proc/self/fd/%d", file.Fd())
}
