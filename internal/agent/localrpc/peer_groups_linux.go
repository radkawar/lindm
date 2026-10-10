package localrpc

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rejectRootPeerGroup checks the credentials snapshotted by the kernel when the
// Unix connection was established, not /proc/<pid> (which can race PID reuse).
// SO_PEERGROUPS is available on every supported Linux kernel. Fail closed if the
// kernel cannot supply a complete group list, rather than trusting account data
// that may differ from a process's actual credentials.
func rejectRootPeerGroup(fd int) error {
	var initial [32]uint32
	groups := initial[:]
	n, err := readPeerGroups(fd, groups)
	if errors.Is(err, unix.ERANGE) {
		// Linux NGROUPS_MAX is 65536. Allocate only for an unusually large
		// actual peer group list, bounded by the kernel's maximum.
		if n == 0 || n%4 != 0 || n > 65536*4 {
			return errors.New("invalid peer group count")
		}
		groups = make([]uint32, n/4)
		n, err = readPeerGroups(fd, groups)
	}
	if err != nil {
		return err
	}
	if n%4 != 0 || n/4 > uint32(len(groups)) {
		return errors.New("invalid peer group count")
	}
	for _, gid := range groups[:n/4] {
		if gid == 0 {
			return errors.New("unprivileged peer belongs to group zero")
		}
	}
	return nil
}

func readPeerGroups(fd int, groups []uint32) (uint32, error) {
	n := uint32(len(groups) * 4)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
		uintptr(unsafe.Pointer(&groups[0])), uintptr(unsafe.Pointer(&n)), 0)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}
