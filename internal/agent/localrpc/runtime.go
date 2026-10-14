// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localrpc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

var errRuntimeUnsafe = errors.New("unsafe executor runtime directory")

// openRuntimeDirectory validates a traversable runtime directory. It must not
// use statefs.OpenDirectory: that API requires a private 0700 directory, and
// the network account has to traverse this one.
func openRuntimeDirectory(directory string) (*os.File, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(absolute), "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return nil, errRuntimeUnsafe
		}
		var info unix.Stat_t
		if err := unix.Fstat(fd, &info); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		if !custody.TrustedDirectory(&info) && (info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != 0 && info.Uid != uint32(os.Geteuid()) || info.Mode&0022 != 0 && info.Mode&unix.S_ISVTX == 0) {
			_ = unix.Close(fd)
			return nil, errRuntimeUnsafe
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if info.Uid != uint32(os.Geteuid()) || (!custody.TrustedDirectory(&info) && (info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&0022 != 0)) {
		_ = unix.Close(fd)
		return nil, errRuntimeUnsafe
	}
	return os.NewFile(uintptr(fd), absolute), nil
}

// socketAccess is the pathname policy for one listener when the process runs
// as root. Non-root processes (tests) keep their own group and need no traversal.
type socketAccess struct {
	mode uint32
	gid  uint32
	// traversable reports whether the retained directory lets intended peers reach the socket.
	traversable func(unix.Stat_t) bool
}

// executorAccess limits the executor socket to root and the network group.
func executorAccess(networkGID uint32) socketAccess {
	return socketAccess{mode: 0660, gid: networkGID, traversable: func(info unix.Stat_t) bool {
		perm := info.Mode & 0777
		return perm&0001 != 0 || perm&0010 != 0 && info.Gid == networkGID
	}}
}

// sessionAccess lets every local user connect; SO_PEERCRED and logind decide.
func sessionAccess() socketAccess {
	return socketAccess{mode: 0666, gid: 0, traversable: func(info unix.Stat_t) bool {
		return info.Mode&0001 != 0
	}}
}

type ownedSocket struct {
	listener net.Listener
	dir      *os.File
	name     string
	dev      uint64
	ino      uint64
}

func listenSocket(dir *os.File, name string, access socketAccess) (_ *ownedSocket, resultErr error) {
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, "/\x00") {
		return nil, errRuntimeUnsafe
	}
	// AF_UNIX has no bindat. Resolve the socket through the retained, validated
	// directory rather than walking its original pathname again.
	directory := "/proc/self/fd/" + strconv.Itoa(int(dir.Fd()))
	var info unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &info); err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 && !access.traversable(info) {
		return nil, errors.New("runtime directory is not traversable by the intended peers")
	}
	if err := prepareSocket(int(dir.Fd()), name, directory); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(directory, name)
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, err
	}
	// The socket descriptor's sockfs inode is NOT its filesystem pathname
	// inode. Pin the latter before changing or recording pathname metadata.
	namedFD, err := unix.Openat(int(dir.Fd()), name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(namedFD) }()
	var named unix.Stat_t
	if err := unix.Fstat(namedFD, &named); err != nil {
		return nil, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFSOCK || named.Uid != uint32(os.Geteuid()) {
		return nil, errRuntimeUnsafe
	}
	owned := &ownedSocket{dir: dir, name: name, dev: named.Dev, ino: named.Ino}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, owned.unlink())
		}
	}()
	mode, gid := uint32(0600), named.Gid
	if os.Geteuid() == 0 {
		mode, gid = access.mode, access.gid
		if err := unix.Fchownat(namedFD, "", 0, int(gid), unix.AT_EMPTY_PATH); err != nil {
			return nil, err
		}
	}
	// Resolve only the pinned O_PATH filesystem inode, not a replaceable name
	// or the AF_UNIX descriptor's unrelated sockfs inode. This also avoids
	// requiring fchmodat2/AT_EMPTY_PATH support on older supported kernels.
	if err := unix.Chmod("/proc/self/fd/"+strconv.Itoa(namedFD), mode); err != nil {
		return nil, err
	}
	var secured unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &secured, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if secured.Dev != named.Dev || secured.Ino != named.Ino || secured.Mode&unix.S_IFMT != unix.S_IFSOCK || secured.Mode&07777 != mode || secured.Uid != uint32(os.Geteuid()) || secured.Gid != gid {
		return nil, errRuntimeUnsafe
	}
	if err := unix.Listen(fd, 64); err != nil {
		return nil, err
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	// Only our directory-relative identity check may unlink the pathname.
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return nil, errors.Join(errors.New("executor listener is not a Unix socket"), listener.Close())
	}
	unixListener.SetUnlinkOnClose(false)
	owned.listener = listener
	return owned, nil
}

func prepareSocket(dirFD int, name, directory string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("runtime socket path is occupied")
	}
	conn, dialErr := net.DialTimeout("unix", filepath.Join(directory, name), 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("executor socket is already accepting connections")
	}
	return unix.Unlinkat(dirFD, name, 0)
}

func (s *ownedSocket) unlink() error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(s.dir.Fd()), s.name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Dev != s.dev || stat.Ino != s.ino {
		return nil
	}
	return unix.Unlinkat(int(s.dir.Fd()), s.name, 0)
}

func (s *ownedSocket) close() error {
	return errors.Join(s.listener.Close(), s.unlink())
}
