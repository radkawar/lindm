// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceprovider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// destWalkFlags opens a directory component anchored at the pinned destination
// root. O_NOFOLLOW refuses a substituted symlink instead of following it.
const destWalkFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// destWriter pins the caller-provided destination root and walks every later
// path from that descriptor. It does not retain per-directory fds for the
// capture; each operation closes its temporary fds before returning.
// Destination ancestry outside this root is a caller precondition and is not
// checked here.
type destWriter struct {
	rootFile *os.File
	rootFD   int
}

func (s *session) attachDest(destination *os.Root) error {
	// Pin the os.Root. Later creates, links, and labels are descriptor-relative
	// from rootFD; they do not os.Open absolute host paths.
	file, err := destination.Open(".")
	if err != nil {
		return mapDestLimit(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		_ = file.Close()
		return err
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 {
		_ = file.Close()
		return fmt.Errorf("%w: snapshot destination must be an empty root-owned mode 0700 directory", ErrUnsupported)
	}
	empty, err := dirEmpty(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		return err
	}
	if !empty {
		_ = file.Close()
		return fmt.Errorf("%w: snapshot destination is not empty", ErrConflict)
	}
	s.dest = &destWriter{
		rootFile: file,
		rootFD:   int(file.Fd()),
	}
	s.destDev = st.Dev
	s.destIno = st.Ino
	s.hasDest = true
	return nil
}

func dirEmpty(fd int) (bool, error) {
	buf := make([]byte, 4096)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err != nil {
			return false, mapDestLimit(err)
		}
		if n == 0 {
			return true, nil
		}
		// A malformed record is a failure, not an empty directory. unix.ParseDirent
		// reports an invalid reclen as a fully consumed buffer with count 0.
		_, saw, err := parseSnapshotDirents(buf[:n], nil, false, nil)
		if err != nil {
			return false, err
		}
		if saw {
			return false, nil
		}
	}
}

func (d *destWriter) close() {
	if d.rootFile != nil {
		_ = d.rootFile.Close()
		d.rootFile = nil
	}
	d.rootFD = -1
}

func (d *destWriter) ensureDir(canonical string) error {
	if err := validateDestPath(canonical); err != nil {
		return err
	}
	parent, name, err := splitFinal(canonical)
	if err != nil {
		return err
	}
	parentFD, err := d.openDir(parent)
	if err != nil {
		return destMissing(err, "snapshot destination parent missing for", canonical)
	}
	defer func() { _ = unix.Close(parentFD) }()
	if err := unix.Mkdirat(parentFD, name, 0700); err != nil && !os.IsExist(err) {
		return mapDestLimit(err)
	}
	fd, err := unix.Openat(parentFD, name, destWalkFlags, 0)
	if err != nil {
		return classifyDestWalkErr(err, canonical)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchmod(fd, 0700); err != nil {
		return err
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	return nil
}

func (d *destWriter) createExclusive(canonical string, mode uint32) (*os.File, error) {
	if err := validateDestPath(canonical); err != nil {
		return nil, err
	}
	parent, name, err := splitFinal(canonical)
	if err != nil {
		return nil, err
	}
	parentFD, err := d.openDir(parent)
	if err != nil {
		return nil, destMissing(err, "snapshot destination parent missing for", canonical)
	}
	defer func() { _ = unix.Close(parentFD) }()
	fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, classifyDestWalkErr(err, canonical)
	}
	return os.NewFile(uintptr(fd), canonical), nil
}

func (d *destWriter) link(oldCanonical, newCanonical string) error {
	if err := validateDestPath(oldCanonical); err != nil {
		return err
	}
	if err := validateDestPath(newCanonical); err != nil {
		return err
	}
	oldParent, oldName, err := splitFinal(oldCanonical)
	if err != nil {
		return err
	}
	newParent, newName, err := splitFinal(newCanonical)
	if err != nil {
		return err
	}
	oldFD, err := d.openDir(oldParent)
	if err != nil {
		return destMissing(err, "snapshot hardlink source missing for", oldCanonical)
	}
	defer func() { _ = unix.Close(oldFD) }()
	newFD, err := d.openDir(newParent)
	if err != nil {
		return destMissing(err, "snapshot hardlink parent missing for", newCanonical)
	}
	defer func() { _ = unix.Close(newFD) }()
	if err := unix.Linkat(oldFD, oldName, newFD, newName, 0); err != nil {
		return classifyDestWalkErr(err, newCanonical)
	}
	return nil
}

// setDirLabel applies a directory SELinux label by re-walking path from the
// pinned root. class is a snapLabel* value; labels are unchanged unless class
// is snapLabelPresent, matching setSELinuxFD. The walk fd is closed before return.
func (d *destWriter) setDirLabel(path string, class byte, label []byte) error {
	// "/" is the caller-owned pin, not a projected directory. Callers skip it;
	// rewriting its label is not part of capture.
	if path == "/" {
		return nil
	}
	if err := validateDestPath(path); err != nil {
		return err
	}
	fd, err := d.openDir(path)
	if err != nil {
		return destMissing(err, "snapshot destination directory missing for", path)
	}
	defer func() { _ = unix.Close(fd) }()
	return setSELinuxFD(fd, class, label)
}

func (s *session) writeSymlinks() error {
	paths := make([]string, 0)
	for path, node := range s.nodes {
		if node.kind == kindSymlink {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	for _, path := range paths {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if err := s.plantSymlink(path, s.nodes[path]); err != nil {
			return err
		}
	}
	return s.ctx.Err()
}

func (s *session) plantSymlink(path string, node *snapNode) error {
	if err := validateDestPath(path); err != nil {
		return err
	}
	parent, name, err := splitFinal(path)
	if err != nil {
		return err
	}
	parentFD, err := s.dest.openDir(parent)
	if err != nil {
		return destMissing(err, "snapshot symlink parent missing for", path)
	}
	defer func() { _ = unix.Close(parentFD) }()
	if err := unix.Symlinkat(node.target, parentFD, name); err != nil {
		return classifyDestWalkErr(err, path)
	}
	if err := unix.Fchownat(parentFD, name, 0, 0, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	return setSELinuxName(parentFD, name, node.selClass, node.selinux)
}

// openDir walks canonical from the pinned root, closing each intermediate fd
// before opening the next. The caller closes the returned fd. "" is the root.
// ".." is rejected so openat cannot escape the pin. Peak use is two fds.
func (d *destWriter) openDir(canonical string) (int, error) {
	if err := validateDestPath(canonical); err != nil {
		return -1, err
	}
	fd, err := unix.FcntlInt(uintptr(d.rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, mapDestLimit(err)
	}
	if canonical == "" {
		return fd, nil
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()
	for i := 0; i < len(canonical); {
		j := i + 1
		for j < len(canonical) && canonical[j] != '/' {
			j++
		}
		next, oerr := unix.Openat(fd, canonical[i+1:j], destWalkFlags, 0)
		if oerr != nil {
			return -1, classifyDestWalkErr(oerr, canonical)
		}
		_ = unix.Close(fd)
		fd = next
		i = j
	}
	owned = false
	return fd, nil
}

func validateDestPath(canonical string) error {
	if canonical == "" {
		return nil
	}
	if len(canonical) > maxDefinitionPath || canonical[0] != '/' || strings.ContainsRune(canonical, '\x00') {
		return fmt.Errorf("%w: invalid snapshot destination path %q", ErrUnsupported, canonical)
	}
	depth := 0
	for i := 0; i < len(canonical); {
		if canonical[i] != '/' {
			return fmt.Errorf("%w: invalid snapshot destination path %q", ErrUnsupported, canonical)
		}
		j := i + 1
		for j < len(canonical) && canonical[j] != '/' {
			j++
		}
		if err := validDestComponent(canonical[i+1 : j]); err != nil {
			return err
		}
		depth++
		if depth > maxSnapshotDepth {
			return fmt.Errorf("%w: snapshot destination path exceeds depth", ErrUnsupported)
		}
		i = j
	}
	return nil
}

func validDestComponent(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("%w: invalid snapshot destination component %q", ErrUnsupported, name)
	}
	return nil
}

func destMissing(err error, what, path string) error {
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: %s %s", ErrConflict, what, path)
	}
	return err
}

func mapDestLimit(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) {
		return fmt.Errorf("%w: snapshot destination descriptor limit: %w", ErrUnsupported, err)
	}
	return err
}

func classifyDestWalkErr(err error, path string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) {
		return fmt.Errorf("%w: snapshot destination descriptor limit: %w", ErrUnsupported, err)
	}
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("%w: snapshot destination symlink refused for %s: %w", ErrConflict, path, err)
	}
	if errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("%w: snapshot destination component is not a directory for %s: %w", ErrConflict, path, err)
	}
	return err
}

func splitFinal(canonical string) (parent, name string, err error) {
	if canonical == "" || canonical == "/" || !strings.HasPrefix(canonical, "/") {
		return "", "", fmt.Errorf("%w: invalid snapshot destination path %q", ErrUnsupported, canonical)
	}
	i := strings.LastIndexByte(canonical, '/')
	name = canonical[i+1:]
	parent = canonical[:i]
	if err := validDestComponent(name); err != nil {
		return "", "", err
	}
	return parent, name, nil
}

func destFileMode(mode uint32) uint32 {
	if mode&0111 != 0 {
		return 0700
	}
	return 0600
}

func finishDestFile(file *os.File, mode uint32, labelClass byte, label []byte) error {
	if err := unix.Fchown(int(file.Fd()), 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(int(file.Fd()), mode); err != nil {
		return err
	}
	return setSELinuxFD(int(file.Fd()), labelClass, label)
}

func setSELinuxFD(fd int, class byte, value []byte) error {
	if class != snapLabelPresent {
		return nil
	}
	if err := unix.Fsetxattr(fd, selinuxAttr, value, 0); err != nil {
		return fmt.Errorf("%w: set SELinux label: %w", ErrUnsupported, err)
	}
	return nil
}

func setSELinuxName(parentFD int, name string, class byte, value []byte) error {
	if class != snapLabelPresent {
		return nil
	}
	if strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("%w: invalid snapshot component", ErrUnsupported)
	}
	// Lsetxattr has no dirfd form here. /proc/self/fd/<parent> is the already
	// pinned directory inode, not a host-path walk; the final component is not
	// followed. name was validated and contains no slash.
	proc := "/proc/self/fd/" + itoa(parentFD) + "/" + name
	if err := unix.Lsetxattr(proc, selinuxAttr, value, 0); err != nil {
		return fmt.Errorf("%w: set SELinux symlink label: %w", ErrUnsupported, err)
	}
	return nil
}

var (
	snapshotDirentReclenOff = unsafe.Offsetof(unix.Dirent{}.Reclen)
	snapshotDirentReclenSz  = unsafe.Sizeof(unix.Dirent{}.Reclen)
	snapshotDirentInoOff    = unsafe.Offsetof(unix.Dirent{}.Ino)
	snapshotDirentInoSz     = unsafe.Sizeof(unix.Dirent{}.Ino)
	snapshotDirentNameOff   = unsafe.Offsetof(unix.Dirent{}.Name)
	snapshotDot             = []byte(".")
	snapshotDotDot          = []byte("..")
)

// parseSnapshotDirents validates one getdents buffer. Every byte must belong to
// a complete record with a non-zero reclen and a NUL-terminated name. An invalid
// reclen is ErrConflict, including the case unix.ParseDirent reports as fully
// consumed. Inode 0, ".", and ".." are omitted. collect appends the other names;
// sawName is true when any such name exists even if collect is false. reserve,
// when supplied, admits each collected name before allocation. On error the
// returned names include every successful reservation so the caller can release
// them; no unsuccessful reservation is appended.
func parseSnapshotDirents(buf []byte, names []string, collect bool, reserve func(int) error) ([]string, bool, error) {
	if len(buf) == 0 {
		return names, false, nil
	}
	saw := false
	rest := buf
	for len(rest) > 0 {
		reclen, ok := direntUint(rest, snapshotDirentReclenOff, snapshotDirentReclenSz)
		if !ok || reclen == 0 || reclen < uint64(snapshotDirentNameOff)+1 || reclen > uint64(len(rest)) {
			return names, false, fmt.Errorf("%w: malformed snapshot directory entry", ErrConflict)
		}
		rec := rest[:reclen]
		rest = rest[reclen:]
		ino, ok := direntUint(rec, snapshotDirentInoOff, snapshotDirentInoSz)
		if !ok {
			return names, false, fmt.Errorf("%w: malformed snapshot directory entry", ErrConflict)
		}
		nameOff := int(snapshotDirentNameOff)
		nul := bytes.IndexByte(rec[nameOff:], 0)
		if nul <= 0 || nul > 255 || bytes.IndexByte(rec[nameOff:nameOff+nul], '/') >= 0 {
			return names, false, fmt.Errorf("%w: malformed snapshot directory entry", ErrConflict)
		}
		name := rec[nameOff : nameOff+nul]
		if ino == 0 || bytes.Equal(name, snapshotDot) || bytes.Equal(name, snapshotDotDot) {
			continue
		}
		saw = true
		if collect {
			if reserve != nil {
				if err := reserve(len(name)); err != nil {
					return names, false, err
				}
			}
			names = append(names, string(name))
		}
	}
	return names, saw, nil
}

func direntUint(buf []byte, off, size uintptr) (uint64, bool) {
	if size == 0 || off > uintptr(len(buf)) || size > uintptr(len(buf)-int(off)) {
		return 0, false
	}
	b := buf[off : off+size]
	switch size {
	case 1:
		return uint64(b[0]), true
	case 2:
		return uint64(binary.NativeEndian.Uint16(b)), true
	case 4:
		return uint64(binary.NativeEndian.Uint32(b)), true
	case 8:
		return binary.NativeEndian.Uint64(b), true
	default:
		return 0, false
	}
}
