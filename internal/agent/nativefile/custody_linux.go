//go:build linux

// Package nativefile supplies descriptor-held atomic public-data file operations
// to closed native providers. It is not an authorization API: each caller derives
// its native paths and enforces its own protected configuration and authority.
package nativefile

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	pathcustody "lindm/internal/custody"
)

// These bounds cap native reads as well as the corresponding protobuf fields.
const maxContent = 32768
const maxXattrs = 32768

var (
	ErrUnsafePath  = errors.New("nativefile: unsafe_path")
	ErrConflict    = errors.New("nativefile: precondition_conflict")
	ErrUnsupported = errors.New("nativefile: unsupported_metadata_or_filesystem")
)

// custody retains every directory descriptor, including /, until observation or
// mutation finishes. Reopening the chain proves it still names the same objects.
// There is deliberately no openat2 fallback on older kernels.
type custody struct {
	path     string
	name     string
	dirs     []int
	stats    []unix.Stat_t
	file     *os.File
	stat     unix.Stat_t
	ancestry []byte
	leased   bool
	readOnly bool
}

func openCustody(path string, readOnly bool) (_ *custody, err error) {
	c, err := openAncestors(path, readOnly)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	fd, err := unix.Openat(c.parent(), c.name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	c.file = os.NewFile(uintptr(fd), path)
	if err = unix.Fstat(fd, &c.stat); err != nil {
		return nil, err
	}
	if c.stat.Mode&unix.S_IFMT != unix.S_IFREG || c.stat.Mode&07000 != 0 || c.stat.Size < 0 || c.stat.Size > maxContent || c.stat.Dev != c.stats[len(c.stats)-1].Dev {
		return nil, ErrUnsafePath
	}
	// A read-only dependency may be hardlinked (for example, a packaged crypto
	// policy), but cannot be writable by an unprivileged owner or group.
	// Every mutation-capable capture still requires exclusive link ownership.
	if (!readOnly && c.stat.Nlink != 1) || (readOnly && !pathcustody.RootProtected(&c.stat)) {
		return nil, ErrUnsafePath
	}
	// Replacing immutable, append-only, verity, encrypted or other special files
	// would discard semantics. Extents (ext4) and compression or copy-on-write
	// state (btrfs) are filesystem allocation details only.
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return nil, fmt.Errorf("read native file flags: %w", err)
	}
	if flags&^storageOnlyFlags != 0 {
		return nil, fmt.Errorf("%w: native file flags %#x", ErrUnsupported, flags)
	}
	return c, nil
}

// openAncestors retains custody of every root-protected directory above path
// without opening path itself.
func openAncestors(path string, readOnly bool) (_ *custody, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrUnsafePath
	}
	c := &custody{path: path, name: filepath.Base(path), readOnly: readOnly}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	c.dirs = append(c.dirs, fd)
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for i := 0; ; i++ {
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || !pathcustody.RootProtected(&st) {
			return nil, ErrUnsafePath
		}
		c.stats = append(c.stats, st)
		if i == len(parts) || parts[i] == "" {
			break
		}
		// systemd RestrictSUIDSGID= fails openat2 with ENOSYS. A single clean
		// component opened with O_NOFOLLOW cannot escape or follow a link.
		fd, err = unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			// An absent approved parent is a reported precondition, not an
			// internal failure retried forever; the file is never created there.
			return nil, fmt.Errorf("%w: protected ancestor %s absent: %w", ErrConflict, filepath.Join(append([]string{"/"}, parts[:i+1]...)...), err)
		}
		if err != nil {
			return nil, fmt.Errorf("open protected ancestor: %w", err)
		}
		c.dirs = append(c.dirs, fd)
	}
	h := sha256.New()
	for _, st := range c.stats {
		_, _ = fmt.Fprintf(h, "%d:%d:%d:%d:%d;", st.Dev, st.Ino, st.Uid, st.Gid, st.Mode)
	}
	c.ancestry = h.Sum(nil)
	return c, nil
}

// storageOnlyFlags are FS_COMPR_FL, FS_NOCOMP_FL, FS_EXTENT_FL and FS_NOCOW_FL.
const storageOnlyFlags = 0x4 | 0x400 | 0x80000 | 0x800000

func (c *custody) parent() int { return c.dirs[len(c.dirs)-1] }
func (c *custody) close() error {
	var result error
	if c.file != nil {
		result = c.file.Close()
		c.file = nil
	}
	for i := len(c.dirs) - 1; i >= 0; i-- {
		result = errors.Join(result, unix.Close(c.dirs[i]))
	}
	c.dirs = nil
	return result
}
func (c *custody) unchanged() (err error) {
	fresh, err := openCustody(c.path, c.readOnly)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fresh.close()) }()
	if !bytes.Equal(c.ancestry, fresh.ancestry) || (c.file == nil) != (fresh.file == nil) {
		return ErrConflict
	}
	if c.file != nil && !sameStat(c.stat, fresh.stat) {
		return ErrConflict
	}
	if c.leased {
		lease, err := unix.FcntlInt(c.file.Fd(), unix.F_GETLEASE, 0)
		if err != nil || lease != unix.F_RDLCK {
			return errors.Join(ErrConflict, err)
		}
	}
	return nil
}
func sameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Nlink == b.Nlink && a.Ctim == b.Ctim && a.Mtim == b.Mtim
}

// A read lease excludes concurrent writable opens and fails if a writer already
// holds the inode. Clear the async owner: a lease break is detected with GETLEASE
// rather than delivering process-global SIGIO. Helpers must have CAP_LEASE.
func (c *custody) lease() error {
	if c.file == nil {
		return nil
	}
	if _, err := unix.FcntlInt(c.file.Fd(), unix.F_SETOWN, 0); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(c.file.Fd(), unix.F_SETLEASE, unix.F_RDLCK); err != nil {
		return fmt.Errorf("%w: file has an active writer or lacks lease support: %w", ErrConflict, err)
	}
	c.leased = true
	return nil
}

func (c *custody) snapshot(template *resourcev1.ResourceObservation) (*agentv1.ResourceOwnershipSnapshot, error) {
	o := &resourcev1.ManagedFileObservation{Path: c.path, Exists: c.file != nil, AncestrySha256: bytes.Clone(c.ancestry)}
	s := &agentv1.ResourceOwnershipSnapshot{Observation: proto.CloneOf(template)}
	s.Observation.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: o}
	if c.file != nil {
		fd := int(c.file.Fd())
		data, err := io.ReadAll(io.NewSectionReader(c.file, 0, maxContent+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxContent {
			return nil, ErrUnsafePath
		}
		if data == nil {
			data = []byte{}
		}
		s.ManagedFileContent = data
		xattrs, err := readXattrs(fd)
		if err != nil {
			return nil, err
		}
		s.ManagedFileXattrs = xattrs
		digest := sha256.Sum256(data)
		o.File = &resourcev1.FileIdentity{Path: c.path, Device: c.stat.Dev, Inode: c.stat.Ino, Uid: c.stat.Uid, Gid: c.stat.Gid, Mode: c.stat.Mode & 0777, Sha256: digest[:]}
		var stx unix.Statx_t
		if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME|unix.STATX_INO, &stx); err != nil {
			return nil, err
		}
		if stx.Mask&unix.STATX_BTIME == 0 {
			return nil, fmt.Errorf("%w: inode birth-time evidence unavailable", ErrUnsupported)
		}
		native := sha256.Sum256(fmt.Appendf(nil, "%d:%d:%d:%d", c.stat.Dev, c.stat.Ino, stx.Btime.Sec, stx.Btime.Nsec))
		o.NativeIdentitySha256 = native[:]
	} else {
		native := sha256.Sum256([]byte("lindm.file.absent.v1"))
		o.NativeIdentitySha256 = native[:]
	}
	o.SecurityMetadataSha256 = XattrDigest(s.GetManagedFileXattrs())
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(o)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write(encoded)
	if c.file != nil {
		_, _ = fmt.Fprintf(h, "%d:%d:%d:%d", c.stat.Ctim.Sec, c.stat.Ctim.Nsec, c.stat.Mtim.Sec, c.stat.Mtim.Nsec)
	}
	s.Observation.Metadata.NativeRevision = h.Sum(nil)
	if err := c.unchanged(); err != nil {
		return nil, err
	}
	return s, nil
}

func readXattrs(fd int) ([]*agentv1.NativeFileXattr, error) {
	size, err := unix.Flistxattr(fd, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if size > maxXattrs {
		return nil, ErrUnsupported
	}
	if size == 0 {
		return nil, nil
	}
	data := make([]byte, size)
	n, err := unix.Flistxattr(fd, data)
	if err != nil || n != size {
		return nil, errors.Join(ErrConflict, err)
	}
	names := strings.Split(string(data[:n-1]), "\x00")
	if len(names) > 64 {
		return nil, ErrUnsupported
	}
	slices.Sort(names)
	attrs := make([]*agentv1.NativeFileXattr, 0, len(names))
	total := 0
	for _, name := range names {
		if name != "security.selinux" && !strings.HasPrefix(name, "user.") {
			return nil, fmt.Errorf("%w: cannot preserve security xattr %q", ErrUnsupported, name)
		}
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		total += len(name) + size
		if total > maxXattrs {
			return nil, ErrUnsupported
		}
		value := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, value)
		if err != nil || n != size {
			return nil, errors.Join(ErrConflict, err)
		}
		attrs = append(attrs, &agentv1.NativeFileXattr{Name: name, Value: value})
	}
	return attrs, nil
}

// XattrDigest binds ordered private xattrs without publishing their values.
func XattrDigest(attrs []*agentv1.NativeFileXattr) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.file.xattrs.v1\x00"))
	for _, attr := range attrs {
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(attr.GetName()), attr.GetName(), len(attr.GetValue()))
		_, _ = h.Write(attr.GetValue())
	}
	return h.Sum(nil)
}
