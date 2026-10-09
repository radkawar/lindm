//go:build linux

package serviceprovider

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxSnapshotUnits         = 64
	maxSnapshotExplicit      = 256
	maxSnapshotEntries       = 32768
	maxSnapshotUnitFile      = 1 << 20
	maxSnapshotUnitTotal     = 32 << 20
	maxSnapshotRunFile       = 64 << 20
	maxSnapshotRunTotal      = 256 << 20
	maxSnapshotDepth         = 64
	maxSnapshotLabel         = 4096
	snapshotBufSize          = 64 * 1024
	maxSnapshotMetadataBytes = 32 << 20

	snapshotDomain = "lindm.systemd.install-snapshot.v1\x00"
	selinuxAttr    = "security.selinux"
)

var nullRdev = unix.Mkdev(1, 3)

const (
	kindNegative byte = 1
	kindDir      byte = 2
	kindFile     byte = 3
	kindSymlink  byte = 4
	kindNull     byte = 5
)

const (
	snapErrNone    byte = 0
	snapErrMissing byte = 1
	snapErrNotDir  byte = 2
)

const (
	snapLabelNone        byte = 0
	snapLabelAbsent      byte = 1
	snapLabelUnsupported byte = 2
	snapLabelPresent     byte = 3
)

const (
	classContext pathClass = 1 << iota
	classRuntime
	classUnit
)

// Logical trees that must never be projected as native unit or runtime input.
// Private protocol state is not a remotely manageable definition. procfs and
// sysfs are not regular source files; boot ID is bound separately.
var forbiddenSnapshotPrefixes = []string{
	"/var/lib/lindm",
	"/run/lindm",
	"/proc",
	"/sys",
}

// InstallSnapshotInputs are absolute logical host paths. They are not
// lexical-cleaned before symlink traversal. UnitPaths order is significant.
// ContextFiles and RuntimeFiles are explicit files, not recursive directories.
// Runtime discovery supplies sorted unique original paths; this package does
// not discover them.
type InstallSnapshotInputs struct {
	UnitPaths    []string
	ContextFiles []string
	RuntimeFiles []string
}

type pathClass uint8

type snapNode struct {
	path        string
	kind        byte
	errClass    byte
	selClass    byte
	selinux     []byte
	mode        uint32
	uid         uint32
	gid         uint32
	dev         uint64
	ino         uint64
	nlink       uint64
	rdev        uint64
	size        int64
	mtimeSec    int64
	mtimeNsec   int64
	ctimeSec    int64
	ctimeNsec   int64
	target      string
	content     [32]byte
	hasContent  bool
	class       pathClass
	unitScanned bool
	recursed    bool
	recursing   bool
}

type inodeKey struct {
	dev uint64
	ino uint64
}

type session struct {
	ctx            context.Context
	rootFD         int
	rootDev        uint64
	rootIno        uint64
	dest           *destWriter
	destDev        uint64
	destIno        uint64
	hasDest        bool
	nodes          map[string]*snapNode
	byInode        map[inodeKey]string
	unitUsed       int64
	runUsed        int64
	unitCharged    map[inodeKey]struct{}
	runCharged     map[inodeKey]struct{}
	buf            []byte
	metadataUsed   int
	pendingEntries int
	targets        []snapshotWork
}

// CaptureInstallSnapshot copies the logical input filesystem into destination
// for use as the worker RootDirectory (--root=/). Symlink text is preserved.
// The canonical character device /dev/null is stored as a root-owned empty
// regular placeholder; the caller must bind the genuine device there before
// native execution without overmounting captured /dev. Paths that resolve
// into /var/lib/lindm, /run/lindm, /proc, or /sys are rejected. destination
// must be an empty root-owned mode 0700 directory. The caller discards it
// after any error. The digest binds source metadata and bytes, not destination
// inode numbers. This is not an atomic or crash-durable snapshot.
func CaptureInstallSnapshot(ctx context.Context, destination *os.Root, inputs InstallSnapshotInputs) ([32]byte, error) {
	if destination == nil {
		return [32]byte{}, fmt.Errorf("%w: nil snapshot destination", ErrUnsupported)
	}
	root, err := openHostSnapshotRoot()
	if err != nil {
		return [32]byte{}, err
	}
	defer func() { _ = unix.Close(root) }()
	return captureInstallSnapshotRoot(ctx, root, destination, inputs)
}

// FingerprintInstallSnapshot walks the same source graph as capture and
// returns the same digest without writing a destination. The caller compares
// a fresh fingerprint before publishing a capture. Per-object pre/post checks
// reject metadata that changes during the walk; this is not an ABA claim.
func FingerprintInstallSnapshot(ctx context.Context, inputs InstallSnapshotInputs) ([32]byte, error) {
	root, err := openHostSnapshotRoot()
	if err != nil {
		return [32]byte{}, err
	}
	defer func() { _ = unix.Close(root) }()
	return fingerprintInstallSnapshotRoot(ctx, root, inputs)
}

// captureInstallSnapshotRoot is the root-FD test seam. Traversal clamps ".."
// at rootFD and restarts absolute symlinks there. It never opens physical "/".
// Trusted UID remains 0; this does not accept a caller-selected owner.
func captureInstallSnapshotRoot(ctx context.Context, rootFD int, destination *os.Root, inputs InstallSnapshotInputs) ([32]byte, error) {
	if destination == nil {
		return [32]byte{}, fmt.Errorf("%w: nil snapshot destination", ErrUnsupported)
	}
	return snapshotFromRoot(ctx, rootFD, destination, inputs)
}

func fingerprintInstallSnapshotRoot(ctx context.Context, rootFD int, inputs InstallSnapshotInputs) ([32]byte, error) {
	return snapshotFromRoot(ctx, rootFD, nil, inputs)
}

func openHostSnapshotRoot() (int, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if !trustedDirectory(&st) {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%w: untrusted snapshot root", ErrUnsupported)
	}
	return fd, nil
}

func snapshotFromRoot(ctx context.Context, rootFD int, destination *os.Root, inputs InstallSnapshotInputs) ([32]byte, error) {
	var zero [32]byte
	if ctx == nil {
		return zero, fmt.Errorf("%w: nil context", ErrUnsupported)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := validateSnapshotInputs(inputs); err != nil {
		return zero, err
	}
	dup, err := dupFD(rootFD)
	if err != nil {
		return zero, err
	}
	defer func() { _ = unix.Close(dup) }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(dup, &rootStat); err != nil {
		return zero, err
	}
	if !trustedDirectory(&rootStat) {
		return zero, fmt.Errorf("%w: untrusted snapshot root", ErrUnsupported)
	}
	s := &session{
		ctx:         ctx,
		rootFD:      dup,
		rootDev:     rootStat.Dev,
		rootIno:     rootStat.Ino,
		nodes:       make(map[string]*snapNode),
		byInode:     make(map[inodeKey]string),
		unitCharged: make(map[inodeKey]struct{}),
		runCharged:  make(map[inodeKey]struct{}),
		buf:         make([]byte, snapshotBufSize),
	}
	if destination != nil {
		if err := s.attachDest(destination); err != nil {
			return zero, err
		}
		defer s.dest.close()
		if s.destDev == s.rootDev && s.destIno == s.rootIno {
			return zero, fmt.Errorf("%w: snapshot destination is the source root", ErrUnsupported)
		}
	}
	if err := s.captureInputs(inputs); err != nil {
		return zero, mapSnapshotErrno(err)
	}
	if err := s.ctx.Err(); err != nil {
		return zero, err
	}
	if s.dest != nil {
		if err := s.writeSymlinks(); err != nil {
			return zero, mapSnapshotErrno(err)
		}
	}
	if err := s.ctx.Err(); err != nil {
		return zero, err
	}
	digest := digestSnapshot(inputs, s.nodes)
	if err := s.ctx.Err(); err != nil {
		return zero, err
	}
	return digest, nil
}

func validateSnapshotInputs(inputs InstallSnapshotInputs) error {
	if len(inputs.UnitPaths) > maxSnapshotUnits {
		return fmt.Errorf("%w: too many unit paths", ErrUnsupported)
	}
	if len(inputs.ContextFiles) > maxSnapshotExplicit || len(inputs.RuntimeFiles) > maxSnapshotExplicit ||
		len(inputs.ContextFiles)+len(inputs.RuntimeFiles) > maxSnapshotExplicit {
		return fmt.Errorf("%w: too many explicit snapshot paths", ErrUnsupported)
	}
	for _, path := range inputs.UnitPaths {
		if err := validSnapshotPath(path); err != nil {
			return err
		}
	}
	for _, path := range inputs.ContextFiles {
		if err := validSnapshotPath(path); err != nil {
			return err
		}
	}
	for _, path := range inputs.RuntimeFiles {
		if err := validSnapshotPath(path); err != nil {
			return err
		}
	}
	return nil
}

func validSnapshotPath(path string) error {
	if path == "" || path[0] != '/' || len(path) > maxDefinitionPath || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("%w: invalid snapshot path %q", ErrUnsupported, path)
	}
	if err := forbiddenSnapshotPath(path); err != nil {
		return err
	}
	// Reject a forbidden prefix formed by the literal components, including
	// repeated slashes, without resolving ".." or symlink targets.
	parent := ""
	for _, part := range splitSnapshotPath(path) {
		if part == ".." {
			break // Only actual traversal can resolve what precedes "..".
		}
		parent = childPath(parent, part)
		if err := forbiddenSnapshotPath(parent); err != nil {
			return err
		}
	}
	return nil
}

func forbiddenSnapshotPath(path string) error {
	if path == "" {
		return nil
	}
	for _, prefix := range forbiddenSnapshotPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return fmt.Errorf("%w: snapshot path %s is private state or a special filesystem", ErrUnsupported, path)
		}
	}
	return nil
}

// privateNamespaceAncestor reports whether path is a strict ancestor of a
// forbidden snapshot prefix. The prefix itself is rejected separately.
func privateNamespaceAncestor(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	for _, prefix := range forbiddenSnapshotPrefixes {
		if strings.HasPrefix(prefix, path+"/") {
			return true
		}
	}
	return false
}

func (s *session) captureInputs(inputs InstallSnapshotInputs) error {
	// Runtime paths are walked first. A later unit or context observation of
	// the same inode still uses the unit/context caps and the include guard.
	for _, path := range inputs.RuntimeFiles {
		if err := s.captureLogical(path, classRuntime, false); err != nil {
			return err
		}
	}
	for _, path := range inputs.ContextFiles {
		if err := s.captureLogical(path, classContext, false); err != nil {
			return err
		}
	}
	for _, path := range inputs.UnitPaths {
		if err := s.captureLogical(path, classUnit, true); err != nil {
			return err
		}
	}
	return s.captureTargets()
}

// digestSnapshot binds only the ordered inputs and source graph. Destination
// ownership, job ancestry, destination inode numbers, and job UUID paths are
// not inputs. Capture and fingerprint of an unchanged source therefore match
// across different empty destinations. Relative symlink text is preserved, so
// a later native write outside the caller's writable config scope is not
// rewritten or counted here.
func digestSnapshot(inputs InstallSnapshotInputs, nodes map[string]*snapNode) [32]byte {
	list := make([]*snapNode, 0, len(nodes))
	for _, node := range nodes {
		list = append(list, node)
	}
	slices.SortFunc(list, func(a, b *snapNode) int {
		return strings.Compare(a.path, b.path)
	})
	h := sha256.New()
	_, _ = io.WriteString(h, snapshotDomain)
	writePaths(h, inputs.UnitPaths)
	writePaths(h, inputs.ContextFiles)
	writePaths(h, inputs.RuntimeFiles)
	writeLength(h, uint64(len(list)))
	for _, node := range list {
		writeString(h, node.path)
		_, _ = h.Write([]byte{node.kind, node.errClass, node.selClass})
		writeUint32(h, node.mode)
		writeUint32(h, node.uid)
		writeUint32(h, node.gid)
		writeUint64(h, node.dev)
		writeUint64(h, node.ino)
		writeUint64(h, node.nlink)
		writeUint64(h, node.rdev)
		writeUint64(h, uint64(node.size))
		writeUint64(h, uint64(node.mtimeSec))
		writeUint64(h, uint64(node.mtimeNsec))
		writeUint64(h, uint64(node.ctimeSec))
		writeUint64(h, uint64(node.ctimeNsec))
		writeBytes(h, node.selinux)
		writeString(h, node.target)
		_, _ = h.Write(node.content[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writePaths(h hash.Hash, paths []string) {
	writeLength(h, uint64(len(paths)))
	for _, path := range paths {
		writeString(h, path)
	}
}

func writeString(h hash.Hash, value string) {
	writeLength(h, uint64(len(value)))
	_, _ = io.WriteString(h, value)
}

func writeBytes(h hash.Hash, value []byte) {
	writeLength(h, uint64(len(value)))
	_, _ = h.Write(value)
}

func writeUint32(h hash.Hash, value uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	_, _ = h.Write(buf[:])
}

func writeUint64(h hash.Hash, value uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	_, _ = h.Write(buf[:])
}

func dupFD(fd int) (int, error) {
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return n, nil
}

func mapSnapshotErrno(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) {
		return fmt.Errorf("%w: snapshot descriptor limit: %w", ErrUnsupported, err)
	}
	return err
}

func sameMeta(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode &&
		before.Uid == after.Uid && before.Gid == after.Gid && before.Nlink == after.Nlink &&
		before.Size == after.Size && before.Rdev == after.Rdev &&
		before.Mtim.Sec == after.Mtim.Sec && before.Mtim.Nsec == after.Mtim.Nsec &&
		before.Ctim.Sec == after.Ctim.Sec && before.Ctim.Nsec == after.Ctim.Nsec
}

func fillMeta(node *snapNode, st unix.Stat_t) {
	node.mode = st.Mode
	node.uid = st.Uid
	node.gid = st.Gid
	node.dev = st.Dev
	node.ino = st.Ino
	node.nlink = st.Nlink
	node.rdev = st.Rdev
	node.size = st.Size
	node.mtimeSec = st.Mtim.Sec
	node.mtimeNsec = st.Mtim.Nsec
	node.ctimeSec = st.Ctim.Sec
	node.ctimeNsec = st.Ctim.Nsec
}

func metaMatches(node *snapNode, st unix.Stat_t) bool {
	return node.mode == st.Mode && node.uid == st.Uid && node.gid == st.Gid &&
		node.dev == st.Dev && node.ino == st.Ino && node.nlink == st.Nlink &&
		node.rdev == st.Rdev && node.size == st.Size &&
		node.mtimeSec == st.Mtim.Sec && node.mtimeNsec == st.Mtim.Nsec &&
		node.ctimeSec == st.Ctim.Sec && node.ctimeNsec == st.Ctim.Nsec
}

func (s *session) sameDest(st unix.Stat_t) bool {
	return s.hasDest && st.Dev == s.destDev && st.Ino == s.destIno
}

func (s *session) addNode(node *snapNode) error {
	if _, ok := s.nodes[node.path]; ok {
		return fmt.Errorf("%w: duplicate snapshot node %s", ErrConflict, node.path)
	}
	if len(s.nodes) >= maxSnapshotEntries {
		return fmt.Errorf("%w: snapshot graph exceeds entry limit", ErrUnsupported)
	}
	if err := s.reserveMetadata(snapshotNodeCharge + len(node.path) + len(node.target) + len(node.selinux)); err != nil {
		return err
	}
	s.nodes[node.path] = node
	return nil
}

func (s *session) addNegative(path string, errClass byte) error {
	if err := forbiddenSnapshotPath(path); err != nil {
		return err
	}
	// The worker adds its private protocol trees. An absent ancestor must not
	// become a new positive input merely because that namespace is prepared.
	if privateNamespaceAncestor(path) {
		return fmt.Errorf("%w: missing ancestor of private snapshot namespace %s", ErrUnsupported, path)
	}
	if existing, ok := s.nodes[path]; ok {
		if existing.kind == kindNegative && existing.errClass == errClass {
			return nil
		}
		return fmt.Errorf("%w: snapshot path %s changed", ErrConflict, path)
	}
	node := &snapNode{path: path, kind: kindNegative, errClass: errClass, selClass: snapLabelNone}
	return s.addNode(node)
}

// Preserve every component until traversal establishes that its predecessor is
// a directory. In particular, "file/" and "file/." must retain ENOTDIR.
func splitSnapshotPath(path string) []string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

// pathDepth receives only canonical absolute source-node paths.
func pathDepth(path string) int {
	if path == "" || path == "/" {
		return 0
	}
	return strings.Count(path, "/")
}

func childPath(parent, name string) string {
	if parent == "" || parent == "/" {
		return "/" + name
	}
	return parent + "/" + name
}

func joinLogical(parent, target string) string {
	if strings.HasPrefix(target, "/") {
		return target
	}
	if parent == "" || parent == "/" {
		return "/" + target
	}
	return parent + "/" + target
}

func isNullDevice(path string, st unix.Stat_t) bool {
	return path == "/dev/null" && st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Uid == 0 && st.Rdev == nullRdev
}

func errorsIsNotExist(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist)
}
