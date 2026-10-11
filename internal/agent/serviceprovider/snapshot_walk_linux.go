//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

type dirStack struct {
	frames []stackedDir
}

type stackedDir struct {
	fd   int
	name string
	dev  uint64
	ino  uint64
}

func newStack(rootFD int) (*dirStack, error) {
	frame, err := dupRootFrame(rootFD)
	if err != nil {
		return nil, err
	}
	return &dirStack{frames: []stackedDir{frame}}, nil
}

func (st *dirStack) top() int {
	return st.frames[len(st.frames)-1].fd
}

func (st *dirStack) canonical() string {
	if len(st.frames) <= 1 {
		return ""
	}
	var b strings.Builder
	for i := 1; i < len(st.frames); i++ {
		b.WriteByte('/')
		b.WriteString(st.frames[i].name)
	}
	return b.String()
}

func (st *dirStack) push(fd int, name string, dev, ino uint64) {
	st.frames = append(st.frames, stackedDir{fd: fd, name: name, dev: dev, ino: ino})
}

func (st *dirStack) pop() {
	if len(st.frames) <= 1 {
		return
	}
	top := st.frames[len(st.frames)-1]
	_ = unix.Close(top.fd)
	st.frames = st.frames[:len(st.frames)-1]
}

func (st *dirStack) reset(rootFD int) error {
	st.close()
	frame, err := dupRootFrame(rootFD)
	if err != nil {
		return err
	}
	st.frames = []stackedDir{frame}
	return nil
}

func (st *dirStack) close() {
	for _, frame := range st.frames {
		_ = unix.Close(frame.fd)
	}
	st.frames = nil
}

// atRoot reports whether ".." must be clamped. Only stack depth counts. A
// nested bind of the logical root shares its dev/ino and must still pop,
// because the kernel leaves that mount.
func (st *dirStack) atRoot() bool {
	return len(st.frames) <= 1
}

func (st *dirStack) ancestorKeys() []inodeKey {
	return frameKeys(st.frames)
}

func (st *dirStack) parentKeys() []inodeKey {
	if len(st.frames) == 0 {
		return nil
	}
	return frameKeys(st.frames[:len(st.frames)-1])
}

func frameKeys(frames []stackedDir) []inodeKey {
	keys := make([]inodeKey, len(frames))
	for i, frame := range frames {
		keys[i] = inodeKey{frame.dev, frame.ino}
	}
	return keys
}

func dupRootFrame(rootFD int) (stackedDir, error) {
	fd, err := dupFD(rootFD)
	if err != nil {
		return stackedDir{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return stackedDir{}, err
	}
	return stackedDir{fd: fd, dev: st.Dev, ino: st.Ino}, nil
}

func readlinkPinned(fd int) (string, error) {
	buf := make([]byte, maxDefinitionPath+1)
	n, err := unix.Readlinkat(fd, "", buf)
	if err != nil {
		return "", err
	}
	if n <= 0 || n > maxDefinitionPath {
		return "", fmt.Errorf("%w: invalid snapshot symlink target", ErrUnsupported)
	}
	return string(buf[:n]), nil
}

// resolveInstallSnapshotDirectory resolves logicalPath inside root with the
// snapshot walker. ".." is clamped at root. Absolute symlinks restart at root.
// Paths are not lexical-cleaned and symlink bytes are not rewritten. The
// returned file is a caller-owned readable directory pinned to the resolved
// inode. The path is the absolute canonical logical path within root ("/" for
// the root itself). This is not filepath.EvalSymlinks and does not consult
// the host path namespace outside root.
func resolveInstallSnapshotDirectory(root *os.Root, logicalPath string) (*os.File, string, error) {
	if root == nil {
		return nil, "", fmt.Errorf("%w: nil snapshot root", ErrUnsupported)
	}
	if err := validSnapshotPath(logicalPath); err != nil {
		return nil, "", err
	}
	rootFile, err := root.Open(".")
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rootFile.Close() }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(int(rootFile.Fd()), &rootStat); err != nil {
		return nil, "", err
	}
	if !custody.TrustedDirectory(&rootStat) {
		return nil, "", fmt.Errorf("%w: untrusted snapshot root", ErrUnsupported)
	}
	file, canonical, err := openLogicalDirectory(int(rootFile.Fd()), logicalPath)
	if err != nil {
		return nil, "", mapSnapshotErrno(err)
	}
	return file, canonical, nil
}

func openLogicalDirectory(rootFD int, logicalPath string) (*os.File, string, error) {
	stack, err := newStack(rootFD)
	if err != nil {
		return nil, "", err
	}
	defer stack.close()
	pending := splitSnapshotPath(logicalPath)
	symlinks := 0
	steps := 0
	for {
		if len(pending) == 0 {
			return pinReadableDir(stack)
		}
		steps++
		if steps > maxDefinitionPath {
			return nil, "", fmt.Errorf("%w: snapshot traversal exceeds limit", ErrUnsupported)
		}
		component := pending[0]
		pending = pending[1:]
		if component == "" || component == "." {
			continue
		}
		if len(component) > 255 || strings.ContainsRune(component, '\x00') {
			return nil, "", fmt.Errorf("%w: invalid snapshot component", ErrUnsupported)
		}
		if component == ".." {
			if stack.atRoot() {
				continue
			}
			stack.pop()
			continue
		}
		parentPath := stack.canonical()
		nextPath := childPath(parentPath, component)
		if len(nextPath) > maxDefinitionPath {
			return nil, "", fmt.Errorf("%w: snapshot path exceeds limit", ErrUnsupported)
		}
		if err := forbiddenSnapshotPath(nextPath); err != nil {
			return nil, "", err
		}
		next, err := unix.Openat(stack.top(), component, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, "", fmt.Errorf("snapshot directory %s: %w", nextPath, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil {
			_ = unix.Close(next)
			return nil, "", err
		}
		if st.Uid != 0 {
			_ = unix.Close(next)
			return nil, "", fmt.Errorf("%w: non-root snapshot directory %s", ErrUnsupported, nextPath)
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			if privateNamespaceAncestor(nextPath) {
				_ = unix.Close(next)
				return nil, "", fmt.Errorf("%w: symlink ancestor of private snapshot namespace %s", ErrUnsupported, nextPath)
			}
			symlinks++
			if symlinks > maxSymlinks {
				_ = unix.Close(next)
				return nil, "", fmt.Errorf("%w: too many snapshot symlinks", ErrUnsupported)
			}
			target, err := readlinkPinned(next)
			_ = unix.Close(next)
			if err != nil {
				return nil, "", err
			}
			if strings.HasPrefix(target, "/") {
				if err := stack.reset(rootFD); err != nil {
					return nil, "", err
				}
			}
			pending = append(splitSnapshotPath(target), pending...)
		case unix.S_IFDIR:
			if !custody.TrustedDirectory(&st) {
				_ = unix.Close(next)
				return nil, "", fmt.Errorf("%w: untrusted snapshot directory %s", ErrUnsupported, nextPath)
			}
			if len(stack.frames)-1 >= maxSnapshotDepth {
				_ = unix.Close(next)
				return nil, "", fmt.Errorf("%w: snapshot depth exceeds limit", ErrUnsupported)
			}
			stack.push(next, component, st.Dev, st.Ino)
		default:
			_ = unix.Close(next)
			return nil, "", fmt.Errorf("%w: snapshot path %s is not a directory", ErrUnsupported, nextPath)
		}
	}
}

func pinReadableDir(stack *dirStack) (*os.File, string, error) {
	var before unix.Stat_t
	if err := unix.Fstat(stack.top(), &before); err != nil {
		return nil, "", err
	}
	if !custody.TrustedDirectory(&before) {
		return nil, "", fmt.Errorf("%w: snapshot path is not a trusted directory", ErrUnsupported)
	}
	canonical := stack.canonical()
	if canonical == "" {
		canonical = "/"
	}
	if err := forbiddenSnapshotPath(canonical); err != nil {
		return nil, "", err
	}
	readFD, err := unix.Openat(stack.top(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	var after unix.Stat_t
	if err := unix.Fstat(readFD, &after); err != nil {
		_ = unix.Close(readFD)
		return nil, "", err
	}
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Mode != before.Mode || after.Uid != before.Uid {
		_ = unix.Close(readFD)
		return nil, "", fmt.Errorf("%w: snapshot directory changed while pinning", ErrConflict)
	}
	return os.NewFile(uintptr(readFD), canonical), canonical, nil
}

func (s *session) captureLogical(path string, class pathClass, recurseFinal bool) error {
	return s.walkLogical(path, class, recurseFinal, nil)
}

// followRecorded walks a queued target. A repeated symlink and remaining suffix
// terminate an already-recorded cycle. Explicit inputs still reject cycles
// through the symlink budget.
func (s *session) followRecorded(path string, class pathClass) error {
	return s.walkLogical(path, class, true, make(map[symlinkWalkState]struct{}))
}

func (s *session) walkLogical(path string, class pathClass, recurseFinal bool, seen map[symlinkWalkState]struct{}) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	stack, err := newStack(s.rootFD)
	if err != nil {
		return err
	}
	defer stack.close()
	seenBytes := 0
	defer func() { s.metadataUsed -= seenBytes }()
	pending := splitSnapshotPath(path)
	symlinks := 0
	steps := 0
	for len(pending) > 0 {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		steps++
		if steps > maxDefinitionPath {
			return fmt.Errorf("%w: snapshot traversal exceeds limit", ErrUnsupported)
		}
		component := pending[0]
		pending = pending[1:]
		if component == "" || component == "." {
			continue
		}
		if len(component) > 255 || strings.ContainsRune(component, '\x00') {
			return fmt.Errorf("%w: invalid snapshot component", ErrUnsupported)
		}
		if component == ".." {
			if stack.atRoot() {
				continue
			}
			stack.pop()
			continue
		}
		parentFD := stack.top()
		parentPath := stack.canonical()
		pathHere := childPath(parentPath, component)
		if len(pathHere) > maxDefinitionPath || pathDepth(pathHere) > maxSnapshotDepth {
			return fmt.Errorf("%w: snapshot path exceeds limit", ErrUnsupported)
		}
		if err := forbiddenSnapshotPath(pathHere); err != nil {
			return err
		}
		next, st, missing, err := s.openWalkComponent(parentFD, component, pathHere)
		if missing {
			return s.addNegative(pathHere, snapErrMissing)
		}
		if err != nil {
			return err
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			symlinks++
			if symlinks > maxSymlinks {
				_ = unix.Close(next)
				return fmt.Errorf("%w: too many snapshot symlinks", ErrUnsupported)
			}
			target, err := readlinkPinned(next)
			if err != nil {
				_ = unix.Close(next)
				return err
			}
			if err := s.observeSymlink(parentFD, component, pathHere, st, target); err != nil {
				_ = unix.Close(next)
				return err
			}
			_ = unix.Close(next)
			if seen != nil {
				repeated, charged, err := s.rememberSymlink(seen, pathHere, pending)
				if err != nil {
					return err
				}
				seenBytes += charged
				if repeated {
					return nil
				}
			}
			if strings.HasPrefix(target, "/") {
				if err := stack.reset(s.rootFD); err != nil {
					return err
				}
			}
			pending = append(splitSnapshotPath(target), pending...)
		case unix.S_IFDIR:
			if !custody.TrustedDirectory(&st) {
				_ = unix.Close(next)
				return fmt.Errorf("%w: untrusted snapshot directory %s", ErrUnsupported, pathHere)
			}
			final := len(pending) == 0
			if err := s.observeDir(next, pathHere, st, class, final && recurseFinal, stack.ancestorKeys()); err != nil {
				_ = unix.Close(next)
				return err
			}
			if final {
				_ = unix.Close(next)
				if !recurseFinal {
					return fmt.Errorf("%w: explicit snapshot path %s is a directory", ErrUnsupported, path)
				}
				return nil
			}
			stack.push(next, component, st.Dev, st.Ino)
		case unix.S_IFREG, unix.S_IFCHR:
			return s.observeLeaf(next, parentFD, component, pathHere, st, class, pending)
		default:
			_ = unix.Close(next)
			return fmt.Errorf("%w: unsupported snapshot file type %s", ErrUnsupported, pathHere)
		}
	}
	return s.observeWalkEnd(stack, path, class, recurseFinal)
}

// openWalkComponent pins one path component without following it and requires
// a root-owned object outside the snapshot destination. missing reports an
// absent component, which the walk records as a negative result.
func (s *session) openWalkComponent(parentFD int, component, pathHere string) (next int, st unix.Stat_t, missing bool, err error) {
	next, err = unix.Openat(parentFD, component, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errorsIsNotExist(err) {
			return -1, st, true, nil
		}
		if errors.Is(err, unix.ENOTDIR) {
			return -1, st, false, fmt.Errorf("%w: snapshot directory changed during walk: %w", ErrConflict, err)
		}
		return -1, st, false, fmt.Errorf("%w: snapshot walk %s: %w", ErrUnsupported, pathHere, err)
	}
	if err := unix.Fstat(next, &st); err != nil {
		_ = unix.Close(next)
		return -1, st, false, err
	}
	if st.Uid != 0 {
		_ = unix.Close(next)
		return -1, st, false, fmt.Errorf("%w: non-root snapshot component %s", ErrUnsupported, pathHere)
	}
	if s.sameDest(st) {
		_ = unix.Close(next)
		return -1, st, false, fmt.Errorf("%w: snapshot would recurse into destination", ErrUnsupported)
	}
	return next, st, false, nil
}

// observeLeaf records the read-only regular file or null device that ends a
// walk and closes next. A remaining suffix below it is recorded as a
// not-a-directory negative result.
func (s *session) observeLeaf(next, parentFD int, component, pathHere string, st unix.Stat_t, class pathClass, pending []string) error {
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		if st.Mode&0022 != 0 {
			_ = unix.Close(next)
			return fmt.Errorf("%w: writable snapshot file %s", ErrUnsupported, pathHere)
		}
		if err := s.observeFile(parentFD, component, pathHere, st, class); err != nil {
			_ = unix.Close(next)
			return err
		}
	} else {
		if !isNullDevice(pathHere, st) {
			_ = unix.Close(next)
			return fmt.Errorf("%w: unsupported snapshot device %s", ErrUnsupported, pathHere)
		}
		if err := s.observeNull(parentFD, component, pathHere, st); err != nil {
			_ = unix.Close(next)
			return err
		}
	}
	_ = unix.Close(next)
	if len(pending) == 0 {
		return nil
	}
	return s.addNegative(childPath(pathHere, pending[0]), snapErrNotDir)
}

// observeWalkEnd records the directory a walk ended in after consuming every
// component (for example through a trailing ".."); only recursive captures may
// end on a directory.
func (s *session) observeWalkEnd(stack *dirStack, path string, class pathClass, recurseFinal bool) error {
	current := stack.canonical()
	if current == "" {
		current = "/"
	}
	if err := forbiddenSnapshotPath(current); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(stack.top(), &st); err != nil {
		return err
	}
	if !recurseFinal {
		return fmt.Errorf("%w: explicit snapshot path %s is a directory", ErrUnsupported, path)
	}
	return s.observeDir(stack.top(), current, st, class, true, stack.parentKeys())
}

func (s *session) observeDir(fd int, path string, before unix.Stat_t, class pathClass, recurse bool, ancestors []inodeKey) error {
	if err := forbiddenSnapshotPath(path); err != nil {
		return err
	}
	if s.sameDest(before) {
		return fmt.Errorf("%w: snapshot would recurse into destination", ErrUnsupported)
	}
	if existing, ok := s.nodes[path]; ok {
		if existing.kind != kindDir || !metaMatches(existing, before) {
			return fmt.Errorf("%w: snapshot directory %s changed", ErrConflict, path)
		}
		labelClass, label, err := selinuxFromDir(fd)
		if err != nil {
			return err
		}
		var after unix.Stat_t
		if err := unix.Fstat(fd, &after); err != nil {
			return err
		}
		if !metaMatches(existing, after) || existing.selClass != labelClass || !bytes.Equal(existing.selinux, label) {
			return fmt.Errorf("%w: snapshot directory %s changed", ErrConflict, path)
		}
		if err := s.noteClass(existing, class); err != nil {
			return err
		}
		if recurse {
			return s.recurse(fd, existing, class, ancestors)
		}
		return nil
	}
	labelClass, label, err := selinuxFromDir(fd)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if !sameMeta(before, after) {
		return fmt.Errorf("%w: snapshot directory %s changed", ErrConflict, path)
	}
	labelClass2, label2, err := selinuxFromDir(fd)
	if err != nil {
		return err
	}
	if labelClass != labelClass2 || !bytes.Equal(label, label2) {
		return fmt.Errorf("%w: snapshot SELinux label changed", ErrConflict)
	}
	node := &snapNode{path: path, kind: kindDir, selClass: labelClass, selinux: label, class: class}
	fillMeta(node, before)
	if err := s.addNode(node); err != nil {
		return err
	}
	if s.dest != nil && path != "/" {
		if err := s.dest.ensureDir(path); err != nil {
			return err
		}
		if err := s.dest.setDirLabel(path, labelClass, label); err != nil {
			return err
		}
	}
	if recurse {
		return s.recurse(fd, node, class, ancestors)
	}
	return nil
}

func (s *session) recurse(dirFD int, node *snapNode, class pathClass, ancestors []inodeKey) error {
	// Same canonical path, including a symlink back to a directory already
	// being recorded, terminates. A different path with an ancestor dev/ino
	// is a bind cycle and is rejected below.
	if node.recursed || node.recursing {
		return nil
	}
	key := inodeKey{node.dev, node.ino}
	for _, prev := range ancestors {
		if prev == key {
			return fmt.Errorf("%w: snapshot directory cycle %s", ErrUnsupported, node.path)
		}
	}
	if pathDepth(node.path) > maxSnapshotDepth {
		return fmt.Errorf("%w: snapshot depth exceeds limit", ErrUnsupported)
	}
	node.recursing = true
	names, err := s.list(dirFD)
	if err != nil {
		node.recursing = false
		return err
	}
	defer func() {
		for _, name := range names {
			if name != "" {
				s.releasePending(name)
			}
		}
	}()
	var after unix.Stat_t
	if err := unix.Fstat(dirFD, &after); err != nil {
		node.recursing = false
		return err
	}
	if !metaMatches(node, after) {
		node.recursing = false
		return fmt.Errorf("%w: snapshot directory %s changed while listing", ErrConflict, node.path)
	}
	if len(names) > 0 && pathDepth(node.path) >= maxSnapshotDepth {
		node.recursing = false
		return fmt.Errorf("%w: snapshot depth exceeds limit", ErrUnsupported)
	}
	node.recursed = true
	node.recursing = false
	nextAnc := make([]inodeKey, len(ancestors)+1)
	copy(nextAnc, ancestors)
	nextAnc[len(ancestors)] = key
	for i, name := range names {
		names[i] = ""
		s.releasePending(name)
		if err := s.captureEntry(dirFD, node.path, name, class, nextAnc); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) list(dirFD int) ([]string, error) {
	readFD, err := unix.Openat(dirFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(readFD) }()
	var names []string
	complete := false
	defer func() {
		if !complete {
			for _, name := range names {
				s.releasePending(name)
			}
		}
	}()
	for {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
		n, err := unix.ReadDirent(readFD, s.buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		names, _, err = parseSnapshotDirents(s.buf[:n], names, true, s.reservePending)
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(names)
	complete = true
	return names, nil
}

func (s *session) captureEntry(parentFD int, parentPath, name string, class pathClass, ancestors []inodeKey) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) > 255 {
		return fmt.Errorf("%w: unsafe snapshot directory entry %q", ErrUnsupported, name)
	}
	path := childPath(parentPath, name)
	if len(path) > maxDefinitionPath || pathDepth(path) > maxSnapshotDepth {
		return fmt.Errorf("%w: snapshot path exceeds limit", ErrUnsupported)
	}
	if err := forbiddenSnapshotPath(path); err != nil {
		return err
	}
	next, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: snapshot entry %s: %w", ErrUnsupported, path, err)
	}
	defer func() { _ = unix.Close(next) }()
	var st unix.Stat_t
	if err := unix.Fstat(next, &st); err != nil {
		return err
	}
	if st.Uid != 0 {
		return fmt.Errorf("%w: non-root snapshot entry %s", ErrUnsupported, path)
	}
	if s.sameDest(st) {
		return fmt.Errorf("%w: snapshot would recurse into destination", ErrUnsupported)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if !custody.TrustedDirectory(&st) {
			return fmt.Errorf("%w: untrusted snapshot directory %s", ErrUnsupported, path)
		}
		return s.observeDir(next, path, st, class, true, ancestors)
	case unix.S_IFREG:
		if st.Mode&0022 != 0 {
			return fmt.Errorf("%w: writable snapshot file %s", ErrUnsupported, path)
		}
		return s.observeFile(parentFD, name, path, st, class)
	case unix.S_IFLNK:
		target, err := readlinkPinned(next)
		if err != nil {
			return err
		}
		if err := s.observeSymlink(parentFD, name, path, st, target); err != nil {
			return err
		}
		return s.enqueueTarget(joinLogical(parentPath, target), class)
	case unix.S_IFCHR:
		if isNullDevice(path, st) {
			return s.observeNull(parentFD, name, path, st)
		}
		return fmt.Errorf("%w: unsupported snapshot device %s", ErrUnsupported, path)
	default:
		return fmt.Errorf("%w: unsupported snapshot file type %s", ErrUnsupported, path)
	}
}

func (s *session) observeSymlink(parentFD int, name, path string, before unix.Stat_t, target string) error {
	if err := forbiddenSnapshotPath(path); err != nil {
		return err
	}
	if privateNamespaceAncestor(path) {
		return fmt.Errorf("%w: symlink ancestor of private snapshot namespace %s", ErrUnsupported, path)
	}
	if existing, ok := s.nodes[path]; ok {
		if existing.kind != kindSymlink || !metaMatches(existing, before) || existing.target != target {
			return fmt.Errorf("%w: snapshot symlink %s changed", ErrConflict, path)
		}
		return validateCachedName(parentFD, name, existing)
	}
	labelClass, label, err := selinuxFromName(parentFD, name)
	if err != nil {
		return err
	}
	again, err := readlinkPinnedParent(parentFD, name)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if again != target || !sameMeta(before, after) {
		return fmt.Errorf("%w: snapshot symlink %s changed", ErrConflict, path)
	}
	labelClass2, label2, err := selinuxFromName(parentFD, name)
	if err != nil {
		return err
	}
	if labelClass != labelClass2 || !bytes.Equal(label, label2) {
		return fmt.Errorf("%w: snapshot SELinux label changed", ErrConflict)
	}
	node := &snapNode{path: path, kind: kindSymlink, selClass: labelClass, selinux: label, target: target}
	fillMeta(node, before)
	return s.addNode(node)
}

func (s *session) observeNull(parentFD int, name, path string, before unix.Stat_t) error {
	if !isNullDevice(path, before) {
		return fmt.Errorf("%w: unsupported snapshot device %s", ErrUnsupported, path)
	}
	if existing, ok := s.nodes[path]; ok {
		if existing.kind != kindNull || !metaMatches(existing, before) {
			return fmt.Errorf("%w: snapshot null device changed", ErrConflict)
		}
		return validateCachedName(parentFD, name, existing)
	}
	labelClass, label, err := selinuxFromFile(parentFD, name, before)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameMeta(before, after) || !isNullDevice(path, after) {
		return fmt.Errorf("%w: snapshot null device changed", ErrConflict)
	}
	node := &snapNode{path: path, kind: kindNull, selClass: labelClass, selinux: label}
	fillMeta(node, before)
	if err := s.addNode(node); err != nil {
		return err
	}
	if s.dest == nil {
		return nil
	}
	file, err := s.dest.createExclusive(path, 0600)
	if err != nil {
		return err
	}
	err = finishDestFile(file, 0600, labelClass, label)
	cerr := file.Close()
	if err != nil {
		return err
	}
	return cerr
}

func (s *session) accountFile(dev, ino uint64, size int64, class pathClass, path string) error {
	if size < 0 {
		return fmt.Errorf("%w: snapshot file %s exceeds size limit", ErrUnsupported, path)
	}
	key := inodeKey{dev, ino}
	if class&(classUnit|classContext) != 0 {
		if err := s.chargeUnique(s.unitCharged, &s.unitUsed, key, size, maxSnapshotUnitFile, maxSnapshotUnitTotal, path); err != nil {
			return err
		}
	}
	if class&classRuntime != 0 {
		if err := s.chargeUnique(s.runCharged, &s.runUsed, key, size, maxSnapshotRunFile, maxSnapshotRunTotal, path); err != nil {
			return err
		}
	}
	return nil
}

// chargeUnique applies a pool's per-file cap on every observation. Bytes are
// added to the pool once per inode. A runtime classification does not waive
// the unit/context pool.
func (s *session) chargeUnique(charged map[inodeKey]struct{}, used *int64, key inodeKey, size, fileLimit, totalLimit int64, path string) error {
	if size > fileLimit {
		return fmt.Errorf("%w: snapshot file %s exceeds size limit", ErrUnsupported, path)
	}
	if _, ok := charged[key]; ok {
		return nil
	}
	if size > totalLimit || *used > totalLimit-size {
		return fmt.Errorf("%w: snapshot byte budget exceeded", ErrUnsupported)
	}
	*used += size
	charged[key] = struct{}{}
	return nil
}

func readLimit(class pathClass) int64 {
	if class&(classUnit|classContext) != 0 || class&classRuntime == 0 {
		return maxSnapshotUnitFile
	}
	return maxSnapshotRunFile
}

func (s *session) observeFile(parentFD int, name, path string, before unix.Stat_t, class pathClass) error {
	if err := forbiddenSnapshotPath(path); err != nil {
		return err
	}
	if existing, ok := s.nodes[path]; ok {
		if existing.kind != kindFile || !metaMatches(existing, before) {
			return fmt.Errorf("%w: snapshot file %s changed", ErrConflict, path)
		}
		if err := validateCachedName(parentFD, name, existing); err != nil {
			return err
		}
		if err := s.accountFile(before.Dev, before.Ino, before.Size, class, path); err != nil {
			return err
		}
		return s.noteClass(existing, class)
	}
	key := inodeKey{before.Dev, before.Ino}
	if first, ok := s.byInode[key]; ok {
		origin := s.nodes[first]
		if origin == nil || !metaMatches(origin, before) {
			return fmt.Errorf("%w: snapshot hardlink %s changed", ErrConflict, path)
		}
		if err := validateCachedName(parentFD, name, origin); err != nil {
			return err
		}
		if err := s.accountFile(before.Dev, before.Ino, before.Size, class, path); err != nil {
			return err
		}
		node := &snapNode{
			path: path, kind: kindFile, selClass: origin.selClass, selinux: append([]byte(nil), origin.selinux...),
			content: origin.content, hasContent: true, class: class, unitScanned: origin.unitScanned,
		}
		fillMeta(node, before)
		if err := s.addNode(node); err != nil {
			return err
		}
		if err := s.noteClass(node, class); err != nil {
			return err
		}
		if s.dest != nil {
			return s.dest.link(first, path)
		}
		return nil
	}
	if err := s.accountFile(before.Dev, before.Ino, before.Size, class, path); err != nil {
		return err
	}
	sum, labelClass, label, err := s.readRegular(parentFD, name, path, before, class)
	if err != nil {
		return err
	}
	node := &snapNode{
		path: path, kind: kindFile, selClass: labelClass, selinux: label,
		content: sum, hasContent: true, class: class,
		unitScanned: class&classUnit != 0,
	}
	fillMeta(node, before)
	if err := s.addNode(node); err != nil {
		return err
	}
	s.byInode[key] = path
	return nil
}

func validateCachedName(parentFD int, name string, node *snapNode) error {
	labelClass, label, err := selinuxFromName(parentFD, name)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !metaMatches(node, after) || node.selClass != labelClass || !bytes.Equal(node.selinux, label) {
		return fmt.Errorf("%w: cached snapshot node %s changed", ErrConflict, node.path)
	}
	return nil
}

func (s *session) noteClass(node *snapNode, class pathClass) error {
	node.class |= class
	if class&classUnit == 0 || node.kind != kindFile || node.unitScanned {
		return nil
	}
	if err := s.scanInclude(node); err != nil {
		return err
	}
	node.unitScanned = true
	return nil
}

func (s *session) scanInclude(node *snapNode) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	fd, err := dupFD(s.rootFD)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	rel := strings.TrimPrefix(node.path, "/")
	parts := strings.Split(rel, "/")
	for i, name := range parts {
		if name == "" || name == "." || name == ".." {
			return fmt.Errorf("%w: canonical snapshot path %s is not physical", ErrConflict, node.path)
		}
		flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
		next, err := unix.Openat(fd, name, flags, 0)
		if err != nil {
			return fmt.Errorf("%w: snapshot file %s changed: %w", ErrConflict, node.path, err)
		}
		if i == len(parts)-1 {
			var st unix.Stat_t
			if err := unix.Fstat(next, &st); err != nil {
				_ = unix.Close(next)
				return err
			}
			if !metaMatches(node, st) || st.Mode&unix.S_IFMT != unix.S_IFREG {
				_ = unix.Close(next)
				return fmt.Errorf("%w: snapshot file %s changed", ErrConflict, node.path)
			}
			readFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			_ = unix.Close(next)
			if err != nil {
				return fmt.Errorf("%w: snapshot file %s changed: %w", ErrConflict, node.path, err)
			}
			file := os.NewFile(uintptr(readFD), node.path)
			err = scanUnitFile(s.ctx, file, node, s.buf)
			cerr := file.Close()
			if err != nil {
				return err
			}
			return cerr
		}
		_ = unix.Close(fd)
		fd = next
	}
	return fmt.Errorf("%w: empty canonical snapshot path", ErrConflict)
}

func scanUnitFile(ctx context.Context, file *os.File, node *snapNode, buf []byte) error {
	if node == nil || !node.hasContent {
		return fmt.Errorf("%w: snapshot file has no content digest", ErrConflict)
	}
	if node.size < 0 || node.size > maxSnapshotUnitFile {
		return fmt.Errorf("%w: snapshot file %s exceeds size limit", ErrUnsupported, node.path)
	}
	hasher := sha256.New()
	var guard legacyIncludeGuard
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := file.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > node.size {
				return fmt.Errorf("%w: snapshot file changed while scanning", ErrConflict)
			}
			if guard.scan(buf[:n]) {
				return fmt.Errorf("%w: legacy .include definitions are not bound; use drop-ins", ErrUnsupported)
			}
			_, _ = hasher.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: snapshot file changed while scanning: %w", ErrConflict, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if total != node.size {
		return fmt.Errorf("%w: snapshot file length does not match metadata", ErrConflict)
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return err
	}
	if !metaMatches(node, after) {
		return fmt.Errorf("%w: snapshot file changed while scanning", ErrConflict)
	}
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	if sum != node.content {
		return fmt.Errorf("%w: snapshot file changed while scanning", ErrConflict)
	}
	return nil
}

func (s *session) readRegular(parentFD int, name, path string, before unix.Stat_t, class pathClass) ([32]byte, byte, []byte, error) {
	var zero [32]byte
	if err := s.ctx.Err(); err != nil {
		return zero, 0, nil, err
	}
	limit := readLimit(class)
	if before.Size < 0 || before.Size > limit {
		return zero, 0, nil, fmt.Errorf("%w: snapshot file %s exceeds size limit", ErrUnsupported, path)
	}
	readFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return zero, 0, nil, fmt.Errorf("%w: snapshot file %s: %w", ErrConflict, path, err)
	}
	file := os.NewFile(uintptr(readFD), path)
	var out *os.File
	if s.dest != nil {
		out, err = s.dest.createExclusive(path, destFileMode(before.Mode))
		if err != nil {
			_ = file.Close()
			return zero, 0, nil, err
		}
	}
	sum, labelClass, label, err := s.copyRegular(file, out, before, class, limit)
	cerr := file.Close()
	if out != nil {
		if err == nil {
			err = finishDestFile(out, destFileMode(before.Mode), labelClass, label)
		}
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return zero, 0, nil, err
	}
	if cerr != nil {
		return zero, 0, nil, cerr
	}
	return sum, labelClass, label, nil
}

func (s *session) copyRegular(file, out *os.File, before unix.Stat_t, class pathClass, limit int64) ([32]byte, byte, []byte, error) {
	var zero [32]byte
	var opened unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
		return zero, 0, nil, err
	}
	if !sameMeta(before, opened) {
		return zero, 0, nil, fmt.Errorf("%w: snapshot file changed during open", ErrConflict)
	}
	labelClass, label, err := readSELinuxFD(int(file.Fd()))
	if err != nil {
		return zero, 0, nil, err
	}
	hasher := sha256.New()
	var guard legacyIncludeGuard
	scanGuard := class&classUnit != 0
	var total int64
	for {
		if err := s.ctx.Err(); err != nil {
			return zero, 0, nil, err
		}
		n, err := file.Read(s.buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return zero, 0, nil, fmt.Errorf("%w: snapshot file exceeds size limit", ErrUnsupported)
			}
			if total > before.Size {
				return zero, 0, nil, fmt.Errorf("%w: snapshot file length does not match metadata", ErrConflict)
			}
			if scanGuard && guard.scan(s.buf[:n]) {
				return zero, 0, nil, fmt.Errorf("%w: legacy .include definitions are not bound; use drop-ins", ErrUnsupported)
			}
			_, _ = hasher.Write(s.buf[:n])
			if out != nil {
				if _, werr := out.Write(s.buf[:n]); werr != nil {
					return zero, 0, nil, werr
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, 0, nil, fmt.Errorf("%w: snapshot file changed while reading: %w", ErrConflict, err)
		}
	}
	if err := s.ctx.Err(); err != nil {
		return zero, 0, nil, err
	}
	if total != before.Size {
		return zero, 0, nil, fmt.Errorf("%w: snapshot file length does not match metadata", ErrConflict)
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return zero, 0, nil, err
	}
	if !sameMeta(before, after) {
		return zero, 0, nil, fmt.Errorf("%w: snapshot file changed while reading", ErrConflict)
	}
	labelClass2, label2, err := readSELinuxFD(int(file.Fd()))
	if err != nil {
		return zero, 0, nil, err
	}
	if labelClass != labelClass2 || !bytes.Equal(label, label2) {
		return zero, 0, nil, fmt.Errorf("%w: snapshot SELinux label changed", ErrConflict)
	}
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum, labelClass, label, nil
}

func readlinkPinnedParent(parentFD int, name string) (string, error) {
	buf := make([]byte, maxDefinitionPath+1)
	n, err := unix.Readlinkat(parentFD, name, buf)
	if err != nil {
		return "", err
	}
	if n <= 0 || n > maxDefinitionPath {
		return "", fmt.Errorf("%w: invalid snapshot symlink target", ErrUnsupported)
	}
	return string(buf[:n]), nil
}

func selinuxFromDir(dirFD int) (byte, []byte, error) {
	readFD, err := unix.Openat(dirFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = unix.Close(readFD) }()
	return readSELinuxFD(readFD)
}

func selinuxFromName(parentFD int, name string) (byte, []byte, error) {
	if strings.ContainsAny(name, "/\x00") {
		return 0, nil, fmt.Errorf("%w: invalid snapshot component", ErrUnsupported)
	}
	proc := "/proc/self/fd/" + itoa(parentFD) + "/" + name
	return readSELinuxL(proc)
}

func selinuxFromFile(parentFD int, name string, before unix.Stat_t) (byte, []byte, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, nil, err
	}
	if st.Dev != before.Dev || st.Ino != before.Ino || st.Mode != before.Mode {
		return 0, nil, fmt.Errorf("%w: snapshot file changed during open", ErrConflict)
	}
	return readSELinuxFD(fd)
}

func readSELinuxFD(fd int) (byte, []byte, error) {
	n, err := unix.Fgetxattr(fd, selinuxAttr, nil)
	if err != nil {
		return classifyXattrErr(err)
	}
	return readSELinuxSized(n, func(buf []byte) (int, error) {
		return unix.Fgetxattr(fd, selinuxAttr, buf)
	})
}

func readSELinuxL(path string) (byte, []byte, error) {
	n, err := unix.Lgetxattr(path, selinuxAttr, nil)
	if err != nil {
		return classifyXattrErr(err)
	}
	return readSELinuxSized(n, func(buf []byte) (int, error) {
		return unix.Lgetxattr(path, selinuxAttr, buf)
	})
}

func readSELinuxSized(n int, read func([]byte) (int, error)) (byte, []byte, error) {
	if n < 0 || n > maxSnapshotLabel {
		return 0, nil, fmt.Errorf("%w: SELinux context exceeds limit", ErrUnsupported)
	}
	buf := make([]byte, n)
	got, err := read(buf)
	if err != nil {
		if errors.Is(err, unix.ERANGE) {
			return 0, nil, fmt.Errorf("%w: SELinux context changed while reading", ErrConflict)
		}
		return classifyXattrErr(err)
	}
	if got != n {
		return 0, nil, fmt.Errorf("%w: SELinux context changed while reading", ErrConflict)
	}
	return snapLabelPresent, buf, nil
}

func classifyXattrErr(err error) (byte, []byte, error) {
	switch {
	case errors.Is(err, unix.ENODATA):
		return snapLabelAbsent, nil, nil
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOTSUP):
		return snapLabelUnsupported, nil, nil
	default:
		return 0, nil, fmt.Errorf("%w: read SELinux label: %w", ErrUnsupported, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	neg := n < 0
	u := uint(n)
	if neg {
		u = uint(-n)
	}
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
