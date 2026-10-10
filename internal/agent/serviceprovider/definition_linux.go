//go:build linux

package serviceprovider

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

const (
	maxDefinitionFiles = 65 // one fragment and at most 64 ordered drop-ins
	maxDefinitionBytes = 1 << 20
	maxDefinitionTotal = 4 << 20
	maxDefinitionPath  = 4096
	maxSymlinks        = 40
)

func definitionHash(ctx context.Context, fragment string, dropIns []string) ([]byte, error) {
	if fragment == "" || len(dropIns) >= maxDefinitionFiles {
		return nil, fmt.Errorf("%w: missing fragment or too many drop-ins", ErrUnsupported)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.systemd.definition.v1\x00"))
	writeLength(h, uint64(1+len(dropIns)))
	var total int64
	var buffer [32 * 1024]byte
	for index := 0; index <= len(dropIns); index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := fragment
		if index > 0 {
			path = dropIns[index-1]
		}
		file, canonical, stat, err := openProtectedFile(path, maxDefinitionBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: unsafe definition %q: %w", ErrUnsupported, path, err)
		}
		total += stat.Size
		if total > maxDefinitionTotal {
			_ = file.Close()
			return nil, fmt.Errorf("%w: total definition bytes exceed limit", ErrUnsupported)
		}
		// Bind the systemd-reported path, its safely resolved target, ordering,
		// and exact bytes, with unambiguous framing between all fields.
		writeLength(h, uint64(len(path)))
		_, _ = io.WriteString(h, path)
		writeLength(h, uint64(len(canonical)))
		_, _ = io.WriteString(h, canonical)
		writeLength(h, uint64(stat.Size))
		err = hashFile(ctx, h, file, stat, buffer[:])
		closeErr := file.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return h.Sum(nil), nil
}

func writeLength(h hash.Hash, value uint64) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], value)
	_, _ = h.Write(length[:])
}

func hashFile(ctx context.Context, h hash.Hash, file *os.File, before unix.Stat_t, buffer []byte) error {
	remaining := before.Size
	var include legacyIncludeGuard
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		size := min(int64(len(buffer)), remaining)
		n, err := io.ReadFull(file, buffer[:size])
		if err != nil {
			return fmt.Errorf("%w: definition changed while reading: %w", ErrConflict, err)
		}
		if include.scan(buffer[:n]) {
			return fmt.Errorf("%w: legacy .include definitions are not bound; use drop-ins", ErrUnsupported)
		}
		_, _ = h.Write(buffer[:n])
		remaining -= int64(n)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A regular file can expose bytes beyond st_size (for example procfs).
	// Require actual EOF: metadata stability alone does not bind those bytes.
	if _, err := io.ReadFull(file, buffer[:1]); err != io.EOF {
		return fmt.Errorf("%w: definition length does not match metadata", ErrConflict)
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return err
	}
	if after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
		after.Mode != before.Mode || after.Uid != before.Uid || after.Gid != before.Gid ||
		after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return fmt.Errorf("%w: definition changed while reading", ErrConflict)
	}
	return nil
}

// Legacy systemd accepts .include before section dispatch and can load files
// absent from FragmentPath/DropInPaths. Refuse the directive rather than hash
// an incomplete definition. This screens physical-line prefixes, not INI values
// or install semantics. It conservatively rejects prefixes in continuations too.
// Native continuation folding inserts a space, so it cannot assemble the token
// from separate lines. v239 read_line also treats NUL as a physical delimiter.
type legacyIncludeGuard uint8

func (g *legacyIncludeGuard) scan(data []byte) bool {
	const (
		token   = ".include"
		ignored = 255
		bomEF   = 254
		bomBB   = 253
	)
	for _, c := range data {
		switch {
		case c == '\n' || c == 0:
			*g = 0
		case *g == ignored:
			continue
		case *g == bomEF:
			*g = ignored
			if c == 0xbb {
				*g = bomBB
			}
		case *g == bomBB:
			*g = ignored
			if c == 0xbf {
				*g = 0
			}
		case *g == 0 && (c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'):
			continue
		case *g == 0 && c == 0xef:
			*g = bomEF
		case c == token[*g]:
			*g++
			if int(*g) == len(token) {
				return true
			}
		default:
			*g = ignored
		}
	}
	return false
}

// openProtectedFile resolves even vendor /lib symlinks without following any
// unchecked directory. Each link is pinned with O_PATH|O_NOFOLLOW and read via
// its own descriptor; both the original and resolved ancestry must be trusted.
// Unlike private agent state, these files may be world-readable but may never
// have a non-root owner or ancestry writable outside root's group (even sticky dirs).
func openProtectedFile(path string, maxBytes int64) (*os.File, string, unix.Stat_t, error) {
	var zero unix.Stat_t
	if maxBytes <= 0 || !strings.HasPrefix(path, "/") || strings.ContainsRune(path, '\x00') || len(path) > maxDefinitionPath {
		return nil, "", zero, fmt.Errorf("invalid absolute definition path")
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", zero, err
	}
	fd := root
	defer func() { _ = unix.Close(fd) }()
	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil {
		return nil, "", zero, err
	}
	if !custody.TrustedDirectory(&rootStat) {
		return nil, "", zero, fmt.Errorf("untrusted root directory")
	}
	pending := strings.Split(strings.TrimPrefix(path, "/"), "/")
	canonical := make([]string, 0, len(pending))
	symlinks := 0
	steps := 0
	for len(pending) > 0 {
		steps++
		if steps > maxDefinitionPath {
			return nil, "", zero, fmt.Errorf("definition traversal exceeds limit")
		}
		component := pending[0]
		pending = pending[1:]
		if component == "" || component == "." {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, "", zero, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(next, &stat); err != nil {
			_ = unix.Close(next)
			return nil, "", zero, err
		}
		if stat.Uid != 0 {
			_ = unix.Close(next)
			return nil, "", zero, fmt.Errorf("non-root definition path component")
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			symlinks++
			if symlinks > maxSymlinks {
				_ = unix.Close(next)
				return nil, "", zero, fmt.Errorf("too many definition symlinks")
			}
			var target [maxDefinitionPath + 1]byte
			n, err := unix.Readlinkat(next, "", target[:])
			_ = unix.Close(next)
			if err != nil {
				return nil, "", zero, err
			}
			if n == 0 || n > maxDefinitionPath {
				return nil, "", zero, fmt.Errorf("invalid definition symlink target")
			}
			value := string(target[:n])
			if strings.HasPrefix(value, "/") {
				newRoot, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
				if err != nil {
					return nil, "", zero, err
				}
				_ = unix.Close(fd)
				fd = newRoot
				canonical = canonical[:0]
			}
			pending = append(strings.Split(value, "/"), pending...)
			continue
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if !custody.TrustedDirectory(&stat) {
				_ = unix.Close(next)
				return nil, "", zero, fmt.Errorf("writable definition directory")
			}
			_ = unix.Close(fd)
			fd = next
			if component == ".." {
				if len(canonical) > 0 {
					canonical = canonical[:len(canonical)-1]
				}
			} else {
				canonical = append(canonical, component)
			}
			continue
		}
		if len(pending) != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 || stat.Size < 0 || stat.Size > maxBytes {
			_ = unix.Close(next)
			return nil, "", zero, fmt.Errorf("unsafe or oversized definition file")
		}
		// Reopen for reading from the same pinned parent, still with NOFOLLOW.
		// O_NONBLOCK avoids blocking if root replaces a regular file with a FIFO.
		readFD, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		_ = unix.Close(next)
		if err != nil {
			return nil, "", zero, err
		}
		var opened unix.Stat_t
		if err := unix.Fstat(readFD, &opened); err != nil {
			_ = unix.Close(readFD)
			return nil, "", zero, err
		}
		if opened.Dev != stat.Dev || opened.Ino != stat.Ino || opened.Mode != stat.Mode || opened.Uid != stat.Uid || opened.Size != stat.Size {
			_ = unix.Close(readFD)
			return nil, "", zero, fmt.Errorf("definition changed during open")
		}
		canonical = append(canonical, component)
		resolved := "/" + strings.Join(canonical, "/")
		if len(resolved) > maxDefinitionPath {
			_ = unix.Close(readFD)
			return nil, "", zero, fmt.Errorf("resolved definition path exceeds limit")
		}
		return os.NewFile(uintptr(readFD), resolved), resolved, opened, nil
	}
	return nil, "", zero, fmt.Errorf("definition is not a regular file")
}
