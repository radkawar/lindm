// SPDX-License-Identifier: Apache-2.0

//go:build linux

package custody

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenResolved opens a root-owned regular file, resolving even vendor /lib
// symlinks without following any
// unchecked directory. Each link is pinned with O_PATH|O_NOFOLLOW and read via
// its own descriptor; both the original and resolved ancestry must be trusted.
// Unlike private agent state, these files may be world-readable but may never
// have a non-root owner or ancestry writable outside root's group (even sticky dirs).
//
// maxBytes bounds the reported file size; maxPath bounds input, resolved and link
// target lengths and traversal steps, and must be in [1, unix.PathMax].
// maxSymlinks bounds followed links. The caller owns the returned readable file;
// the other results are its canonical absolute path and metadata at open time.
// Callers must bound reads and check stability separately.
func OpenResolved(path string, maxBytes int64, maxPath, maxSymlinks int) (*os.File, string, unix.Stat_t, error) {
	return openResolved(path, maxBytes, maxPath, maxSymlinks, false)
}

// OpenResolvedRoot applies OpenResolved's pinned symlink traversal with the
// stricter RootProtected directory rule: group zero may not replace any
// original or resolved ancestor. Link metadata itself only requires UID zero;
// its root-protected parent prevents replacement.
func OpenResolvedRoot(path string, maxBytes int64, maxPath, maxSymlinks int) (*os.File, string, unix.Stat_t, error) {
	return openResolved(path, maxBytes, maxPath, maxSymlinks, true)
}

func openResolved(path string, maxBytes int64, maxPath, maxSymlinks int, rootOnly bool) (*os.File, string, unix.Stat_t, error) {
	var zero unix.Stat_t
	if maxPath <= 0 || maxPath > unix.PathMax || maxBytes <= 0 || !strings.HasPrefix(path, "/") || strings.ContainsRune(path, '\x00') || len(path) > maxPath {
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
	if !TrustedDirectory(&rootStat) || (rootOnly && !RootProtected(&rootStat)) {
		return nil, "", zero, fmt.Errorf("untrusted root directory")
	}
	pending := strings.Split(strings.TrimPrefix(path, "/"), "/")
	canonical := make([]string, 0, len(pending))
	symlinks := 0
	steps := 0
	for len(pending) > 0 {
		steps++
		if steps > maxPath {
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
			var target [unix.PathMax + 1]byte
			n, err := unix.Readlinkat(next, "", target[:maxPath+1])
			_ = unix.Close(next)
			if err != nil {
				return nil, "", zero, err
			}
			if n == 0 || n > maxPath {
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
			if !TrustedDirectory(&stat) || (rootOnly && !RootProtected(&stat)) {
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
		if len(resolved) > maxPath {
			_ = unix.Close(readFD)
			return nil, "", zero, fmt.Errorf("resolved definition path exceeds limit")
		}
		return os.NewFile(uintptr(readFD), resolved), resolved, opened, nil
	}
	return nil, "", zero, fmt.Errorf("definition is not a regular file")
}
