//go:build linux

package fileprovider

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// initramfsBlocklist reads newc archives without extracting paths or allocating
// the archive. Early uncompressed microcode and concatenated gzip/zstd members
// are supported. Other formats fail closed rather than imply boot persistence.
func initramfsBlocklist(path string) (image, content []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 512<<20 {
		return nil, nil, ErrUnsupported
	}
	hash := sha256.New()
	input := bufio.NewReader(io.TeeReader(io.LimitReader(f, (512<<20)+1), hash))
	var total int64
	paths := moduleArchivePaths{links: make(map[string]string)}
	for {
		for {
			prefix, peekErr := input.Peek(1)
			if errors.Is(peekErr, io.EOF) {
				if total == 0 {
					return nil, nil, ErrUnsupported
				}
				after, statErr := f.Stat()
				if statErr != nil {
					return nil, nil, statErr
				}
				if !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() {
					return nil, nil, ErrConflict
				}
				return hash.Sum(nil), content, nil
			}
			if peekErr != nil {
				return nil, nil, peekErr
			}
			if prefix[0] != 0 {
				break
			}
			if _, err := input.Discard(1); err != nil {
				return nil, nil, err
			}
		}
		prefix, err := input.Peek(6)
		if err != nil {
			return nil, nil, err
		}
		var archive io.Reader = input
		var closeReader func() error
		switch {
		case bytes.HasPrefix(prefix, []byte("070701")):
		case bytes.HasPrefix(prefix, []byte{0x1f, 0x8b}):
			reader, err := gzip.NewReader(input)
			if err != nil {
				return nil, nil, err
			}
			reader.Multistream(false)
			archive, closeReader = reader, reader.Close
		case bytes.HasPrefix(prefix, []byte{0x28, 0xb5, 0x2f, 0xfd}):
			reader, err := zstd.NewReader(input, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
			if err != nil {
				return nil, nil, err
			}
			archive = reader
			closeReader = func() error { reader.Close(); return nil }
		default:
			return nil, nil, fmt.Errorf("%w: unsupported initramfs compression", ErrUnsupported)
		}
		var found []byte
		var consumed int64
		var scanErr error
		if closeReader == nil {
			found, consumed, scanErr = readModuleArchive(archive, &paths)
		} else {
			found, consumed, scanErr = readCompressedModuleArchives(archive, (2<<30)-total, &paths)
			scanErr = errors.Join(scanErr, closeReader())
		}
		total += consumed
		if scanErr != nil {
			return nil, nil, scanErr
		}
		if total > 2<<30 {
			return nil, nil, ErrUnsupported
		}
		if found != nil {
			if content != nil {
				return nil, nil, fmt.Errorf("%w: duplicate initramfs blocklist", ErrConflict)
			}
			content = found
		}
	}
}

func readModuleArchive(r io.Reader, paths *moduleArchivePaths) ([]byte, int64, error) {
	var total int64
	var found []byte
	var header [110]byte
	var nameBuffer [4096]byte
	for range 262144 {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, total, err
		}
		total += 110
		if string(header[:6]) != "070701" {
			return nil, total, ErrUnsupported
		}
		mode, err := strconv.ParseUint(string(header[14:22]), 16, 32)
		if err != nil {
			return nil, total, err
		}
		size, err := strconv.ParseUint(string(header[54:62]), 16, 32)
		if err != nil {
			return nil, total, err
		}
		nameSize, err := strconv.ParseUint(string(header[94:102]), 16, 32)
		if err != nil || nameSize == 0 || nameSize > 4096 || size > 2<<30 || total+int64(size) > 2<<30 {
			return nil, total, ErrUnsupported
		}
		name := nameBuffer[:nameSize]
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, total, err
		}
		padding := (4 - (110+nameSize)%4) % 4
		if _, err := io.CopyN(io.Discard, r, int64(padding)); err != nil {
			return nil, total, err
		}
		total += int64(nameSize + padding)
		if name[len(name)-1] != 0 || bytes.IndexByte(name[:len(name)-1], 0) >= 0 {
			return nil, total, ErrUnsupported
		}
		raw := strings.TrimPrefix(string(name[:len(name)-1]), "./")
		if raw == "" || path.IsAbs(raw) || path.Clean(raw) != raw || raw == ".." || strings.HasPrefix(raw, "../") {
			return nil, total, ErrUnsupported
		}
		member := "/" + raw
		if raw == "." {
			member = "/"
		}
		if member == "/TRAILER!!!" {
			if size != 0 {
				return nil, total, ErrUnsupported
			}
			return found, total, nil
		}
		parent, err := paths.resolve(path.Dir(member))
		if err != nil {
			return nil, total, err
		}
		resolved := path.Join(parent, path.Base(member))
		if member != resolved && protectedModuleArchivePath(resolved) {
			return nil, total, ErrUnsupported
		}
		member = resolved
		if (member == "/" || member == "/etc" || member == "/etc/modprobe.d") && mode&0170000 != 0040000 {
			return nil, total, ErrUnsupported
		}
		if member == "/etc" {
			paths.etc = true
		}
		if member == "/etc/modprobe.d" {
			if !paths.etc {
				return nil, total, ErrUnsupported
			}
			paths.modprobe = true
		}
		if _, exists := paths.links[member]; exists {
			final, err := paths.resolve(member)
			if err != nil || protectedModuleArchivePath(final) {
				return nil, total, ErrUnsupported
			}
		}
		paths.removeLink(member)
		if member == ModuleBlocklistPath {
			links, err := strconv.ParseUint(string(header[38:46]), 16, 32)
			if err != nil || links != 1 || mode&0170000 != 0100000 || size > 32768 || found != nil || !paths.modprobe {
				return nil, total, ErrUnsupported
			}
			hash := sha256.New()
			if _, err := io.CopyN(hash, r, int64(size)); err != nil {
				return nil, total, err
			}
			found = hash.Sum(nil)
		} else if mode&0170000 == 0120000 {
			if size == 0 || size > uint64(len(nameBuffer)) {
				return nil, total, ErrUnsupported
			}
			target := nameBuffer[:size]
			if _, err := io.ReadFull(r, target); err != nil {
				return nil, total, err
			}
			if bytes.IndexByte(target, 0) >= 0 {
				return nil, total, ErrUnsupported
			}
			if err := paths.addLink(member, string(target)); err != nil {
				return nil, total, err
			}
		} else if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
			return nil, total, err
		}
		padding = (4 - size%4) % 4
		if _, err := io.CopyN(io.Discard, r, int64(padding)); err != nil {
			return nil, total, err
		}
		total += int64(size + padding)
	}
	return nil, total, ErrUnsupported
}

func readCompressedModuleArchives(r io.Reader, limit int64, paths *moduleArchivePaths) ([]byte, int64, error) {
	input := bufio.NewReader(io.LimitReader(r, limit+1))
	var found []byte
	var total int64
	archives := 0
	for total <= limit {
		prefix, err := input.Peek(1)
		if errors.Is(err, io.EOF) {
			if archives == 0 {
				return nil, total, ErrUnsupported
			}
			return found, total, nil
		}
		if err != nil {
			return nil, total, err
		}
		if prefix[0] == 0 {
			if _, err := input.Discard(1); err != nil {
				return nil, total, err
			}
			total++
			continue
		}
		next, n, err := readModuleArchive(input, paths)
		total += n
		if err != nil {
			return nil, total, err
		}
		archives++
		if next != nil {
			if found != nil {
				return nil, total, ErrConflict
			}
			found = next
		}
	}
	return nil, total, ErrUnsupported
}

// Only the protected stanza's identity is relevant, but parent aliases can
// reach it from anywhere in the archive. Keep bounded symlink state across all
// compressed members; resolve '..' after links, as pathname lookup does.
type moduleArchivePaths struct {
	links         map[string]string
	linkBytes     int
	etc, modprobe bool
}

func protectedModuleArchivePath(name string) bool {
	return name == "/" || name == "/etc" || name == "/etc/modprobe.d" || strings.HasPrefix(name, "/etc/modprobe.d/")
}

func (p *moduleArchivePaths) resolve(name string) (string, error) {
	current := "/"
	followed := 0
	for name != "" {
		part, rest, _ := strings.Cut(name, "/")
		name = rest
		switch part {
		case "", ".":
			continue
		case "..":
			current = path.Dir(current)
			continue
		}
		parent := current
		current = path.Join(current, part)
		if target, ok := p.links[current]; ok {
			followed++
			if followed > 40 || len(target)+len(name) > 8192 {
				return "", ErrUnsupported
			}
			current = parent
			if path.IsAbs(target) {
				current = "/"
			}
			name = target + "/" + name
		}
	}
	return current, nil
}

func (p *moduleArchivePaths) removeLink(member string) {
	if old, ok := p.links[member]; ok {
		p.linkBytes -= len(member) + len(old)
		delete(p.links, member)
	}
}

func (p *moduleArchivePaths) addLink(member, target string) error {
	name := target
	if !path.IsAbs(target) {
		name = path.Dir(member) + "/" + target
	}
	resolved, err := p.resolve(name)
	if err != nil {
		return err
	}
	if protectedModuleArchivePath(resolved) || len(p.links) >= 8192 || p.linkBytes+len(member)+len(target) > 4<<20 {
		return ErrUnsupported
	}
	p.links[member] = target
	p.linkBytes += len(member) + len(target)
	return nil
}
