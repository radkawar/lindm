//go:build linux

package sysctlprovider

import (
	"bufio"
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

	resourcev1 "lindm/gen/lindm/resource/v1"
)

const maxGraphBytes = 4 << 20

type configFile struct {
	path   string
	data   []byte
	masked bool
}
type persistence struct {
	value    *string
	source   *string
	graph    []byte
	conflict bool
}

// StanzaPath is derived only from the canonical key, never an operator path.
func StanzaPath(key string) string {
	return fmt.Sprintf("/etc/sysctl.d/60-lindm-%x.conf", sha256.Sum256([]byte(key)))
}
func stanza(key, value string) []byte {
	return []byte("# Managed by lindm; ownership is recorded in the protected journal.\n" + key + " = " + value + "\n")
}

// Adopting a derived filename must not acquire unrelated kernel knobs. Preserve
// formatting/comments in the private baseline, but accept only this exact key's
// typed value assignments; neither globs nor ignored-error directives are owned.
func validateOwnedStanza(key string, data []byte) error {
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || sysctlPath(strings.TrimSpace(name)) != sysctlPath(key) {
			return ErrConflict
		}
		if err := validateMessage(&resourcev1.SysctlDesired{Key: key, Value: normalizeValue(strings.TrimSpace(value))}); err != nil {
			return errors.Join(ErrUnsupported, err)
		}
	}
	return nil
}

// sysctlPath implements systemd's first-separator rule, including interfaces
// containing dots. Desired keys have a narrower canonical dotted representation.
func sysctlPath(key string) string {
	if first := strings.IndexAny(key, "./"); first >= 0 && key[first] == '.' {
		return strings.Map(func(r rune) rune {
			if r == '.' {
				return '/'
			}
			if r == '/' {
				return '.'
			}
			return r
		}, key)
	}
	return key
}

// Numeric vectors use kernel tabs versus sysctl.d spaces. Non-numeric strings
// retain internal whitespace; hostname-like values must not be compared lossy.
func normalizeValue(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value
	}
	for _, field := range fields {
		digits := strings.TrimPrefix(strings.TrimPrefix(field, "+"), "-")
		if digits == "" {
			return value
		}
		for _, r := range digits {
			if r < '0' || r > '9' {
				return value
			}
		}
	}
	return strings.Join(fields, " ")
}

// effectivePersistence follows basename masking, lexicographic ordering and
// explicit-key exclusion from globs. Unknown or malformed syntax fails closed.
// It does not pretend that parsing configuration proves a successful reboot.
func effectivePersistence(files []configFile, key string) (persistence, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.sysctl.graph.v1\x00"))
	target := sysctlPath(key)
	type assignment struct {
		name, value, source string
		excluded            bool
	}
	var assignments []assignment
	for _, file := range files {
		_, _ = fmt.Fprintf(h, "%d:%s:%t:%d:", len(file.path), file.path, file.masked, len(file.data))
		_, _ = h.Write(file.data)
		if file.masked {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(file.data))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.ContainsRune(line, 0) || strings.HasSuffix(line, "\\") {
				return persistence{}, fmt.Errorf("%w: unsupported sysctl.d syntax", ErrUnsupported)
			}
			name, value, assigned := strings.Cut(line, "=")
			name = strings.TrimSpace(name)
			excluded := !assigned && strings.HasPrefix(name, "-")
			if !assigned && !excluded {
				return persistence{}, fmt.Errorf("%w: malformed sysctl.d assignment", ErrUnsupported)
			}
			name = strings.TrimPrefix(name, "-")
			name = sysctlPath(name)
			if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "//") || strings.ContainsAny(name, " \t\r\n") {
				return persistence{}, ErrUnsupported
			}
			for _, part := range strings.Split(name, "/") {
				if part == "." || part == ".." {
					return persistence{}, ErrUnsupported
				}
			}
			if _, err := filepath.Match(name, target); err != nil {
				return persistence{}, fmt.Errorf("%w: malformed sysctl.d glob", ErrUnsupported)
			}
			if len(assignments) >= 65536 {
				return persistence{}, ErrUnsupported
			}
			assignments = append(assignments, assignment{name: name, value: normalizeValue(strings.TrimSpace(value)), source: file.path, excluded: excluded})
		}
		if err := scanner.Err(); err != nil {
			return persistence{}, err
		}
	}
	result := persistence{graph: h.Sum(nil)}
	explicit := false
	for _, entry := range assignments {
		if entry.name == target {
			explicit = true
		}
	}
	for _, entry := range assignments {
		matches := entry.name == target
		if !explicit {
			var err error
			matches, err = filepath.Match(entry.name, target)
			if err != nil {
				return persistence{}, err
			}
		}
		if !matches {
			continue
		}
		if entry.excluded {
			result.value = nil
			result.source = nil
			continue
		}
		value, source := entry.value, entry.source
		result.value = &value
		result.source = &source
	}
	result.conflict = result.source != nil && *result.source != StanzaPath(key)
	return result, nil
}

func readPersistence(key string, replacement []byte, replace bool) (persistence, error) {
	files, err := readConfiguration()
	if err != nil {
		return persistence{}, err
	}
	if replace {
		path := StanzaPath(key)
		found := false
		for i := range files {
			if filepath.Base(files[i].path) == filepath.Base(path) {
				files[i] = configFile{path: path, data: replacement}
				found = true
				break
			}
		}
		if !found {
			files = append(files, configFile{path: path, data: replacement})
		}
		slices.SortFunc(files, func(a, b configFile) int { return strings.Compare(filepath.Base(a.path), filepath.Base(b.path)) })
	}
	return effectivePersistence(files, key)
}
func readConfiguration() ([]configFile, error) {
	seen := make(map[string]bool)
	var files []configFile
	total := 0
	for _, directory := range []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d"} {
		fd, err := openProtected(directory, unix.O_RDONLY|unix.O_DIRECTORY)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		dir := os.NewFile(uintptr(fd), directory)
		entries, readErr := dir.ReadDir(257)
		closeErr := dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, errors.Join(readErr, closeErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(entries) > 256 {
			return nil, ErrUnsupported
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".conf") || seen[name] {
				continue
			}
			seen[name] = true
			path := filepath.Join(directory, name)
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil, err
			}
			file := configFile{path: path, masked: resolved == "/dev/null"}
			if !file.masked {
				file.data, err = protectedRead(resolved, 1<<20)
				if err != nil {
					return nil, err
				}
			}
			total += len(file.data)
			if total > maxGraphBytes || len(files) >= 256 {
				return nil, ErrUnsupported
			}
			files = append(files, file)
		}
	}
	slices.SortFunc(files, func(a, b configFile) int { return strings.Compare(filepath.Base(a.path), filepath.Base(b.path)) })
	return files, nil
}

// Configuration symlinks may name root-protected files (Ubuntu's
// 99-sysctl.conf -> ../sysctl.conf), but traversal and the opened target must
// remain root-owned and non-writable by other principals.
func openProtected(path string, flags int) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, ErrUnsupported
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		mode := unix.O_RDONLY | unix.O_DIRECTORY
		if i == len(parts)-1 {
			mode = flags
		}
		next, openErr := unix.Openat2(fd, part, &unix.OpenHow{Flags: uint64(mode | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		closeErr := unix.Close(fd)
		if openErr != nil {
			return -1, errors.Join(openErr, closeErr)
		}
		fd = next
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if closeErr != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return -1, errors.Join(ErrConflict, closeErr)
		}
	}
	return fd, nil
}
func protectedRead(path string, maximum int64) ([]byte, error) {
	fd, err := openProtected(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.Join(ErrUnsupported, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, statErr, closeErr)
	}
	if int64(len(data)) > maximum || before.Ino != after.Ino || before.Dev != after.Dev || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, ErrConflict
	}
	return data, nil
}
