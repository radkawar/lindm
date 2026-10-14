// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
)

const (
	systemctlPath           = "/usr/bin/systemctl"
	maxRuntimeBytes         = 64 << 20
	maxRuntimeListStdout    = 64 << 10
	maxRuntimeListStderr    = 32 << 10
	runtimeDiscoveryTimeout = 10 * time.Second
	// PT_INTERP is the absolute path plus exactly one trailing NUL.
	maxInterpreterSegment = maxDefinitionPath + 1
	maxLoaderLine         = 2*maxDefinitionPath + 64
)

// InstallRuntimeFiles discovers the fixed /usr/bin/systemctl runtime closure.
// It returns that program, its ELF interpreter, and loader-resolved DSO source
// paths as sorted unique original strings. Paths are not lexical-cleaned and
// are not replaced by canonical targets.
//
// A static ELF returns the program only. A dynamic ELF is not executed. Its
// protected interpreter is invoked only as "<interpreter> --list /usr/bin/systemctl"
// with a fixed C locale, working directory /, no inherited environment, and a
// deadline of at most 10s. Listing text is not native effect authority.
//
// The result does not qualify optional dlopen closures, package immutability,
// source snapshot stability, native install effects, or any distribution.
// Capture must revalidate every returned path and byte.
func InstallRuntimeFiles(ctx context.Context) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrUnsupported)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, runtimeDiscoveryTimeout)
	defer cancel()

	program, err := openRuntimeFile(systemctlPath)
	if err != nil {
		return nil, err
	}
	interpreter, static, err := elfInterpreter(program)
	closeErr := program.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if static {
		return runtimeSourcePaths(systemctlPath, "", nil), nil
	}
	if err := protectRuntimeELF(interpreter); err != nil {
		return nil, err
	}
	listing, err := runLoaderList(ctx, interpreter)
	if err != nil {
		return nil, err
	}
	discovered, err := parseLoaderListing(listing)
	if err != nil {
		return nil, err
	}
	paths := runtimeSourcePaths(systemctlPath, interpreter, discovered)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if path == systemctlPath || path == interpreter {
			continue
		}
		if err := protectRuntimeELF(path); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func openRuntimeFile(path string) (*os.File, error) {
	file, _, stat, err := custody.OpenResolved(path, maxRuntimeBytes, maxDefinitionPath, maxSymlinks)
	if err != nil {
		return nil, fmt.Errorf("%w: unsafe runtime file %q: %w", ErrUnsupported, path, err)
	}
	if err := runtimeFileStat(stat); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: unsafe runtime file %q: %w", ErrUnsupported, path, err)
	}
	return file, nil
}

func runtimeFileStat(stat unix.Stat_t) error {
	// custody.OpenResolved already requires a root-owned, non-writable regular
	// file. Refuse modes that would change privileges if this path is executed.
	if stat.Size <= 0 || stat.Mode&unix.S_ISUID != 0 || stat.Mode&unix.S_ISGID != 0 {
		return fmt.Errorf("refusing empty or privileged runtime file")
	}
	return nil
}

func protectRuntimeELF(path string) error {
	file, err := openRuntimeFile(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	parsed, err := elf.NewFile(file)
	if err != nil {
		return fmt.Errorf("%w: runtime file %q is not ELF: %w", ErrUnsupported, path, err)
	}
	defer func() { _ = parsed.Close() }()
	if parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN {
		return fmt.Errorf("%w: runtime file %q ELF type %s", ErrUnsupported, path, parsed.Type)
	}
	return nil
}

// elfInterpreter reads one PT_INTERP from a protected executable. static is
// true only when the ELF is ET_EXEC or ET_DYN and has no interpreter.
func elfInterpreter(file io.ReaderAt) (interpreter string, static bool, err error) {
	parsed, err := elf.NewFile(file)
	if err != nil {
		return "", false, fmt.Errorf("%w: systemctl is not ELF: %w", ErrUnsupported, err)
	}
	defer func() { _ = parsed.Close() }()
	if parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN {
		return "", false, fmt.Errorf("%w: systemctl ELF type %s", ErrUnsupported, parsed.Type)
	}
	var segment []byte
	seen := 0
	for _, prog := range parsed.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		seen++
		if seen > 1 {
			return "", false, fmt.Errorf("%w: multiple ELF interpreters", ErrUnsupported)
		}
		if prog.Filesz == 0 || prog.Filesz > maxInterpreterSegment {
			return "", false, fmt.Errorf("%w: ELF interpreter length", ErrUnsupported)
		}
		segment = make([]byte, prog.Filesz)
		if _, err := io.ReadFull(prog.Open(), segment); err != nil {
			return "", false, fmt.Errorf("%w: ELF interpreter unreadable: %w", ErrUnsupported, err)
		}
	}
	if seen == 0 {
		return "", true, nil
	}
	path, err := interpreterPath(segment)
	if err != nil {
		return "", false, err
	}
	return path, false, nil
}

func interpreterPath(segment []byte) (string, error) {
	if len(segment) < 2 || segment[len(segment)-1] != 0 || bytes.IndexByte(segment, 0) != len(segment)-1 {
		return "", fmt.Errorf("%w: ELF interpreter is not exactly NUL-terminated", ErrUnsupported)
	}
	path := string(segment[:len(segment)-1])
	if !validRuntimePath(path) {
		return "", fmt.Errorf("%w: ELF interpreter is not an absolute path", ErrUnsupported)
	}
	return path, nil
}

func runLoaderList(ctx context.Context, interpreter string) ([]byte, error) {
	// The interpreter string comes from the protected PT_INTERP, never from
	// caller argv. Refuse anything that is not the same absolute-path grammar
	// before exec. This does not run systemctl or a shell.
	if !validRuntimePath(interpreter) {
		return nil, fmt.Errorf("%w: refusing interpreter %q", ErrUnsupported, interpreter)
	}
	// The whole discovery shares runtimeDiscoveryTimeout through ctx; the
	// explicit per-call bound is the same, so the earlier of the two applies.
	result, err := nativeexec.Run(ctx, nativeexec.Command{
		Path:        interpreter,
		Args:        []string{"--list", systemctlPath},
		Timeout:     runtimeDiscoveryTimeout,
		StdoutLimit: maxRuntimeListStdout,
		StderrLimit: maxRuntimeListStderr,
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return classifyLoaderResult(result, err)
}

func classifyLoaderResult(result nativeexec.Result, runErr error) ([]byte, error) {
	if result.StdoutTruncated || result.StderrTruncated {
		return nil, fmt.Errorf("%w: loader listing exceeded limit", ErrUnsupported)
	}
	if runErr != nil {
		return nil, fmt.Errorf("%w: loader listing command failed: %w", ErrUnsupported, runErr)
	}
	// Diagnostics are not an alternate listing. A clean --list writes none.
	if len(result.Stderr) != 0 {
		return nil, fmt.Errorf("%w: loader listing wrote diagnostics", ErrUnsupported)
	}
	return result.Stdout, nil
}

// parseLoaderListing accepts only the observed loader --list forms:
//
//	<TAB> name " => " absolute-path " (0x" hex ")"
//	<TAB> absolute-path " (0x" hex ")"
//	<TAB> virtual-dso " (0x" hex ")"
//
// virtual-dso is linux-vdso.so.1, linux-gate.so.1, linux-vdso32.so.1, or
// linux-vdso64.so.1 and contributes no filesystem path. hex is 1..16
// lowercase digits and is not authority. Missing libraries, unknown lines,
// and truncated output fail.
func parseLoaderListing(stdout []byte) ([]string, error) {
	if len(stdout) == 0 {
		return nil, fmt.Errorf("%w: empty loader listing", ErrUnsupported)
	}
	if len(stdout) > maxRuntimeListStdout {
		return nil, fmt.Errorf("%w: loader listing exceeded limit", ErrUnsupported)
	}
	if bytes.Contains(stdout, []byte{0}) {
		return nil, fmt.Errorf("%w: malformed loader listing", ErrUnsupported)
	}
	if stdout[len(stdout)-1] != '\n' {
		return nil, fmt.Errorf("%w: truncated loader listing", ErrUnsupported)
	}
	lines := bytes.Split(stdout, []byte{'\n'})
	lines = lines[:len(lines)-1]
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		path, keep, err := parseLoaderLine(string(line))
		if err != nil {
			return nil, err
		}
		if keep {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func parseLoaderLine(line string) (string, bool, error) {
	if line == "" || line[0] != '\t' || len(line) > maxLoaderLine || strings.ContainsRune(line, '\r') {
		return "", false, fmt.Errorf("%w: malformed loader listing", ErrUnsupported)
	}
	body := line[1:]
	if strings.Contains(body, "not found") {
		return "", false, fmt.Errorf("%w: missing loader library", ErrUnsupported)
	}
	rest, ok := cutLoaderAddress(body)
	if !ok || rest == "" {
		return "", false, fmt.Errorf("%w: malformed loader listing", ErrUnsupported)
	}
	if isVirtualDSO(rest) {
		return "", false, nil
	}
	name, target, mapped := strings.Cut(rest, " => ")
	if mapped {
		if strings.Contains(target, " => ") || !validRuntimeName(name) || !validRuntimePath(target) {
			return "", false, fmt.Errorf("%w: malformed loader listing", ErrUnsupported)
		}
		return target, true, nil
	}
	if !validRuntimePath(rest) {
		return "", false, fmt.Errorf("%w: malformed loader listing", ErrUnsupported)
	}
	return rest, true, nil
}

func cutLoaderAddress(body string) (string, bool) {
	const prefix = " (0x"
	if len(body) < len(prefix)+2 || body[len(body)-1] != ')' {
		return "", false
	}
	open := strings.LastIndex(body, prefix)
	if open < 1 {
		return "", false
	}
	hexDigits := body[open+len(prefix) : len(body)-1]
	if len(hexDigits) < 1 || len(hexDigits) > 16 {
		return "", false
	}
	for i := range len(hexDigits) {
		c := hexDigits[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return body[:open], true
}

func isVirtualDSO(name string) bool {
	switch name {
	case "linux-vdso.so.1", "linux-gate.so.1", "linux-vdso32.so.1", "linux-vdso64.so.1":
		return true
	default:
		return false
	}
}

func validRuntimePath(path string) bool {
	return len(path) >= 2 && len(path) <= maxDefinitionPath && path[0] == '/' && path[len(path)-1] != '/' && validRuntimeToken(path)
}

func validRuntimeName(name string) bool {
	return name != "" && len(name) <= maxDefinitionPath && !isVirtualDSO(name) && validRuntimeToken(name)
}

func validRuntimeToken(value string) bool {
	for i := range len(value) {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '.' || c == '_' || c == '-' || c == '+':
		default:
			return false
		}
	}
	return true
}

func runtimeSourcePaths(program, interpreter string, discovered []string) []string {
	paths := make([]string, 0, 2+len(discovered))
	if program != "" {
		paths = append(paths, program)
	}
	if interpreter != "" {
		paths = append(paths, interpreter)
	}
	paths = append(paths, discovered...)
	slices.Sort(paths)
	paths = slices.Compact(paths)
	return append([]string(nil), paths...)
}
