//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInstallRuntimeFilesRejectsContext(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InstallRuntimeFiles(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	if _, err := InstallRuntimeFiles(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired context: %v", err)
	}
}

func TestInstallRuntimeFilesProtectedDiscovery(t *testing.T) {
	program, err := openRuntimeFile(systemctlPath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		t.Skip("protected systemctl is not readable here")
	}
	if err != nil {
		t.Fatal(err)
	}
	interpreter, static, interpErr := elfInterpreter(program)
	closeErr := program.Close()
	if interpErr != nil {
		t.Fatal(interpErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	paths, err := InstallRuntimeFiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 || !slices.IsSorted(paths) {
		t.Fatalf("runtime paths = %q", paths)
	}
	for i := 1; i < len(paths); i++ {
		if paths[i-1] >= paths[i] {
			t.Fatalf("runtime paths not strictly unique: %q", paths)
		}
	}
	if !slices.Contains(paths, systemctlPath) {
		t.Fatalf("original program path missing: %q", paths)
	}
	if static {
		if len(paths) != 1 {
			t.Fatalf("static runtime returned %q", paths)
		}
		return
	}
	if interpreter == "" || !slices.Contains(paths, interpreter) {
		t.Fatalf("interpreter %q missing from %q", interpreter, paths)
	}
	for _, path := range paths {
		if isVirtualDSO(path) || strings.Contains(path, "\x00") || !validRuntimePath(path) {
			t.Fatalf("discovered path is not an original filesystem path: %q", path)
		}
		file, canonical, stat, err := openProtectedFile(path, maxRuntimeBytes)
		if err != nil {
			t.Fatalf("discovered path %q: %v", path, err)
		}
		_ = file.Close()
		if canonical == "" || stat.Uid != 0 || stat.Size <= 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG {
			t.Fatalf("discovered path %q is not a protected regular file", path)
		}
	}
}

func TestRuntimeSourcePathsStayOriginal(t *testing.T) {
	got := runtimeSourcePaths(systemctlPath, "/lib64/ld-linux-x86-64.so.2", []string{
		"/lib/../libc.so.6",
		"/lib//libc.so.6",
		"/lib64/ld-linux-x86-64.so.2",
		"/usr/lib/libz.so.1",
	})
	want := []string{
		"/lib/../libc.so.6",
		"/lib//libc.so.6",
		"/lib64/ld-linux-x86-64.so.2",
		systemctlPath,
		"/usr/lib/libz.so.1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	if slices.Contains(runtimeSourcePaths(systemctlPath, "", nil), "") {
		t.Fatal("static runtime invented an interpreter path")
	}
}

func TestRuntimeFileRefusesPrivilegedOrEmpty(t *testing.T) {
	regular := unix.Stat_t{Size: 1, Mode: unix.S_IFREG | 0755}
	if err := runtimeFileStat(regular); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []uint32{unix.S_ISUID, unix.S_ISGID} {
		if err := runtimeFileStat(unix.Stat_t{Size: 1, Mode: unix.S_IFREG | 0755 | mode}); err == nil {
			t.Fatalf("privileged mode %o accepted", mode)
		}
	}
	if err := runtimeFileStat(unix.Stat_t{Mode: unix.S_IFREG | 0755}); err == nil {
		t.Fatal("empty runtime file accepted")
	}
}

func TestLoaderResultBoundaries(t *testing.T) {
	stdout := &boundedCapture{limit: 4}
	stderr := &boundedCapture{limit: 4}
	if _, err := stdout.Write([]byte("abc")); err != nil || stdout.exceeded || stdout.buf.String() != "abc" {
		t.Fatalf("bounded write changed a short listing: exceeded=%v %q", stdout.exceeded, stdout.buf.Bytes())
	}
	if _, err := stdout.Write([]byte("def")); err != nil || !stdout.exceeded || stdout.buf.String() != "abcd" {
		t.Fatalf("overflow was not retained as a bounded prefix: exceeded=%v %q", stdout.exceeded, stdout.buf.Bytes())
	}
	if _, err := classifyLoaderResult(stdout, stderr, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("truncated listing: %v", err)
	}
	stdout = &boundedCapture{limit: 8}
	_, _ = stdout.Write([]byte("ok\n"))
	stderr = &boundedCapture{limit: 8}
	_, _ = stderr.Write([]byte("warn"))
	if _, err := classifyLoaderResult(stdout, stderr, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("diagnostics accepted: %v", err)
	}
	stderr = &boundedCapture{limit: 8}
	runErr := errors.New("loader exited")
	if _, err := classifyLoaderResult(stdout, stderr, runErr); !errors.Is(err, ErrUnsupported) || !errors.Is(err, runErr) {
		t.Fatalf("nonzero listing exit: %v", err)
	}
	listing, err := classifyLoaderResult(stdout, stderr, nil)
	if err != nil || string(listing) != "ok\n" {
		t.Fatalf("clean listing = %q, %v", listing, err)
	}
}

func TestParseLoaderListingBoundaries(t *testing.T) {
	valid := "" +
		"\tlinux-vdso.so.1 (0x00007c5fe2fb5000)\n" +
		"\tlinux-gate.so.1 (0x00000001)\n" +
		"\tlinux-vdso32.so.1 (0x10)\n" +
		"\tlinux-vdso64.so.1 (0x0000000000000010)\n" +
		"\tlibstdc++.so.6 => /usr/lib/libstdc++.so.6 (0x00007f0000001000)\n" +
		"\t/lib/libfoo.so.1 => /usr/lib/libfoo.so.1 (0x2)\n" +
		"\t/lib64/ld-linux-x86-64.so.2 (0x00007c5fe2fb7000)\n" +
		"\tlibcap.so.2 => /lib/x86_64-linux-gnu/libcap.so.2 (0x1)\n" +
		"\tlibcap.so.2 => /lib/x86_64-linux-gnu/libcap.so.2 (0x0000000000000001)\n"
	got, err := parseLoaderListing([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/usr/lib/libstdc++.so.6",
		"/usr/lib/libfoo.so.1",
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/x86_64-linux-gnu/libcap.so.2",
		"/lib/x86_64-linux-gnu/libcap.so.2",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("paths = %q", got)
	}
	for _, path := range got {
		if strings.Contains(path, "0x") || isVirtualDSO(path) {
			t.Fatalf("listing authority leaked into path %q", path)
		}
	}
	maxPath := "/" + strings.Repeat("a", maxDefinitionPath-1)
	accepted, err := parseLoaderListing([]byte("\tlibfoo.so.1 => " + maxPath + " (0x10)\n"))
	if err != nil || !slices.Equal(accepted, []string{maxPath}) {
		t.Fatalf("max original path = %q, %v", accepted, err)
	}
	preserved, err := parseLoaderListing([]byte("\tlibfoo.so.1 => /lib/../libc.so.6 (0xab)\n"))
	if err != nil || !slices.Equal(preserved, []string{"/lib/../libc.so.6"}) {
		t.Fatalf("original path cleaned: %q, %v", preserved, err)
	}

	rejected := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"truncated", "\t/lib64/ld-linux-x86-64.so.2 (0x1)"},
		{"overflow", strings.Repeat("\t/lib/libc.so.6 (0x1)\n", (maxRuntimeListStdout/len("\t/lib/libc.so.6 (0x1)\n"))+1)},
		{"no tab", "/lib64/ld-linux-x86-64.so.2 (0x1)\n"},
		{"not found", "\tlibmissing.so.1 => not found\n"},
		{"not found addressed", "\tlibmissing.so.1 => not found (0x0)\n"},
		{"relative", "\tlibfoo.so.1 => libfoo.so.1 (0x1)\n"},
		{"dot relative", "\tlibfoo.so.1 => ./libfoo.so.1 (0x1)\n"},
		{"unknown vdso", "\tlinux-vdso.so.2 (0x1)\n"},
		{"vdso path", "\tlinux-vdso.so.1 => /lib/linux-vdso.so.1 (0x1)\n"},
		{"uppercase hex", "\t/lib64/ld-linux-x86-64.so.2 (0xABCD)\n"},
		{"long hex", "\t/lib64/ld-linux-x86-64.so.2 (0x" + strings.Repeat("ab", 9) + ")\n"},
		{"empty hex", "\t/lib64/ld-linux-x86-64.so.2 (0x)\n"},
		{"crlf", "\t/lib64/ld-linux-x86-64.so.2 (0x1)\r\n"},
		{"blank line", "\t/lib64/ld-linux-x86-64.so.2 (0x1)\n\n"},
		{"extra field", "\t/lib64/ld-linux-x86-64.so.2 (0x1) extra\n"},
		{"space path", "\tlibfoo.so.1 => /lib/foo bar.so (0x1)\n"},
		{"shell meta", "\tlibfoo.so.1 => /lib/$(foo).so (0x1)\n"},
		{"relative direct", "\tlib64/ld-linux-x86-64.so.2 (0x1)\n"},
		{"address only", "\t(0x1)\n"},
		{"nul", "\t/lib/libc.so.6\x00 (0x1)\n"},
		{"overlong path", "\tlibfoo.so.1 => /" + strings.Repeat("a", maxDefinitionPath) + " (0x1)\n"},
		{"trailing slash", "\tlibfoo.so.1 => /lib/libc.so.6/ (0x1)\n"},
		{"double arrow", "\tlibfoo.so.1 => /lib/a.so.1 => /lib/b.so.1 (0x1)\n"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLoaderListing([]byte(tc.in))
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsupported loader listing accepted: %v", err)
			}
		})
	}
}

func TestELFInterpreterBoundaries(t *testing.T) {
	const interp = "/lib64/ld-linux-x86-64.so.2"
	segment := []byte(interp + "\x00")
	for _, class := range []byte{1, 2} {
		path, static, err := elfInterpreter(bytes.NewReader(testELF(t, class, 3, []testProg{{typ: 3, data: segment}})))
		if err != nil || static || path != interp {
			t.Fatalf("class %d interpreter = %q static=%v err=%v", class, path, static, err)
		}
	}
	path, static, err := elfInterpreter(bytes.NewReader(testELF(t, 2, 2, nil)))
	if err != nil || !static || path != "" {
		t.Fatalf("static executable = %q static=%v err=%v", path, static, err)
	}
	path, static, err = elfInterpreter(bytes.NewReader(testELF(t, 2, 3, []testProg{{typ: 1, filesz: 1}})))
	if err != nil || !static || path != "" {
		t.Fatalf("static-pie = %q static=%v err=%v", path, static, err)
	}

	maxPath := "/" + strings.Repeat("a", maxDefinitionPath-1)
	path, static, err = elfInterpreter(bytes.NewReader(testELF(t, 2, 3, []testProg{{typ: 3, data: append([]byte(maxPath), 0)}})))
	if err != nil || static || path != maxPath {
		t.Fatalf("max interpreter = %q static=%v err=%v", path, static, err)
	}

	rejected := []struct {
		name  string
		class byte
		typ   uint16
		progs []testProg
		raw   []byte
	}{
		{name: "not elf", raw: []byte("not an elf")},
		{name: "relocatable", class: 2, typ: 1},
		{name: "multiple", class: 2, typ: 3, progs: []testProg{{typ: 3, data: segment}, {typ: 3, data: segment}}},
		{name: "overlong", class: 2, typ: 3, progs: []testProg{{typ: 3, filesz: maxInterpreterSegment + 1}}},
		{name: "empty segment", class: 2, typ: 3, progs: []testProg{{typ: 3, filesz: 0}}},
		{name: "unreadable", class: 2, typ: 3, progs: []testProg{{typ: 3, filesz: 8}}},
		{name: "missing nul", class: 2, typ: 3, progs: []testProg{{typ: 3, data: []byte(interp)}}},
		{name: "extra nul", class: 2, typ: 3, progs: []testProg{{typ: 3, data: append([]byte(interp+"\x00"), 0)}}},
		{name: "interior nul", class: 2, typ: 3, progs: []testProg{{typ: 3, data: []byte("/lib\x00/ld.so\x00")}}},
		{name: "relative", class: 2, typ: 3, progs: []testProg{{typ: 3, data: []byte("lib64/ld.so\x00")}}},
		{name: "space", class: 2, typ: 3, progs: []testProg{{typ: 3, data: []byte("/lib/ld so\x00")}}},
		{name: "trailing slash", class: 2, typ: 3, progs: []testProg{{typ: 3, data: []byte("/lib64/\x00")}}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == nil {
				raw = testELF(t, tc.class, tc.typ, tc.progs)
			}
			if _, _, err := elfInterpreter(bytes.NewReader(raw)); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsupported interpreter accepted: %v", err)
			}
		})
	}
}

type testProg struct {
	typ    uint32
	filesz uint64
	data   []byte
}

func testELF(t *testing.T, class byte, typ uint16, progs []testProg) []byte {
	t.Helper()
	ehsize, phentsize := 52, 32
	if class == 2 {
		ehsize, phentsize = 64, 56
	} else if class != 1 {
		t.Fatalf("ELF class %d", class)
	}
	phoff := 0
	if len(progs) > 0 {
		phoff = ehsize
	}
	dataOff := ehsize + len(progs)*phentsize
	var buf bytes.Buffer
	ident := make([]byte, 16)
	ident[0], ident[1], ident[2], ident[3] = 0x7f, 'E', 'L', 'F'
	ident[4], ident[5], ident[6] = class, 1, 1
	buf.Write(ident)
	writeELF := func(v any) {
		t.Helper()
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	writeELF(typ)
	writeELF(uint16(62))
	if class == 1 {
		writeELF(uint32(1))
		writeELF(uint32(0))
		writeELF(uint32(phoff))
		writeELF(uint32(0))
		writeELF(uint32(0))
	} else {
		writeELF(uint32(1))
		writeELF(uint64(0))
		writeELF(uint64(phoff))
		writeELF(uint64(0))
		writeELF(uint32(0))
	}
	writeELF(uint16(ehsize))
	writeELF(uint16(phentsize))
	writeELF(uint16(len(progs)))
	writeELF(uint16(0))
	writeELF(uint16(0))
	writeELF(uint16(0))
	if buf.Len() != ehsize {
		t.Fatalf("ELF header size %d, want %d", buf.Len(), ehsize)
	}
	payload := make([]byte, 0)
	for _, prog := range progs {
		filesz := prog.filesz
		if filesz == 0 && len(prog.data) > 0 {
			filesz = uint64(len(prog.data))
		}
		writeELF(prog.typ)
		if class == 2 {
			writeELF(uint32(4))
			writeELF(uint64(dataOff))
			writeELF(uint64(0))
			writeELF(uint64(0))
			writeELF(filesz)
			writeELF(filesz)
			writeELF(uint64(1))
		} else {
			writeELF(uint32(dataOff))
			writeELF(uint32(0))
			writeELF(uint32(0))
			writeELF(uint32(filesz))
			writeELF(uint32(filesz))
			writeELF(uint32(4))
			writeELF(uint32(1))
		}
		if len(prog.data) > 0 {
			payload = append(payload, prog.data...)
		}
	}
	if len(progs) > 0 && buf.Len() != dataOff {
		t.Fatalf("program header end %d, want %d", buf.Len(), dataOff)
	}
	buf.Write(payload)
	return buf.Bytes()
}
