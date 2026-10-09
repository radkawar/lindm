//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	snapshotWideEnv     = "LINDM_SNAPSHOT_DEST_WIDE"
	snapshotWideSrcEnv  = "LINDM_SNAPSHOT_DEST_SRC"
	snapshotWideDstEnv  = "LINDM_SNAPSHOT_DEST_DST"
	snapshotWideOutEnv  = "LINDM_SNAPSHOT_DEST_OUT"
	snapshotWideDirs    = 256
	snapshotWideFDSlack = 32
)

func TestSnapshotDestWideTreeLowFD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("wide snapshot capture requires root")
	}
	src := t.TempDir()
	if err := os.Chmod(src, 0755); err != nil {
		t.Fatal(err)
	}
	writeWideTree(t, src, snapshotWideDirs)
	dst := t.TempDir()
	if err := os.Chmod(dst, 0700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "result")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSnapshotDestWideTreeLowFDChild$", "-test.count=1", "-test.v")
	child.Env = append(os.Environ(),
		snapshotWideEnv+"=1",
		snapshotWideSrcEnv+"="+src,
		snapshotWideDstEnv+"="+dst,
		snapshotWideOutEnv+"="+out,
	)
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("low-fd capture: %v\n%s", err, output)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("child result: %v\n%s", err, output)
	}
	var limit int
	var digestText string
	if _, err := fmt.Sscanf(string(body), "%d\n%s\n", &limit, &digestText); err != nil {
		t.Fatalf("child result %q: %v", body, err)
	}
	if limit >= snapshotWideDirs {
		t.Fatalf("child rlimit %d did not bound %d directories", limit, snapshotWideDirs)
	}
	raw, err := hex.DecodeString(digestText)
	if err != nil || len(raw) != 32 {
		t.Fatalf("child digest %q: %v", digestText, err)
	}
	srcFD, err := unix.Open(src, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(srcFD) }()
	finger, err := fingerprintInstallSnapshotRoot(context.Background(), srcFD, wideSnapshotInputs())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(finger[:], raw) {
		t.Fatalf("child digest %x != parent fingerprint %x", raw, finger[:])
	}
	for i := range snapshotWideDirs {
		got := readRegularNoFollow(t, dst, wideRel(i))
		if !bytes.Equal(got, widePayload(i)) {
			t.Fatalf("captured %s = %q", wideRel(i), got)
		}
	}
}

func TestSnapshotDestWideTreeLowFDChild(t *testing.T) {
	if os.Getenv(snapshotWideEnv) != "1" {
		return
	}
	src := os.Getenv(snapshotWideSrcEnv)
	dst := os.Getenv(snapshotWideDstEnv)
	out := os.Getenv(snapshotWideOutEnv)
	if src == "" || dst == "" || out == "" {
		t.Fatal("missing wide-tree fixture paths")
	}
	srcFD, err := unix.Open(src, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(srcFD) }()
	dest, err := os.OpenRoot(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dest.Close() }()
	limit := lowerSnapshotFDLimit(t, snapshotWideDirs)
	ctx := context.Background()
	inputs := wideSnapshotInputs()
	finger, err := fingerprintInstallSnapshotRoot(ctx, srcFD, inputs)
	if err != nil {
		t.Fatalf("fingerprint under rlimit %d: %v", limit, err)
	}
	captured, err := captureInstallSnapshotRoot(ctx, srcFD, dest, inputs)
	if err != nil {
		t.Fatalf("capture under rlimit %d: %v", limit, err)
	}
	if finger != captured {
		t.Fatalf("digest mismatch under rlimit %d: finger %x captured %x", limit, finger, captured)
	}
	for i := range snapshotWideDirs {
		got := readRegularNoFollow(t, dst, wideRel(i))
		if !bytes.Equal(got, widePayload(i)) {
			t.Fatalf("payload %d = %q", i, got)
		}
	}
	body := fmt.Sprintf("%d\n%x\n", limit, captured[:])
	if err := os.WriteFile(out, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotDestSymlinkSubstitutionRefuses(t *testing.T) {
	destDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Chmod(outside, 0755); err != nil {
		t.Fatal(err)
	}
	outsideInfo, err := os.Lstat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(destDir, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(destDir, "up")); err != nil {
		t.Fatal(err)
	}
	escapeName := "lindm-dest-follow-" + filepath.Base(destDir)
	escapePath := filepath.Join(filepath.Dir(destDir), escapeName)
	if _, err := os.Lstat(escapePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escape path precondition: %v", err)
	}
	d := openTestDest(t, destDir)
	defer d.close()
	before := countOpenFDs(t)

	err = d.ensureDir("/alias")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("ensureDir followed symlink: %v", err)
	}
	after, err := os.Lstat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != outsideInfo.Mode() {
		t.Fatalf("followed symlink changed outside mode %v -> %v", outsideInfo.Mode(), after.Mode())
	}
	if _, err := os.Lstat(filepath.Join(outside, "child")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ensureDir created %s: %v", filepath.Join(outside, "child"), err)
	}
	if err := d.ensureDir("/up/" + escapeName); !errors.Is(err, ErrConflict) {
		t.Fatalf("relative symlink substitution: %v", err)
	}
	if _, err := os.Lstat(escapePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("relative symlink escaped to %s: %v", escapePath, err)
	}
	if _, err := d.createExclusive("/alias/escaped", 0600); !errors.Is(err, ErrConflict) {
		t.Fatalf("createExclusive followed symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "escaped")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("createExclusive wrote outside: %v", err)
	}
	origin, err := d.createExclusive("/origin", 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := origin.Write([]byte("origin")); err != nil {
		_ = origin.Close()
		t.Fatal(err)
	}
	if err := origin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.link("/origin", "/alias/cloned"); !errors.Is(err, ErrConflict) {
		t.Fatalf("link followed symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "cloned")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link wrote outside: %v", err)
	}
	if err := d.setDirLabel("/alias", snapLabelPresent, []byte("system_u:object_r:tmp_t:s0")); !errors.Is(err, ErrConflict) {
		t.Fatalf("setDirLabel followed symlink: %v", err)
	}
	s := &session{
		ctx:  context.Background(),
		dest: d,
		nodes: map[string]*snapNode{
			"/alias/planted": {kind: kindSymlink, target: "/outside/raw", selClass: snapLabelNone},
		},
	}
	if err := s.writeSymlinks(); !errors.Is(err, ErrConflict) {
		t.Fatalf("writeSymlinks followed symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "planted")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writeSymlinks wrote outside: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "origin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "origin" {
		t.Fatalf("origin bytes = %q", got)
	}
	if countOpenFDs(t) != before {
		t.Fatalf("fd leak: before %d after %d", before, countOpenFDs(t))
	}
}

func TestSnapshotDestWalkCreatesAndLinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	d := openTestDest(t, dir)
	defer d.close()
	before := countOpenFDs(t)
	file, err := d.createExclusive("/sub/file", 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("payload")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.link("/sub/file", "/sub/clone"); err != nil {
		t.Fatal(err)
	}
	if err := d.setDirLabel("/sub", snapLabelNone, nil); err != nil {
		t.Fatal(err)
	}
	got := readRegularNoFollow(t, dir, "sub/file")
	clone := readRegularNoFollow(t, dir, "sub/clone")
	if !bytes.Equal(got, []byte("payload")) || !bytes.Equal(clone, got) {
		t.Fatalf("file %q clone %q", got, clone)
	}
	if _, err := d.createExclusive("/sub/file", 0600); err == nil {
		t.Fatal("exclusive create replaced an existing file")
	}
	if countOpenFDs(t) != before {
		t.Fatalf("fd leak: before %d after %d", before, countOpenFDs(t))
	}
}

func TestSnapshotDestRejectsEscapeAndDepth(t *testing.T) {
	dir := t.TempDir()
	d := openTestDest(t, dir)
	defer d.close()
	name := "lindm-dest-escape-" + filepath.Base(dir)
	escape := filepath.Join(filepath.Dir(dir), name)
	if _, err := os.Lstat(escape); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	before := countOpenFDs(t)
	if err := d.ensureDir("/../" + name); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dotdot ensureDir: %v", err)
	}
	if _, err := d.createExclusive("/../"+name, 0600); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dotdot create: %v", err)
	}
	if _, err := os.Lstat(escape); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dotdot escaped to %s: %v", escape, err)
	}
	parts := make([]string, maxSnapshotDepth+1)
	for i := range parts {
		parts[i] = "a"
	}
	if err := d.ensureDir("/" + strings.Join(parts, "/")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("deep path: %v", err)
	}
	if countOpenFDs(t) != before {
		t.Fatalf("fd leak: before %d after %d", before, countOpenFDs(t))
	}
}

func TestSnapshotWriteSymlinksHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &session{
		ctx:  ctx,
		dest: &destWriter{rootFD: -1},
		nodes: map[string]*snapNode{
			"/etc/alias": {kind: kindSymlink, target: "/etc/systemd"},
		},
	}
	err := s.writeSymlinks()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled symlink plant: %v", err)
	}
}

func TestSnapshotDirEmptyMatchesDirectory(t *testing.T) {
	dir := t.TempDir()
	fd := openDirFD(t, dir)
	empty, err := dirEmpty(fd)
	_ = unix.Close(fd)
	if err != nil || !empty {
		t.Fatalf("empty dir: empty=%v err=%v", empty, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	fd = openDirFD(t, dir)
	defer func() { _ = unix.Close(fd) }()
	empty, err = dirEmpty(fd)
	if err != nil || empty {
		t.Fatalf("occupied dir: empty=%v err=%v", empty, err)
	}
	// Rewind by reopening; dirEmpty consumed the first fd's offset.
	_ = unix.Close(fd)
	fd = openDirFD(t, dir)
	var names []string
	buf := make([]byte, 4096)
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		names, _, err = parseSnapshotDirents(buf[:n], names, true, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !sameNames(names, []string{"nested", "payload"}) {
		t.Fatalf("dirents %q", names)
	}
}

func TestParseSnapshotDirentsRejectsMalformed(t *testing.T) {
	if _, _, err := parseSnapshotDirents([]byte{0, 1, 2}, nil, false, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("short buffer: %v", err)
	}
	reclenOff := int(unsafe.Offsetof(unix.Dirent{}.Reclen))
	buf := make([]byte, reclenOff+2)
	binary.NativeEndian.PutUint16(buf[reclenOff:], uint16(len(buf)+8))
	consumed, count, _ := unix.ParseDirent(buf, -1, nil)
	if consumed != len(buf) || count != 0 {
		t.Fatalf("ParseDirent fixture changed: consumed=%d count=%d len=%d", consumed, count, len(buf))
	}
	if _, saw, err := parseSnapshotDirents(buf, nil, false, nil); err == nil || saw || !errors.Is(err, ErrConflict) {
		t.Fatalf("invalid reclen: saw=%v err=%v", saw, err)
	}
	binary.NativeEndian.PutUint16(buf[reclenOff:], 0)
	if _, _, err := parseSnapshotDirents(buf, nil, true, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("zero reclen: %v", err)
	}
	if snapshotDirentReclenSz != 2 || snapshotDirentInoSz != 8 {
		t.Fatalf("dirent field size reclen=%d ino=%d", snapshotDirentReclenSz, snapshotDirentInoSz)
	}
	nameOff := int(snapshotDirentNameOff)
	raw := make([]byte, nameOff+4)
	binary.NativeEndian.PutUint16(raw[int(snapshotDirentReclenOff):], uint16(len(raw)))
	binary.NativeEndian.PutUint64(raw[int(snapshotDirentInoOff):], 1)
	for i := nameOff; i < len(raw); i++ {
		raw[i] = 'a'
	}
	if _, _, err := parseSnapshotDirents(raw, nil, true, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("unterminated name: %v", err)
	}
}

func wideSnapshotInputs() InstallSnapshotInputs {
	return InstallSnapshotInputs{UnitPaths: []string{"/wide"}}
}

func writeWideTree(t *testing.T, root string, n int) {
	t.Helper()
	wide := filepath.Join(root, "wide")
	if err := os.Mkdir(wide, 0755); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		dir := filepath.Join(wide, fmt.Sprintf("d%04d", i))
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "payload"), widePayload(i), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func wideRel(i int) string {
	return fmt.Sprintf("wide/d%04d/payload", i)
}

func widePayload(i int) []byte {
	return []byte(fmt.Sprintf("wide-%04d\n", i))
}

func lowerSnapshotFDLimit(t *testing.T, width int) int {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	open := countOpenFDs(t)
	want := uint64(open + snapshotWideFDSlack)
	if want >= uint64(width) {
		t.Fatalf("open fds %d leave no gap under width %d", open, width)
	}
	if want > lim.Max {
		t.Fatalf("RLIMIT_NOFILE max %d cannot hold walk headroom %d", lim.Max, want)
	}
	lim.Cur = want
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	return int(want)
}

func openTestDest(t *testing.T, dir string) *destWriter {
	t.Helper()
	fd := openDirFD(t, dir)
	return &destWriter{rootFile: os.NewFile(uintptr(fd), dir), rootFD: fd}
}

func openDirFD(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	f, err := os.Open("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 1 {
		t.Fatal("empty /proc/self/fd")
	}
	return len(names) - 1
}

func readRegularNoFollow(t *testing.T, root, rel string) []byte {
	t.Helper()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			t.Fatalf("unsafe relative path %q", rel)
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i != len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		t.Fatalf("%s is not a regular file", rel)
	}
	file := os.NewFile(uintptr(fd), rel)
	buf, err := io.ReadAll(file)
	cerr := file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if cerr != nil {
		t.Fatal(cerr)
	}
	return buf
}

func sameNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, name := range got {
		seen[name]++
	}
	for _, name := range want {
		seen[name]--
		if seen[name] < 0 {
			return false
		}
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
