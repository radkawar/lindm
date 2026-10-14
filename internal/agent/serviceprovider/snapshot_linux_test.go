// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSnapshotRejectsInvalidInputs(t *testing.T) {
	ctx := context.Background()
	if _, err := CaptureInstallSnapshot(ctx, nil, InstallSnapshotInputs{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil destination: %v", err)
	}
	tooLong := "/" + string(bytes.Repeat([]byte{'a'}, maxDefinitionPath))
	for _, path := range []string{"", "relative.service", "/nul\x00", tooLong, "/proc/version", "/sys/class", "/var/lib/lindm", "/var/lib/lindm/executor", "/run/lindm/executor.sock", "//proc/cpuinfo"} {
		_, err := FingerprintInstallSnapshot(ctx, InstallSnapshotInputs{ContextFiles: []string{path}})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("path %q accepted: %v", path, err)
		}
	}
	if err := validSnapshotPath("/var/lib/lindm-extra"); err != nil {
		t.Fatalf("unrelated lindm prefix rejected: %v", err)
	}
	if err := validSnapshotPath("/processing"); err != nil {
		t.Fatalf("unrelated proc prefix rejected: %v", err)
	}
	if _, err := FingerprintInstallSnapshot(ctx, InstallSnapshotInputs{UnitPaths: make([]string, maxSnapshotUnits+1)}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unit count accepted: %v", err)
	}
	files := make([]string, maxSnapshotExplicit+1)
	for i := range files {
		files[i] = "/usr/lib/systemd/system/demo.service"
	}
	if _, err := FingerprintInstallSnapshot(ctx, InstallSnapshotInputs{RuntimeFiles: files}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("explicit path count accepted: %v", err)
	}
	if _, err := FingerprintInstallSnapshot(ctx, InstallSnapshotInputs{ContextFiles: files[:1], RuntimeFiles: files[1:]}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("explicit path count accepted: %v", err)
	}
}

func TestSnapshotCanceledBeforeWalk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := FingerprintInstallSnapshot(ctx, InstallSnapshotInputs{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fingerprint: %v", err)
	}
}

func TestSnapshotMissingPathIsStableAndNotForbidden(t *testing.T) {
	ctx := context.Background()
	inputs := InstallSnapshotInputs{ContextFiles: []string{"/processing-lindm-snapshot-missing"}}
	first, err := FingerprintInstallSnapshot(ctx, inputs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := FingerprintInstallSnapshot(ctx, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("missing-path fingerprint is not stable")
	}
	other, err := FingerprintInstallSnapshot(ctx, InstallSnapshotInputs{ContextFiles: []string{"/processing-lindm-snapshot-other"}})
	if err != nil {
		t.Fatal(err)
	}
	if first == other {
		t.Fatal("distinct missing paths produced the same digest")
	}
}

func TestSnapshotRejectsStickyWritableAncestry(t *testing.T) {
	var st unix.Stat_t
	if err := unix.Stat("/tmp", &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX == 0 {
		t.Skip("/tmp is not a sticky group/world-writable directory")
	}
	_, err := FingerprintInstallSnapshot(context.Background(), InstallSnapshotInputs{ContextFiles: []string{"/tmp/lindm-snapshot-untrusted"}})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("sticky writable ancestry accepted: %v", err)
	}
}

func TestSnapshotDestinationPreconditions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = CaptureInstallSnapshot(context.Background(), root, InstallSnapshotInputs{})
	if os.Geteuid() != 0 {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("non-root destination accepted: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("empty root destination: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "occupied"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if _, err := CaptureInstallSnapshot(context.Background(), again, InstallSnapshotInputs{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-empty destination: %v", err)
	}
}

func TestSnapshotRootFixture(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	if err := os.MkdirAll(filepath.Join(fixture, "usr/lib/systemd/system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture, "usr/lib/other"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture, "etc/systemd/system"), 0755); err != nil {
		t.Fatal(err)
	}
	unit := []byte("[Service]\nExecStart=/bin/true\n")
	if err := os.WriteFile(filepath.Join(fixture, "usr/lib/systemd/system/demo.service"), unit, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "usr/lib/other/skip.txt"), []byte("SKIP"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "marker"), []byte("INSIDE"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(fixture, "lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../usr/lib/systemd/system/demo.service", filepath.Join(fixture, "etc/systemd/system/alias.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/systemd/system/demo.service", filepath.Join(fixture, "etc/systemd/system/abs.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(fixture, "etc/systemd/system/masked.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/marker", filepath.Join(fixture, "abs-marker")); err != nil {
		t.Fatal(err)
	}
	inputs := InstallSnapshotInputs{UnitPaths: []string{"/lib/systemd/system", "/etc/systemd/system"}, ContextFiles: []string{"/abs-marker"}}
	ctx := context.Background()
	finger, err := fingerprintInstallSnapshotRoot(ctx, fd, inputs)
	if err != nil {
		t.Fatal(err)
	}
	dest := snapshotDest(t)
	captured, err := captureInstallSnapshotRoot(ctx, fd, dest, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if captured != finger {
		t.Fatal("capture digest differs from fingerprint")
	}
	assertLink(t, dest, "lib", "usr/lib")
	assertLink(t, dest, "etc/systemd/system/alias.service", "../../../usr/lib/systemd/system/demo.service")
	assertLink(t, dest, "etc/systemd/system/abs.service", "/usr/lib/systemd/system/demo.service")
	assertLink(t, dest, "etc/systemd/system/masked.service", "/dev/null")
	assertLink(t, dest, "abs-marker", "/marker")
	got, err := dest.ReadFile("usr/lib/systemd/system/demo.service")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, unit) {
		t.Fatalf("unit bytes = %q", got)
	}
	marker, err := dest.ReadFile("marker")
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != "INSIDE" {
		t.Fatalf("absolute symlink was not resolved inside the logical root: %q", marker)
	}
	if _, err := dest.Lstat("usr/lib/other/skip.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sibling outside the requested unit directory was copied: %v", err)
	}
	if _, err := dest.Lstat("dev/null"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing /dev/null was invented: %v", err)
	}
	changed := InstallSnapshotInputs{ContextFiles: []string{"/usr/lib/systemd/system/demo.service"}}
	before, err := fingerprintInstallSnapshotRoot(ctx, fd, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "usr/lib/systemd/system/demo.service"), []byte("[Service]\nExecStart=/bin/false\n"), 0644); err != nil {
		t.Fatal(err)
	}
	after, err := fingerprintInstallSnapshotRoot(ctx, fd, changed)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("changed unit bytes kept the same digest")
	}
}

func TestSnapshotMissingDiffersFromEmpty(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	ctx := context.Background()
	missing, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/absent"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "absent"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	empty, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/absent"}})
	if err != nil {
		t.Fatal(err)
	}
	if missing == empty {
		t.Fatal("missing and empty files produced the same digest")
	}
	dest := snapshotDest(t)
	if _, err := captureInstallSnapshotRoot(ctx, fd, dest, InstallSnapshotInputs{ContextFiles: []string{"/absent"}}); err != nil {
		t.Fatal(err)
	}
	info, err := dest.Lstat("absent")
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Size() != 0 {
		t.Fatalf("empty source was not materialized as an empty file: %s", info.Mode())
	}
}

func TestSnapshotClampsLogicalRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("snapshot filesystem fixture requires root")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(base, "root")
	if err := os.Mkdir(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("LEAKED"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../secret", filepath.Join(fixture, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(fixture, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../secret", filepath.Join(fixture, "sub/escape")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(fixture, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	ctx := context.Background()
	for _, path := range []string{"/escape", "/sub/escape", "/../secret"} {
		dest := snapshotDest(t)
		if _, err := captureInstallSnapshotRoot(ctx, fd, dest, InstallSnapshotInputs{ContextFiles: []string{path}}); err != nil {
			t.Fatal(path, err)
		}
		if leaked(t, dest) {
			t.Fatalf("logical root clamp leaked outside content via %s", path)
		}
	}
	root, err := os.OpenRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, _, err := resolveInstallSnapshotDirectory(root, "/../secret"); !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver escaped or failed closed incorrectly: %v", err)
	}
}

func TestSnapshotRejectsUntrustedAndForbiddenLinks(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	ctx := context.Background()
	writable := filepath.Join(fixture, "writable")
	if err := os.Mkdir(writable, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(writable, "unit.service"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/writable/unit.service"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("world-writable ancestry accepted: %v", err)
	}
	sticky := filepath.Join(fixture, "sticky")
	if err := os.Mkdir(sticky, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sticky, "unit.service"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/sticky/unit.service"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("sticky writable ancestry accepted: %v", err)
	}
	if err := os.Symlink("/proc/cpuinfo", filepath.Join(fixture, "to-proc")); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/to-proc"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("symlink into proc accepted: %v", err)
	}
	if err := os.Symlink("/var/lib/lindm/executor", filepath.Join(fixture, "to-state")); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/to-state"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("symlink into private state accepted: %v", err)
	}
}

func TestSnapshotSymlinkCycleAndIncludeGuard(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	ctx := context.Background()
	if err := os.Symlink("b", filepath.Join(fixture, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(fixture, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/a"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("symlink cycle accepted: %v", err)
	}
	if err := os.Mkdir(filepath.Join(fixture, "units"), 0755); err != nil {
		t.Fatal(err)
	}
	include := []byte(".include /unbound.conf\n")
	if err := os.WriteFile(filepath.Join(fixture, "units/bad.service"), include, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{UnitPaths: []string{"/units"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("legacy include accepted in unit tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "context.conf"), include, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{ContextFiles: []string{"/context.conf"}}); err != nil {
		t.Fatalf("context file include mention rejected: %v", err)
	}
}

func TestSnapshotPreservesObservedHardlinks(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	dir := filepath.Join(fixture, "units")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, "a.service")
	if err := os.WriteFile(original, []byte("same"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, filepath.Join(dir, "b.service")); err != nil {
		t.Fatal(err)
	}
	dest := snapshotDest(t)
	if _, err := captureInstallSnapshotRoot(context.Background(), fd, dest, InstallSnapshotInputs{UnitPaths: []string{"/units"}}); err != nil {
		t.Fatal(err)
	}
	a, err := dest.Open("units/a.service")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := dest.Open("units/b.service")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	var left, right unix.Stat_t
	if err := unix.Fstat(int(a.Fd()), &left); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(b.Fd()), &right); err != nil {
		t.Fatal(err)
	}
	if left.Dev != right.Dev || left.Ino != right.Ino {
		t.Fatalf("hardlink relationship was not preserved: %+v %+v", left, right)
	}
}

func TestResolveInstallSnapshotDirectory(t *testing.T) {
	_, fixture := snapshotFixture(t)
	if err := os.MkdirAll(filepath.Join(fixture, "usr/lib/systemd/system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(fixture, "lib")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	file, canonical, err := resolveInstallSnapshotDirectory(root, "/lib/systemd/system")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if canonical != "/usr/lib/systemd/system" {
		t.Fatalf("canonical path = %s", canonical)
	}
	var got, want unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &got); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(fixture, "usr/lib/systemd/system"), &want); err != nil {
		t.Fatal(err)
	}
	if got.Dev != want.Dev || got.Ino != want.Ino || got.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatalf("resolver did not pin the canonical directory: %+v %+v", got, want)
	}
	names, err := file.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("pinned directory was not readable: %v", names)
	}
	if _, _, err := resolveInstallSnapshotDirectory(root, "/proc/cpuinfo"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("resolver accepted special filesystem path: %v", err)
	}
}

func TestSnapshotDigestIgnoresDestination(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	if err := os.WriteFile(filepath.Join(fixture, "unit.service"), []byte("[Service]\nType=simple\n"), 0644); err != nil {
		t.Fatal(err)
	}
	inputs := InstallSnapshotInputs{ContextFiles: []string{"/unit.service"}}
	ctx := context.Background()
	finger, err := fingerprintInstallSnapshotRoot(ctx, fd, inputs)
	if err != nil {
		t.Fatal(err)
	}
	first := snapshotDest(t)
	second := snapshotDest(t)
	left, err := captureInstallSnapshotRoot(ctx, fd, first, inputs)
	if err != nil {
		t.Fatal(err)
	}
	right, err := captureInstallSnapshotRoot(ctx, fd, second, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if left != finger || right != finger {
		t.Fatal("destination identity changed the source fingerprint")
	}
}

func snapshotFixture(t *testing.T) (int, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("snapshot filesystem fixture requires root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd, dir
}

func snapshotDest(t *testing.T) *os.Root {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("snapshot filesystem fixture requires root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func assertLink(t *testing.T, root *os.Root, name, target string) {
	t.Helper()
	got, err := root.Readlink(name)
	if err != nil {
		t.Fatal(name, err)
	}
	if got != target {
		t.Fatalf("link %s = %q, want %q", name, got, target)
	}
}

func leaked(t *testing.T, root *os.Root) bool {
	t.Helper()
	var found bool
	err := walkDest(root, ".", func(path string, info os.FileInfo) error {
		if info.Mode().IsRegular() {
			buf, err := root.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(buf, []byte("LEAKED")) {
				found = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func walkDest(root *os.Root, name string, visit func(string, os.FileInfo) error) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if err := visit(name, info); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	entries, err := readDestDir(root, name)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := entry
		if name != "." {
			child = name + "/" + entry
		}
		if err := walkDest(root, child, visit); err != nil {
			return err
		}
	}
	return nil
}

func readDestDir(root *os.Root, name string) ([]string, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.Readdirnames(-1)
}
