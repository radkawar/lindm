//go:build linux

package serviceprovider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestSnapshotRuntimeAncestorDoesNotWaiveUnitLimits(t *testing.T) {
	t.Run("include sibling", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		writeRuntimeAncestorTree(t, fixture)
		if err := os.WriteFile(filepath.Join(fixture, "tree/units/bad.service"), []byte(".include /unbound.conf\n"), 0644); err != nil {
			t.Fatal(err)
		}
		err := fingerprintRuntimeAncestor(fd)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("legacy include beside runtime input accepted: %v", err)
		}
	})
	t.Run("oversized sibling", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		writeRuntimeAncestorTree(t, fixture)
		writeSized(t, filepath.Join(fixture, "tree/units/big.service"), int64(maxSnapshotUnitFile)+1)
		err := fingerprintRuntimeAncestor(fd)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("oversized unit sibling of runtime input accepted: %v", err)
		}
	})
	t.Run("bounded sibling", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		writeRuntimeAncestorTree(t, fixture)
		if err := os.WriteFile(filepath.Join(fixture, "tree/units/ok.service"), []byte("[Service]\nExecStart=/bin/true\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := fingerprintRuntimeAncestor(fd); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSnapshotSharedRuntimeInodeKeepsUnitCap(t *testing.T) {
	t.Run("same path", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		writeSized(t, filepath.Join(fixture, "tool"), int64(maxSnapshotUnitFile)+1)
		_, err := fingerprintInstallSnapshotRoot(context.Background(), fd, InstallSnapshotInputs{
			RuntimeFiles: []string{"/tool"},
			ContextFiles: []string{"/tool"},
		})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("shared runtime/context file over 1MiB accepted: %v", err)
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		if err := os.Mkdir(filepath.Join(fixture, "units"), 0755); err != nil {
			t.Fatal(err)
		}
		tool := filepath.Join(fixture, "tool")
		writeSized(t, tool, int64(maxSnapshotUnitFile)+1)
		if err := os.Link(tool, filepath.Join(fixture, "units/tool")); err != nil {
			t.Fatal(err)
		}
		_, err := fingerprintInstallSnapshotRoot(context.Background(), fd, InstallSnapshotInputs{
			RuntimeFiles: []string{"/tool"},
			UnitPaths:    []string{"/units"},
		})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unit hardlink of oversized runtime file accepted: %v", err)
		}
	})
	t.Run("small same path", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		if err := os.WriteFile(filepath.Join(fixture, "tool"), []byte("ok"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := fingerprintInstallSnapshotRoot(context.Background(), fd, InstallSnapshotInputs{
			RuntimeFiles: []string{"/tool"},
			ContextFiles: []string{"/tool"},
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSnapshotUnitBudgetCountsUniqueBytes(t *testing.T) {
	t.Run("hardlinks once", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		dir := filepath.Join(fixture, "units")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		first := filepath.Join(dir, "link-00")
		writeSized(t, first, maxSnapshotUnitFile)
		for i := 1; i < 33; i++ {
			if err := os.Link(first, filepath.Join(dir, fmt.Sprintf("link-%02d", i))); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := fingerprintInstallSnapshotRoot(context.Background(), fd, InstallSnapshotInputs{UnitPaths: []string{"/units"}}); err != nil {
			t.Fatalf("unique hardlink bytes were charged per name: %v", err)
		}
	})
	t.Run("distinct aggregate", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		dir := filepath.Join(fixture, "units")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for i := range 32 {
			writeSized(t, filepath.Join(dir, fmt.Sprintf("a-%02d", i)), maxSnapshotUnitFile)
		}
		writeSized(t, filepath.Join(dir, "b-extra"), 1)
		_, err := fingerprintInstallSnapshotRoot(context.Background(), fd, InstallSnapshotInputs{UnitPaths: []string{"/units"}})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unit aggregate over 32MiB accepted: %v", err)
		}
	})
}

func TestSnapshotRejectsDeepUnitRecursion(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	ctx := context.Background()
	if err := os.Mkdir(filepath.Join(fixture, "ok"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "ok/leaf.service"), []byte("[Service]\nExecStart=/bin/true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{UnitPaths: []string{"/ok"}}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(fixture, "deep")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for range maxSnapshotDepth {
		dir = filepath.Join(dir, "d")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "leaf.service"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, InstallSnapshotInputs{UnitPaths: []string{"/deep"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("deep unit tree accepted: %v", err)
	}
}

func TestSnapshotUnitSymlinkCycleTerminates(t *testing.T) {
	fd, fixture := snapshotFixture(t)
	dir := filepath.Join(fixture, "units")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.service"), []byte("[Service]\nExecStart=/bin/true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dest := snapshotDest(t)
	if _, err := captureInstallSnapshotRoot(context.Background(), fd, dest, InstallSnapshotInputs{UnitPaths: []string{"/units"}}); err != nil {
		t.Fatal(err)
	}
	assertLink(t, dest, "units/a", "b")
	assertLink(t, dest, "units/b", "a")
	got, err := dest.ReadFile("units/ok.service")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "[Service]\nExecStart=/bin/true\n" {
		t.Fatalf("unit bytes = %q", got)
	}
}

func TestSnapshotRejectsSymlinkAncestorOfPrivateNamespace(t *testing.T) {
	t.Run("real var directory", func(t *testing.T) {
		fd, fixture := snapshotFixture(t)
		if err := os.MkdirAll(filepath.Join(fixture, "var/log"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, "var/log/x"), []byte("kept"), 0644); err != nil {
			t.Fatal(err)
		}
		dest := snapshotDest(t)
		if _, err := captureInstallSnapshotRoot(context.Background(), fd, dest, InstallSnapshotInputs{ContextFiles: []string{"/var/log/x"}}); err != nil {
			t.Fatal(err)
		}
		got, err := dest.ReadFile("var/log/x")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "kept" {
			t.Fatalf("real /var file = %q", got)
		}
	})
	for _, prefix := range []string{"var", "run"} {
		t.Run(prefix, func(t *testing.T) {
			fd, fixture := snapshotFixture(t)
			target := filepath.Join(fixture, "usr", prefix, "log")
			if err := os.MkdirAll(target, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "x"), []byte("hidden"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("usr/"+prefix, filepath.Join(fixture, prefix)); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			inputs := InstallSnapshotInputs{ContextFiles: []string{"/" + prefix + "/log/x"}}
			if _, err := fingerprintInstallSnapshotRoot(ctx, fd, inputs); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("symlink ancestor /%s accepted: %v", prefix, err)
			}
			dest := snapshotDest(t)
			if _, err := captureInstallSnapshotRoot(ctx, fd, dest, inputs); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("symlink ancestor /%s captured: %v", prefix, err)
			}
			if _, err := dest.Lstat(prefix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("private ancestor symlink was projected: %v", err)
			}
		})
	}
}

func TestSnapshotNestedRootBindDotDot(t *testing.T) {
	if os.Getenv("LINDM_SNAPSHOT_REEXEC") != "nested-root-bind" {
		reexecIsolatedMount(t, "nested-root-bind")
		return
	}
	if err := isolateMountNamespace(); err != nil {
		reexecSkip("isolated mount namespace requires CAP_SYS_ADMIN: " + err.Error())
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "only"), []byte("ROOTONLY"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "sub/only"), []byte("SIBLING"), 0644); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(base, "sub/loop")
	if err := os.Mkdir(loop, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(base, loop, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind logical root: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(loop, 0); err != nil {
			t.Errorf("unmount nested root bind: %v", err)
		}
	})
	fd, err := unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	ctx := context.Background()
	inputs := InstallSnapshotInputs{ContextFiles: []string{"/sub/loop/../only"}}
	dest := snapshotDest(t)
	finger, err := fingerprintInstallSnapshotRoot(ctx, fd, inputs)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureInstallSnapshotRoot(ctx, fd, dest, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if captured != finger {
		t.Fatal("capture digest differs from fingerprint")
	}
	got, err := dest.ReadFile("sub/only")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SIBLING" {
		t.Fatalf("dotdot left the nested root bind at the wrong file: %q", got)
	}
	if _, err := dest.Lstat("sub/loop/only"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walker clamped inside the nested root bind: %v", err)
	}
	if _, err := dest.Lstat("only"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root-only file was captured for a sibling path: %v", err)
	}
	finishReexec(t)
}

func TestSnapshotRejectsDirectoryBindCycle(t *testing.T) {
	if os.Getenv("LINDM_SNAPSHOT_REEXEC") != "bind-cycle" {
		reexecIsolatedMount(t, "bind-cycle")
		return
	}
	if err := isolateMountNamespace(); err != nil {
		reexecSkip("isolated mount namespace requires CAP_SYS_ADMIN: " + err.Error())
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	units := filepath.Join(base, "units")
	if err := os.Mkdir(units, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(units, "demo.service"), []byte("[Service]\nExecStart=/bin/true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(units, "loop")
	if err := os.Mkdir(loop, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(units, loop, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind directory onto descendant: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(loop, 0); err != nil {
			t.Errorf("unmount directory bind cycle: %v", err)
		}
	})
	fd, err := unix.Open(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	ctx := context.Background()
	inputs := InstallSnapshotInputs{UnitPaths: []string{"/units"}}
	if _, err := fingerprintInstallSnapshotRoot(ctx, fd, inputs); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("bind-mount cycle fingerprint: %v", err)
	}
	dest := snapshotDest(t)
	if _, err := captureInstallSnapshotRoot(ctx, fd, dest, inputs); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("bind-mount cycle capture: %v", err)
	}
	if _, err := dest.Lstat("units/loop/loop"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bind cycle was copied into the destination: %v", err)
	}
	finishReexec(t)
}

func TestSnapshotDirentParseRejectsIncompleteRecords(t *testing.T) {
	keep := snapshotDirent(7, "keep")
	dot := snapshotDirent(1, ".")
	dotdot := snapshotDirent(2, "..")
	gone := snapshotDirent(0, "gone")
	buf := append(append(append(dot, dotdot...), gone...), keep...)
	next, saw, err := parseSnapshotDirents(buf, nil, true, nil)
	if err != nil || !saw || len(next) != 1 || next[0] != "keep" {
		t.Fatalf("valid dirent = %v saw=%v err=%v", next, saw, err)
	}
	_, saw, err = parseSnapshotDirents(buf, nil, false, nil)
	if err != nil || !saw {
		t.Fatalf("count-only dirent saw=%v err=%v", saw, err)
	}
	onlyDot, saw, err := parseSnapshotDirents(dot, nil, true, nil)
	if err != nil || saw || len(onlyDot) != 0 {
		t.Fatalf("dot dirent = %v saw=%v err=%v", onlyDot, saw, err)
	}

	overlong := make([]byte, 32)
	binary.NativeEndian.PutUint16(overlong[direntReclenOff():], 1000)
	if _, _, err := parseSnapshotDirents(overlong, nil, true, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlong reclen accepted: %v", err)
	}
	trailing := append(append([]byte(nil), keep...), 1, 2, 3, 4)
	if _, _, err := parseSnapshotDirents(trailing, nil, true, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("truncated trailing dirent accepted: %v", err)
	}
}

func writeRuntimeAncestorTree(t *testing.T, fixture string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(fixture, "tree/bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture, "tree/units"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "tree/bin/helper"), []byte("helper"), 0644); err != nil {
		t.Fatal(err)
	}
}

func fingerprintRuntimeAncestor(fd int) error {
	_, err := fingerprintInstallSnapshotRoot(context.Background(), fd, InstallSnapshotInputs{
		RuntimeFiles: []string{"/tree/bin/helper"},
		UnitPaths:    []string{"/tree"},
	})
	return err
}

func writeSized(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func reexecIsolatedMount(t *testing.T, mode string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("isolated mount namespace requires root")
	}
	result := filepath.Join(t.TempDir(), "reexec-result")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	parentNamespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.timeout=45s")
	// Create the namespace before exec, so every Go runtime thread inherits it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	cmd.Env = append(os.Environ(), "LINDM_SNAPSHOT_REEXEC="+mode, "LINDM_SNAPSHOT_RESULT="+result, "LINDM_SNAPSHOT_PARENT_NS="+parentNamespace)
	out, err := cmd.CombinedOutput()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
		t.Skipf("isolated mount namespace unavailable: %v", err)
	}
	data, readErr := os.ReadFile(result)
	if readErr == nil && bytes.HasPrefix(data, []byte("skip\n")) {
		t.Skip(strings.TrimSpace(string(data[len("skip\n"):])))
	}
	if err != nil {
		t.Fatalf("reexec %s: %v\n%s", mode, err, out)
	}
	if readErr != nil || string(data) != "ok\n" {
		t.Fatalf("reexec %s did not report success: %v\n%s", mode, readErr, out)
	}
}

func isolateMountNamespace() error {
	parentNamespace := os.Getenv("LINDM_SNAPSHOT_PARENT_NS")
	namespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || parentNamespace == "" || namespace == parentNamespace {
		return fmt.Errorf("mount regression is not in a distinct namespace: %v", err)
	}
	if err := unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private mount propagation: %w", err)
	}
	return nil
}

func reexecSkip(reason string) {
	if path := os.Getenv("LINDM_SNAPSHOT_RESULT"); path != "" {
		_ = os.WriteFile(path, []byte("skip\n"+reason), 0600)
	}
	os.Exit(0)
}

func finishReexec(t *testing.T) {
	t.Helper()
	path := os.Getenv("LINDM_SNAPSHOT_RESULT")
	if path == "" {
		t.Fatal("missing reexec result path")
	}
	if err := os.WriteFile(path, []byte("ok\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func snapshotDirent(ino uint64, name string) []byte {
	namoff := int(unsafe.Offsetof(unix.Dirent{}.Name))
	reclen := (namoff + len(name) + 1 + 7) &^ 7
	buf := make([]byte, reclen)
	binary.NativeEndian.PutUint64(buf[int(unsafe.Offsetof(unix.Dirent{}.Ino)):], ino)
	binary.NativeEndian.PutUint16(buf[direntReclenOff():], uint16(reclen))
	copy(buf[namoff:], name)
	return buf
}

func direntReclenOff() int {
	return int(unsafe.Offsetof(unix.Dirent{}.Reclen))
}
