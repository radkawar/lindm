//go:build linux

package serviceprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSnapshotFiniteRepeatedSymlinkPreservesTarget(t *testing.T) {
	fd, source := snapshotFixture(t)
	for _, name := range []string{"units", "data"} {
		if err := os.Mkdir(filepath.Join(source, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	const content = "[Service]\nExecStart=/bin/true\n"
	if err := os.WriteFile(filepath.Join(source, "data/file.service"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(source, "data/s")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/data/s/s/file.service", filepath.Join(source, "units/ref.service")); err != nil {
		t.Fatal(err)
	}
	dest := snapshotDest(t)
	inputs := InstallSnapshotInputs{UnitPaths: []string{"/units"}}
	fingerprint, err := fingerprintInstallSnapshotRoot(t.Context(), fd, inputs)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureInstallSnapshotRoot(t.Context(), fd, dest, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != captured {
		t.Fatal("capture and fingerprint disagree")
	}
	data, err := dest.ReadFile("data/file.service")
	if err != nil || string(data) != content {
		t.Fatalf("finite repeated symlink lost its source target: %q, %v", data, err)
	}
	assertLink(t, dest, "units/ref.service", "/data/s/s/file.service")
	assertLink(t, dest, "data/s", ".")
}

func TestSnapshotExplicitLeafDepthMatchesCapture(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(fmt.Sprint("symlink=", link), func(t *testing.T) {
			fd, source := snapshotFixture(t)
			parent := strings.Repeat("d/", maxSnapshotDepth)
			if err := os.MkdirAll(filepath.Join(source, parent), 0755); err != nil {
				t.Fatal(err)
			}
			leaf := parent + "leaf"
			var err error
			if link {
				err = os.Symlink("/target", filepath.Join(source, leaf))
			} else {
				err = os.WriteFile(filepath.Join(source, leaf), []byte("payload"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			inputs := InstallSnapshotInputs{ContextFiles: []string{"/" + leaf}}
			if _, err := fingerprintInstallSnapshotRoot(t.Context(), fd, inputs); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("over-depth leaf fingerprint accepted: %v", err)
			}
			if _, err := captureInstallSnapshotRoot(t.Context(), fd, snapshotDest(t), inputs); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("over-depth leaf capture accepted: %v", err)
			}
		})
	}
}

func TestSnapshotRevisitedMetadataConflict(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink", "null"} {
		t.Run(kind, func(t *testing.T) {
			fd, source := snapshotFixture(t)
			path := "/object"
			recurse := false
			switch kind {
			case "file":
				if err := os.WriteFile(source+path, []byte("before"), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(source+path, 0755); err != nil {
					t.Fatal(err)
				}
				recurse = true
			case "symlink":
				if err := os.Symlink("/absent", source+path); err != nil {
					t.Fatal(err)
				}
			case "null":
				var filesystem unix.Statfs_t
				if err := unix.Fstatfs(fd, &filesystem); err != nil {
					t.Fatal(err)
				}
				if filesystem.Flags&unix.ST_NODEV != 0 {
					t.Skip("null metadata fixture requires a device-capable temporary filesystem")
				}
				path = "/dev/null"
				if err := os.Mkdir(source+"/dev", 0755); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mknod(source+path, unix.S_IFCHR|0600, int(unix.Mkdev(1, 3))); err != nil {
					if errors.Is(err, unix.EPERM) {
						t.Skip("null metadata fixture requires CAP_MKNOD")
					}
					t.Fatal(err)
				}
			}
			s := graphTestSession(t, fd)
			if err := s.captureLogical(path, classRuntime, recurse); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "file":
				if err := os.WriteFile(source+path, []byte("after, changed size"), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Chmod(source+path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				var st unix.Stat_t
				if err := unix.Lstat(source+path, &st); err != nil {
					t.Fatal(err)
				}
				if err := unix.UtimesNanoAt(fd, "object", []unix.Timespec{st.Atim, {Sec: st.Mtim.Sec + 1, Nsec: st.Mtim.Nsec}}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					t.Fatal(err)
				}
			case "null":
				if err := os.Chmod(source+path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.captureLogical(path, classContext, recurse); !errors.Is(err, ErrConflict) {
				t.Fatalf("already-observed %s metadata change accepted: %v", kind, err)
			}
		})
	}
}

func TestSnapshotDirectoryLinksUseBoundedFDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root snapshot fixture")
	}
	if os.Getenv("LINDM_SNAPSHOT_CHAIN_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSnapshotDirectoryLinksUseBoundedFDs$", "-test.count=1", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "LINDM_SNAPSHOT_CHAIN_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("bounded directory-link traversal: %v\n%s", err, output)
		}
		return
	}
	fd, source := snapshotFixture(t)
	const count = 128
	for i := range count {
		dir := fmt.Sprintf("/d%03d", i)
		if err := os.Mkdir(source+dir, 0755); err != nil {
			t.Fatal(err)
		}
		if i+1 < count {
			if err := os.Symlink(fmt.Sprintf("/d%03d", i+1), source+dir+"/next"); err != nil {
				t.Fatal(err)
			}
		}
	}
	const content = "[Service]\nExecStart=/bin/true\n"
	last := fmt.Sprintf("d%03d/proof.service", count-1)
	if err := os.WriteFile(filepath.Join(source, last), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	dest := snapshotDest(t)
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	if old.Max < 64 {
		t.Skip("requires a 64-fd hard limit")
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 64, Max: old.Max}); err != nil {
		t.Fatal(err)
	}
	inputs := InstallSnapshotInputs{UnitPaths: []string{"/d000"}}
	finger, err := fingerprintInstallSnapshotRoot(t.Context(), fd, inputs)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureInstallSnapshotRoot(t.Context(), fd, dest, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if finger != captured {
		t.Fatal("bounded directory chain capture and fingerprint disagree")
	}
	got, err := dest.ReadFile(last)
	if err != nil || string(got) != content {
		t.Fatalf("directory chain lost final content: %q %v", got, err)
	}
}

func TestSnapshotPendingDirectoryEntriesAreGloballyBounded(t *testing.T) {
	fd, source := snapshotFixture(t)
	outer, inner := source+"/tree", source+"/tree/000-next"
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{outer, inner} {
		for i := range maxSnapshotEntries/2 + 1 {
			file, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("entry-%05d", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	a, err := unix.Open(outer, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(a) }()
	b, err := unix.Open(inner, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(b) }()
	s := graphTestSession(t, fd)
	names, err := s.list(a)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.list(b)
	runtime.KeepAlive(names)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nested pending directory lists exceeded the global entry budget: %v", err)
	}
}

func TestSnapshotMetadataPayloadIsBounded(t *testing.T) {
	fd, source := snapshotFixture(t)
	if err := os.Mkdir(source+"/units", 0755); err != nil {
		t.Fatal(err)
	}
	target := "/absent/" + strings.Repeat("d/", (maxDefinitionPath-10)/2)
	count := maxSnapshotMetadataBytes/len(target) + 1
	if count+2 >= maxSnapshotEntries {
		t.Fatal("metadata fixture must remain below the graph entry limit")
	}
	for i := range count {
		if err := os.Symlink(target, fmt.Sprintf("%s/units/link-%05d", source, i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fingerprintInstallSnapshotRoot(t.Context(), fd, InstallSnapshotInputs{UnitPaths: []string{"/units"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("oversized retained symlink metadata accepted: %v", err)
	}
}

func graphTestSession(t *testing.T, fd int) *session {
	t.Helper()
	var root unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil {
		t.Fatal(err)
	}
	return &session{ctx: t.Context(), rootFD: fd, rootDev: root.Dev, rootIno: root.Ino,
		nodes: make(map[string]*snapNode), byInode: make(map[inodeKey]string),
		unitCharged: make(map[inodeKey]struct{}), runCharged: make(map[inodeKey]struct{}), buf: make([]byte, snapshotBufSize)}
}

func TestSnapshotDirectoryRequiringPathSyntax(t *testing.T) {
	for _, suffix := range []string{"/", "/."} {
		for _, linked := range []bool{false, true} {
			t.Run(fmt.Sprintf("suffix=%q/link=%t", suffix, linked), func(t *testing.T) {
				fd, source := snapshotFixture(t)
				const content = "[Service]\nExecStart=/bin/true\n"
				if err := os.WriteFile(source+"/tool", []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
				target := "/tool" + suffix
				if _, err := os.Stat(source + target); !errors.Is(err, unix.ENOTDIR) {
					t.Fatalf("source lookup must require a directory: %v", err)
				}
				inputs := InstallSnapshotInputs{ContextFiles: []string{target}}
				if linked {
					if err := os.Mkdir(source+"/units", 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, source+"/units/ref.service"); err != nil {
						t.Fatal(err)
					}
					inputs = InstallSnapshotInputs{UnitPaths: []string{"/units"}}
				}
				s := graphTestSession(t, fd)
				if err := s.captureInputs(inputs); err != nil {
					t.Fatal(err)
				}
				negative := s.nodes[target]
				if negative == nil || negative.kind != kindNegative || negative.errClass != snapErrNotDir {
					t.Fatalf("source ENOTDIR resolution was not recorded for %q", target)
				}
				dest := snapshotDest(t)
				captured, err := captureInstallSnapshotRoot(t.Context(), fd, dest, inputs)
				if err != nil {
					t.Fatal(err)
				}
				fingerprint, err := fingerprintInstallSnapshotRoot(t.Context(), fd, inputs)
				if err != nil || fingerprint != captured {
					t.Fatalf("negative resolution fingerprint mismatch: %v", err)
				}
				if _, err := dest.Stat(strings.TrimPrefix(target, "/")); !errors.Is(err, unix.ENOTDIR) {
					t.Fatalf("materialized lookup must retain ENOTDIR: %v", err)
				}
				if linked {
					assertLink(t, dest, "units/ref.service", target)
				}
			})
		}
	}
}
