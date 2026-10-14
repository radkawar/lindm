// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasebuild

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
	"lindm/internal/platform"
	"lindm/internal/serverdeps"
)

func TestNativeWorkDoesNotInheritPublicOutputAncestry(t *testing.T) {
	public := t.TempDir()
	if err := os.Chmod(public, 0775); err != nil {
		t.Fatal(err)
	}
	unsafeWork := filepath.Join(public, "native")
	if err := os.Mkdir(unsafeWork, 0700); err != nil {
		t.Fatal(err)
	}
	if fd, err := statefs.OpenDirectory(unsafeWork); err == nil {
		_ = unix.Close(fd)
		t.Fatal("strict gate accepted group-writable public ancestry")
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", private)
	work, owned, err := createBuildWork()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanupBuildWork(work, owned); err != nil {
			t.Error(err)
		}
	})
	if filepath.Dir(work) != private || owned.Mode().Perm() != 0700 {
		t.Fatal("native work escaped private temporary parent")
	}
	fd, err := statefs.OpenDirectory(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
}

func TestNativeWorkRejectsUnprotectedTemporaryParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0775); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", parent)
	if work, _, err := createBuildWork(); err == nil {
		t.Fatalf("unprotected temporary work accepted: %s", work)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed allocation left work: %v %v", entries, err)
	}
}

func TestExportPublicationVerifiesAndNeverReplacesOutput(t *testing.T) {
	for _, attack := range []string{"existing", "tamper", "cancel"} {
		t.Run(attack, func(t *testing.T) {
			source, public, id := releaseFixture(t)
			output := filepath.Join(t.TempDir(), "release")
			ctx := t.Context()
			switch attack {
			case "existing":
				if err := os.WriteFile(output, []byte("operator-owned"), 0600); err != nil {
					t.Fatal(err)
				}
			case "tamper":
				if err := os.WriteFile(filepath.Join(source, "lindm-agent_1.2.3_amd64.deb"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			if err := publishExport(ctx, source, output, public, id, false); err == nil {
				t.Fatal("unsafe publication succeeded")
			}
			if attack == "existing" {
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "operator-owned" {
					t.Fatal("existing output changed")
				}
			} else if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed export published output")
			}
		})
	}
}

func crossFilesystemParent(t *testing.T, source string) string {
	t.Helper()
	parent, err := os.MkdirTemp("/dev/shm", "lindm-export-test-")
	if err != nil {
		t.Skipf("writable second filesystem unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Error(err)
		}
	})
	var first, second unix.Stat_t
	if err := unix.Stat(source, &first); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(parent, &second); err != nil {
		t.Fatal(err)
	}
	if first.Dev == second.Dev {
		t.Skip("temporary fixtures and /dev/shm share a filesystem")
	}
	return parent
}
func TestCrossFilesystemExportCopyIsVerifiedAndStageIsRemoved(t *testing.T) {
	for _, name := range []string{"valid", "link-refused"} {
		t.Run(name, func(t *testing.T) {
			linked := name == "link-refused"
			source, public, id := releaseFixture(t)
			parent := crossFilesystemParent(t, source)
			output := filepath.Join(parent, "release")
			if linked {
				if err := os.Symlink(public, filepath.Join(source, "unexpected-link")); err != nil {
					t.Fatal(err)
				}
			}
			err := publishExport(t.Context(), source, output, public, id, false)
			if linked {
				if err == nil {
					t.Fatal("linked export copied")
				}
				if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed copy published")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Verify(t.Context(), output, public, id); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".lindm-export-") {
					t.Fatal("temporary export stage retained")
				}
			}
		})
	}
}

func TestCopyHonorsCancellationBoundsAndSnapshotPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := copyExport(ctx, t.TempDir(), t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("empty canceled copy: %v", err)
	}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("five!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyExportFile(t.Context(), input, filepath.Join(t.TempDir(), "output"), 0600, 4); err == nil {
		t.Fatal("copy exceeded bounded stream")
	}
	for _, key := range []string{"ubuntu-24.04", "rhel-9"} {
		release, ok := platform.Lookup(key)
		if !ok || release.Server == nil {
			t.Fatal("server snapshot registry unavailable")
		}
		if exportCopyBound(release.Server.SnapshotName) != int64(serverdeps.HardMaxBytes) {
			t.Fatal("valid offline snapshot bound narrowed")
		}
	}
	if exportCopyBound("unknown.snapshot") != maxArtifact || exportCopyBound("lindmd.deb") != maxArtifact {
		t.Fatal("ordinary artifact bound widened")
	}
}
