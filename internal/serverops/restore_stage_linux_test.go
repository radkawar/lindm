// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRestoreStageSpace(t *testing.T) {
	const blockSize = 4096
	const archiveBytes = 200 << 20
	const required = archiveBytes + 2*(2*65536+4)*blockSize + 64<<20
	for _, test := range []struct {
		name   string
		blocks uint64
		wantOK bool
	}{
		{"insufficient", required/blockSize - 1, false},
		{"exact", required / blockSize, true},
		{"large filesystem does not overflow", math.MaxUint64, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkRestoreStageSpace(unix.Statfs_t{Bsize: blockSize, Bavail: test.blocks}, archiveBytes, 2)
			if (err == nil) != test.wantOK {
				t.Fatalf("space check: %v", err)
			}
			if err != nil && (!strings.Contains(err.Error(), "insufficient_restore_staging_space") || !strings.Contains(err.Error(), "free space on the data filesystem")) {
				t.Fatalf("missing operator remedy: %v", err)
			}
		})
	}
}

func TestRestoreStageRejectsInvalidCapacity(t *testing.T) {
	for _, test := range []struct {
		blockSize int64
		bytes     int64
		archives  int
	}{
		{0, 0, 1}, {1 << 30, 0, 1}, {4096, -1, 1},
		{4096, 0, 0}, {4096, 0, 3}, {4096, maxArchive + 1, 1},
	} {
		if err := checkRestoreStageSpace(unix.Statfs_t{Bsize: test.blockSize, Bavail: math.MaxUint64}, test.bytes, test.archives); err == nil {
			t.Fatalf("invalid capacity admitted: %+v", test)
		}
	}
}

func TestRestoreStagePrivateDataFilesystemAndCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root staging ownership requires native root lane")
	}
	input, err := os.MkdirTemp("/run", "lindmd-restore-stage-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(input); err != nil {
			t.Error(err)
		}
	})
	archive := filepath.Join(input, "fixture.age")
	if err = os.WriteFile(archive, []byte("ciphertext-size fixture; not decrypted"), 0600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(input, "operations")
	abandoned := filepath.Join(parent, "restore-crashed")
	if err = os.MkdirAll(filepath.Join(abandoned, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(abandoned, "nested", "plaintext-fixture"), []byte("crash residue"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(parent, "unrelated")
	if err = os.WriteFile(unrelated, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cleanup, err := prepareRestoreStageAt(parent, archive, archive)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})
	var stat unix.Stat_t
	if err = unix.Lstat(stage, &stat); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(stage) != parent || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0777 != 0700 {
		t.Fatalf("stage not private on the data filesystem: %+v", stat)
	}
	if _, err = os.Lstat(abandoned); !os.IsNotExist(err) {
		t.Fatalf("crashed stage survives sweep: %v", err)
	}
	if got, readErr := os.ReadFile(unrelated); readErr != nil || string(got) != "retain" {
		t.Fatalf("unrelated file changed: %v", readErr)
	}
	if err = os.WriteFile(filepath.Join(stage, "plaintext-fixture"), []byte("test data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage survives cleanup: %v", err)
	}
}

func TestRestoreStageSweepRejectsUnsafeEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root staging ownership requires native root lane")
	}
	for _, symlink := range []bool{false, true} {
		parent, err := os.MkdirTemp("/run", "lindmd-restore-sweep-test-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(parent); err != nil {
				t.Error(err)
			}
		})
		outside := filepath.Join(parent, "unrelated")
		if err = os.Mkdir(outside, 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(outside, "retain")
		if err = os.WriteFile(marker, []byte("retain"), 0600); err != nil {
			t.Fatal(err)
		}
		unsafe := filepath.Join(parent, "restore-unsafe")
		if symlink {
			err = os.Symlink(outside, unsafe)
		} else {
			err = os.Mkdir(unsafe, 0755)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = prepareRestoreStageParent(parent); err == nil || !strings.Contains(err.Error(), "unsafe_restore_staging_entry") {
			t.Fatalf("unsafe sweep entry admitted: %v", err)
		}
		if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "retain" {
			t.Fatalf("outside data changed: %v", readErr)
		}
	}
}
