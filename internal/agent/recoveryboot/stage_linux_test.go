package recoveryboot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestESPCapacityUsesExactImageAllocationAndAvailableBlocks(t *testing.T) {
	for _, test := range []struct {
		name      string
		size      int64
		block     int64
		fragment  int64
		available uint64
		needed    uint64
		freeBytes uint64
	}{
		{"original_uki", 69788216, 4096, 4096, 17038, 69791744, 69787648},
		{"exact_fit", 8192, 4096, 4096, 2, 8192, 8192},
		{"one_byte_over", 8193, 4096, 4096, 2, 12288, 8192},
		{"empty_esp", 1, 4096, 4096, 0, 4096, 0},
		{"allocation_not_io_size", 4097, 4096, 512, 9, 4608, 4608},
		{"block_size_fallback", 4097, 4096, 0, 2, 8192, 8192},
		{"rounding_above_int64", 1<<63 - 1, 4096, 4096, 1 << 51, 1 << 63, 1 << 63},
		{"large_allocation", 1<<63 - 1, 1<<63 - 2, 0, 2, 1<<64 - 4, 1<<64 - 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			stat := unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: test.block, Frsize: test.fragment, Bavail: test.available, Bfree: ^uint64(0)}
			needed, available, err := espCapacity(test.size, stat)
			if needed != test.needed || available != test.freeBytes {
				t.Fatalf("capacity = (%d, %d), want (%d, %d)", needed, available, test.needed, test.freeBytes)
			}
			if test.needed <= test.freeBytes {
				if err != nil {
					t.Fatalf("sufficient allocation refused: %v", err)
				}
				return
			}
			want := fmt.Sprintf("recoveryboot: device_action_esp_insufficient needed=%d available=%d: %s", test.needed, test.freeBytes, unix.ENOSPC)
			if !errors.Is(err, unix.ENOSPC) || err.Error() != want {
				t.Fatalf("imprecise capacity refusal: %v, want %s", err, want)
			}
		})
	}
}

func TestESPCapacityRejectsInvalidAndOverflowingFilesystemFacts(t *testing.T) {
	for _, test := range []struct {
		name   string
		size   int64
		stat   unix.Statfs_t
		reason string
	}{
		{"zero_size", 0, unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 4096}, "invalid_image_size"},
		{"negative_size", -1, unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 4096}, "invalid_image_size"},
		{"wrong_filesystem", 1, unix.Statfs_t{Type: unix.TMPFS_MAGIC, Bsize: 4096}, "qualified_esp_required"},
		{"zero_allocation", 1, unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC}, "invalid_esp_allocation_unit"},
		{"negative_allocation", 1, unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 4096, Frsize: -1}, "invalid_esp_allocation_unit"},
		{"available_overflow", 1, unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 4096, Bavail: ^uint64(0)}, "ESP capacity overflow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := espCapacity(test.size, test.stat)
			if err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("invalid capacity was not refused: %v", err)
			}
			if test.name == "available_overflow" && !errors.Is(err, unix.EOVERFLOW) {
				t.Fatalf("capacity overflow lost syscall cause: %v", err)
			}
		})
	}
}

func TestPreflightRefusesCapacityBeforeCustodyAndArtifactWork(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native preflight requires root")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	request := StageRequest{
		ActionID:       "12345678-1234-1234-1234-123456789abc",
		SourceBootID:   strings.TrimSpace(string(boot)),
		ImageSize:      4097,
		ESPPath:        directory,
		StateDirectory: filepath.Join(directory, "must-not-be-created"),
		TrustedTPMCustody: func(context.Context) error {
			t.Fatal("capacity refusal reached custody")
			return nil
		},
	}
	observed := false
	err = preflight(context.Background(), request, func(path string, size int64) (uint64, uint64, error) {
		observed = true
		if path != request.ESPPath || size != request.ImageSize {
			t.Fatalf("capacity probe lost signed identity: %q, %d", path, size)
		}
		return espCapacity(size, unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 4096, Bavail: 1})
	})
	if !observed || !errors.Is(err, unix.ENOSPC) || !strings.Contains(err.Error(), "needed=8192 available=4096") {
		t.Fatalf("preflight did not preserve exact capacity refusal: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("capacity preflight changed filesystem: %v, %v", entries, err)
	}
}

func TestESPInsufficientPreservesCopyError(t *testing.T) {
	cause := &os.PathError{Op: "write", Path: "/esp/EFI/Linux/recovery.efi", Err: unix.ENOSPC}
	err := espInsufficient(8192, 4096, cause)
	var pathErr *os.PathError
	if !errors.Is(err, unix.ENOSPC) || !errors.As(err, &pathErr) || pathErr != cause {
		t.Fatalf("capacity diagnostic lost native copy error: %v", err)
	}
	if !strings.Contains(err.Error(), "device_action_esp_insufficient needed=8192 available=4096") {
		t.Fatalf("copy error lost capacity diagnostic: %v", err)
	}
}

func TestStageCopyRechecksCapacityBeforeCreatingFile(t *testing.T) {
	directory := t.TempDir()
	request := StageRequest{
		ESPPath:   directory,
		ImagePath: filepath.Join(directory, "not-read-before-capacity-refusal"),
		ImageSize: 4097,
	}
	stat := unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 4096, Bavail: 2}
	if _, _, err := espCapacity(request.ImageSize, stat); err != nil {
		t.Fatalf("initial preflight should fit: %v", err)
	}
	// Another writer consumes a block between preflight and stage.
	stat.Bavail = 1
	target := filepath.Join(directory, "staged.efi")
	called := false
	err := copyESPImage(request, target, func(path string, size int64) (uint64, uint64, error) {
		called = true
		if path != directory || size != request.ImageSize {
			t.Fatalf("stage lost exact capacity identity: %q, %d", path, size)
		}
		return espCapacity(size, stat)
	})
	if !called || !errors.Is(err, unix.ENOSPC) || !strings.Contains(err.Error(), "needed=8192 available=4096") {
		t.Fatalf("stage did not recheck current capacity: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage capacity refusal created a file: %v", err)
	}
}

func TestStagedSnapshotRejectsChangedESPImageDespiteMatchingOffTargetCopy(t *testing.T) {
	root := t.TempDir()
	esp := filepath.Join(root, "esp")
	directory := filepath.Join(esp, "EFI", "Linux")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	action := "12345678-1234-1234-1234-123456789abc"
	image := fixtureIngredient(t, directory, "lindm-recovery-"+action+".efi", []byte("approved-signed-UKI"))
	// An unchanged pre-boot copy must never conceal replacement on the ESP.
	fixtureIngredient(t, root, "recovery.efi", []byte("approved-signed-UKI"))
	request := StageRequest{ESPPath: esp, ActionID: action, ImageSHA256: image.SHA256}
	if _, err := stagedArtifactSnapshot(request); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image.Source, []byte("different-signed-UKI"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stagedArtifactSnapshot(request); err == nil {
		t.Fatal("stale off-target image hid changed selected ESP image")
	}
}

func TestStagedSnapshotBindsExactCapsuleAndRejectsSymlink(t *testing.T) {
	esp := t.TempDir()
	directory := filepath.Join(esp, "EFI", "Linux")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	action := "12345678-1234-1234-1234-123456789abc"
	image := fixtureIngredient(t, directory, "lindm-recovery-"+action+".efi", []byte("approved-signed-UKI"))
	capsule := fixtureIngredient(t, directory, "lindm-recovery-"+action+".capsule", []byte("approved-NV-bound-capsule"))
	request := StageRequest{ESPPath: esp, ActionID: action, ImageSHA256: image.SHA256, CapsuleSHA256: capsule.SHA256, TrustedTPMCustody: func(context.Context) error { t.Fatal("snapshot must not execute TPM operations"); return nil }}
	if _, err := stagedArtifactSnapshot(request); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(capsule.Source, []byte("different-action-capsule"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stagedArtifactSnapshot(request); err == nil {
		t.Fatal("changed action capsule accepted")
	}
	if err := os.Remove(image.Source); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(capsule.Source, image.Source); err != nil {
		t.Fatal(err)
	}
	if _, err := stagedArtifactSnapshot(request); err == nil {
		t.Fatal("symlinked selected image accepted")
	}
}
