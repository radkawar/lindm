package recoveryboot

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

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
