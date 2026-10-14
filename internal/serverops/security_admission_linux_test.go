// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointRequiresEncryptedCustodyBeforeReadingArchives(t *testing.T) {
	err := SignCheckpoint(t.Context(), CheckpointOptions{ConfirmFenced: true, RecoveryEpoch: 1})
	if err == nil || !strings.Contains(err.Error(), "encrypted_checkpoint_custody_required") {
		t.Fatalf("unencrypted checkpoint admitted: %v", err)
	}
}

func TestMissingAndClosedLeaseCannotEnterApply(t *testing.T) {
	var missing *UpgradeLease
	if err := missing.Validate(); err == nil {
		t.Fatal("missing lease admitted")
	}
	if _, _, _, err := missing.ImportedRelease(t.Context()); err == nil {
		t.Fatal("imported bundle read without lease")
	}
	empty := new(UpgradeLease)
	if err := empty.RestartTimersOnClose(); err == nil {
		t.Fatal("zero lease owns timers")
	}
	if err := empty.Close(); err == nil {
		t.Fatal("zero lease close reported success")
	}
	if err := empty.Validate(); err == nil {
		t.Fatal("closed lease admitted")
	}
}

func TestRootPrivateDecryptionInputRejectsReadableCiphertext(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root private input policy requires native root lane")
	}
	directory, err := os.MkdirTemp("/run", "lindmd-custody-input-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	}()
	path := filepath.Join(directory, "identity.age")
	if err = os.WriteFile(path, []byte("ciphertext fixture; content not decrypted by this permission boundary test"), 0644); err != nil {
		t.Fatal(err)
	}
	if file, _, err := openOperationFile(path, 1<<20, true); err == nil {
		_ = file.Close()
		t.Fatal("root accepted public-readable private decryption input")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	file, _, err := openOperationFile(path, 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
}
