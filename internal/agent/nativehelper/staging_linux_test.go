// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nativehelper

import (
	"os"
	"path/filepath"
	"testing"

	"lindm/internal/agent/privatecustody"
)

// An executor without approved package sources never opens the provider, so its
// packageprovider state directory does not exist. Observed live on a demo
// Ubuntu 24.04 aarch64 device: tombstoning the refused action failed with
// ENOENT, the executor retried the preparation forever and every later resource
// on the device stayed pending. The refusal must still be durably tombstoned.
func TestCancelTombstoneWithoutProviderStateDirectory(t *testing.T) {
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	const installation = "341e26dd-13d9-45ae-bdc2-7a2c21d45d1e"
	if err := os.WriteFile(filepath.Join(state, "installation"), []byte(installation+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	custody, err := privatecustody.Initialize(state, installation)
	if err != nil {
		t.Fatal(err)
	}
	custody.Close()
	const action = "c6ae02de-0901-4585-948d-38501d0dc956"
	if _, err := os.Stat(filepath.Join(state, "packageprovider")); !os.IsNotExist(err) {
		t.Fatalf("fixture already has a provider state directory: %v", err)
	}
	for range 2 {
		directory, unlock, err := tombstoneStage(state, action)
		if err != nil {
			t.Fatalf("refused action not tombstoned: %v", err)
		}
		if directory != filepath.Join(state, "packageprovider", action) {
			t.Fatalf("tombstone in %s", directory)
		}
		if err := notCancelled(directory); err == nil {
			t.Fatal("tombstone not durable")
		}
		if err := unlock(); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(filepath.Join(state, "packageprovider"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("provider state directory not private: %v %v", info, err)
	}
	if _, _, err := tombstoneStage(state, "not-a-uuid"); err == nil {
		t.Fatal("invalid action identity tombstoned")
	}
}
