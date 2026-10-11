//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A queued lane must boot the exact planned snapshot, not a newly edited pin.
func TestRetainMatrixManifestRejectsChangedPin(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	data := []byte(`{"repositorySnapshotDate":"2026-10-02"}`)
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	pinned := filepath.Join(dir, "retained.json")
	if err := retainMatrixManifest(source, pinned, digest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(`{"repositorySnapshotDate":"2026-10-09"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(pinned)
	if err != nil || string(retained) != string(data) {
		t.Fatalf("retained manifest changed: %q, %v", retained, err)
	}
	if err := retainMatrixManifest(source, filepath.Join(dir, "changed.json"), digest); err == nil {
		t.Fatal("queued manifest change was accepted")
	}
	if err := retainMatrixManifest(source, pinned, digest); err == nil {
		t.Fatal("existing evidence was overwritten")
	}
}

func TestMatrixOwnerSelectedBootTopology(t *testing.T) {
	selection := matrixSelection{root: "../..", platforms: "arch", cells: "encrypted", architecture: "x86_64", manifestID: "arch-20261001-encrypted-systemd-boot-x86-64"}
	_, cells, err := selection.plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].Manifest == nil || cells[0].Manifest.Image.GetId() != selection.manifestID {
		t.Fatal("matrix did not retain the owner's selected systemd-boot topology")
	}
	selection.architecture = "aarch64"
	if _, _, err := selection.plan(); err == nil {
		t.Fatal("a manifest from another architecture was accepted")
	}
}

func TestAdvisoryRecordScopeNeverInventsFullCoverage(t *testing.T) {
	for _, scope := range []string{"", "complete", "partial-feed matching"} {
		file := filepath.Join(t.TempDir(), "record.json")
		if err := os.WriteFile(file, []byte(fmt.Sprintf(`{"advisories":{"scope":%q}}`, scope)), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := advisoryRecordScope(file)
		if scope == "partial-feed matching" {
			if err != nil || got != scope {
				t.Fatalf("partial scope changed: %q %v", got, err)
			}
		} else if err == nil {
			t.Fatal("unqualified coverage scope was accepted")
		}
	}
}

func TestMatrixActionCellsRequireTheirCompleteNativeProof(t *testing.T) {
	for _, tc := range []struct{ cell, required string }{
		{"encrypted", "-scenario=encryption"},
		{"device-actions", "-wipe-phase=live-actions"},
		{"recovery-sanitize", "-wipe-phase=recovery-nvme"},
	} {
		selection := matrixSelection{root: "../..", platforms: "arch", cells: tc.cell, architecture: "x86_64"}
		_, cells, err := selection.plan()
		if err != nil {
			t.Fatal(err)
		}
		if len(cells) != 1 || cells[0].Spec.GetLane() != "device-actions" || !slices.Contains(cells[0].Spec.GetArgs(), tc.required) {
			t.Fatalf("%s omitted native proof %s", tc.cell, tc.required)
		}
	}
}
