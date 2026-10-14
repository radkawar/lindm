// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"lindm/internal/labhost"
	"lindm/internal/platform"
)

func TestProductionSigningRowsHaveRecipeOrExplicitGate(t *testing.T) {
	for _, release := range platform.Releases() {
		for _, arch := range release.Architectures {
			admitted := release.Key == "ubuntu-24.04" && arch == "x86_64"
			if got := release.LabLaneOn(platform.LaneProductionReleaseSigning, arch); (got == nil) != admitted {
				t.Errorf("%s/%s admission: %v", release.Key, arch, got)
			}
			if !admitted && release.LaneGateOn(platform.LaneProductionReleaseSigning, arch) == "" {
				t.Errorf("%s/%s lacks explicit gate", release.Key, arch)
			}
		}
	}
}

func TestProductionSigningMatrixArgs(t *testing.T) {
	selection := matrixSelection{root: "../..", platforms: "ubuntu-24.04", cells: "production-release-signing", architecture: "x86_64"}
	_, cells, err := selection.plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || !cells[0].Runnable() {
		t.Fatal("maintained signing cell is not runnable")
	}
	run := &matrixRun{root: "/source", repo: "/source", self: "/lab", cache: "/cache", evidence: "/evidence"}
	args, err := run.laneArgs(cells[0], "/evidence/signing")
	if err != nil {
		t.Fatal(err)
	}
	for flag, want := range map[string]string{"repo": "/source", "lab": "/lab", "cache": "/cache", "work-dir": "/evidence", "record": "/evidence/signing.json", "diagnostics": "/evidence/signing.diagnostics"} {
		if got := labhost.FlagValue(args, flag); got != want {
			t.Errorf("%s=%q want %q", flag, got, want)
		}
	}
	if args[0] != "vm" || args[1] != "production-release-signing" || vmGuestCount(args[1], args) != 1 {
		t.Fatal("wrong runner or guest capacity")
	}
}

func TestProductionSigningEvidenceRejectsScopeAndTampering(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tests.log")
	data := []byte("PASS\n")
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	record := map[string]any{"scope": productionSigningScope, "lifecycle_qualified": false, "passed": true, "owned_cleanup_complete": true, "guest_no_swap": true, "source_sha256": digest, "image_id": "ubuntu-noble", "image_sha256": digest, "started_at": "2026-10-14T00:00:00Z", "finished_at": "2026-10-14T00:01:00Z", "tool_versions": map[string]string{"go": "go1.26.9"}, "test_evidence": []map[string]any{{"name": "tests", "path": logPath, "sha256": digest, "size": len(data)}}}
	path := filepath.Join(dir, "record.json")
	save := func() {
		t.Helper()
		bytes, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	if _, err := matrixImportEvidenceSHA256(path, "production-release-signing", productionSigningScope); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "first-run-install-only", "lifecycle"} {
		if _, err := matrixImportEvidenceSHA256(path, "production-release-signing", scope); err == nil {
			t.Fatalf("accepted scope %q", scope)
		}
	}
	if _, err := productionSigningEvidenceSHA256(path, productionSigningScope, "different-image"); err == nil {
		t.Fatal("accepted mismatched image identity")
	}
	for _, cell := range []string{"deploy", "lifecycle"} {
		if _, err := matrixImportEvidenceSHA256(path, cell, productionSigningScope); err == nil {
			t.Fatalf("tests-only evidence qualified %s", cell)
		}
	}
	for _, field := range []string{"lifecycle_qualified", "guest_no_swap", "owned_cleanup_complete", "passed"} {
		old, ok := record[field].(bool)
		if !ok {
			t.Fatalf("fixture field %s is not boolean", field)
		}
		record[field] = !old
		save()
		if _, err := matrixImportEvidenceSHA256(path, "production-release-signing", productionSigningScope); err == nil {
			t.Fatalf("accepted tampered %s", field)
		}
		record[field] = old
	}
	save()
	if err := os.WriteFile(logPath, []byte("FAIL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := matrixImportEvidenceSHA256(path, "production-release-signing", productionSigningScope); err == nil {
		t.Fatal("accepted changed test evidence")
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	record["test_evidence"] = []map[string]any{{"name": "empty-stderr", "path": logPath, "sha256": fmt.Sprintf("%x", sha256.Sum256(nil)), "size": 0}}
	save()
	if _, err := matrixImportEvidenceSHA256(path, "production-release-signing", productionSigningScope); err != nil {
		t.Fatalf("rejected genuine empty stage log: %v", err)
	}
}
