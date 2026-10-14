// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/deploylab"
)

func TestMatrixImportCannotPromoteFirstRunOnlyDeployRecord(t *testing.T) {
	body := []byte(`{"scope":"first-run-install-only","lifecycle_qualified":false,"passed":true}`)
	path := filepath.Join(t.TempDir(), "setup.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "historical-install-audit", "full-lifecycle"} {
		if _, err := matrixImportEvidenceSHA256(path, "deploy", scope); err == nil {
			t.Errorf("first-run-only record accepted with scope %q", scope)
		}
	}
	got, err := matrixImportEvidenceSHA256(path, "deploy", deploylab.FirstRunInstallScope)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(body)
	if got != hex.EncodeToString(expected[:]) {
		t.Fatalf("scope inspection changed evidence hash: %s", got)
	}
}

func TestMatrixImportKeepsExistingHistoricalDeployLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "historical.log")
	if err := os.WriteFile(path, []byte("observed historical command output\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := matrixImportEvidenceSHA256(path, "deploy", "historical-install-audit"); err != nil {
		t.Fatal(err)
	}
}

func TestMatrixImportRejectsExplicitNonLifecycleUnscopedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(`{"lifecycle_qualified":false,"passed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := matrixImportEvidenceSHA256(path, "deploy", ""); err == nil {
		t.Fatal("explicit non-lifecycle record qualified the unscoped deploy cell")
	}
}

func TestMatrixImportCannotPromoteUnavailableDeployEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unavailable.json")
	args := []string{"-root", "../..", "-platform", "ubuntu-24.04", "-cell", "deploy", "-architecture", "x86_64", "-evidence", path, "-sha256", strings.Repeat("1", 64), "-recorded", "2026-10-14"}
	if err := runMatrixImport(t.Context(), args, io.Discard); err == nil || !strings.Contains(err.Error(), "unscoped deploy import requires readable evidence") {
		t.Fatalf("unavailable first-run evidence could be promoted to a full deploy row: %v", err)
	}
}
