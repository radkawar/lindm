// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDeployBuildDoesNotAcceptHostPrivateSigningInputs(t *testing.T) {
	for _, flag := range []string{"-passphrase", "-passphrase-file", "-signer", "-identity-file", "-custody-key-file"} {
		if err := runDeployBuildAdmitted(context.Background(), []string{flag, "private-input"}, io.Discard, io.Discard); err == nil {
			t.Errorf("cold build accepted host secret input %s", flag)
		}
	}
}

func TestColdBuildEvidenceCannotQualifyDeployOrLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cold.json")
	if err := os.WriteFile(path, []byte(`{"scope":"production-cold-release-build-only","lifecycle_qualified":false,"passed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"deploy", "lifecycle"} {
		for _, scope := range []string{"", "production-cold-release-build-only"} {
			if _, err := matrixImportEvidenceSHA256(path, cell, scope); err == nil {
				t.Errorf("cold build qualified %s with scope %q", cell, scope)
			}
		}
	}
}
