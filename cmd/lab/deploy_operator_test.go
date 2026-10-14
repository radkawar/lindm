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

func TestDeployBackupUnlockRequiresExactlyOneProtectedInput(t *testing.T) {
	for _, input := range []struct {
		fd               int
		escrow, identity string
	}{{-1, "", ""}, {-1, "/cipher.age", ""}, {-1, "", "/private-lab-identity"}, {0, "/cipher.age", "/private-lab-identity"}} {
		if _, err := readDeployBackupUnlock(context.Background(), input.fd, input.escrow, input.identity); err == nil {
			t.Fatal("missing or competing private unlock input accepted")
		}
	}
}

func TestOperatorCustodyFixtureCannotQualifyNativeLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.json")
	if err := os.WriteFile(path, []byte(`{"scope":"lab-operator-custody-fixture-only","lifecycle_qualified":false,"passed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"deploy", "lifecycle"} {
		if _, err := matrixImportEvidenceSHA256(path, cell, "lab-operator-custody-fixture-only"); err == nil {
			t.Errorf("operator identity fixture qualified %s", cell)
		}
	}
}

func TestOperatorVerifyDoesNotAcceptPlaintextSecretArguments(t *testing.T) {
	for _, secretFlag := range []string{"-passphrase", "-passphrase-file", "-identity-text"} {
		if err := runDeployOperatorVerify(context.Background(), []string{secretFlag, "private-input"}, io.Discard, io.Discard); err == nil {
			t.Errorf("independent operator reload accepted plaintext secret argument %s", secretFlag)
		}
	}
}
