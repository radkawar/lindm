// SPDX-License-Identifier: Apache-2.0
//go:build linux

package packaging

import (
	"os"
	"strings"
	"testing"

	"lindm/internal/custody"
)

func TestProductionImportRefusesUnsafeHostSwapBeforeParsing(t *testing.T) {
	guardErr := custody.ProtectNativeSigningSecrets()
	if guardErr == nil {
		// Production success is exercised by the dedicated VM integration lane.
		return
	}
	directory := t.TempDir()
	// Refusal precedes secret parsing, mappings, and native key import.
	key, cleanup, err := ImportProductionSigner(t.Context(), directory, []byte("unused public key sentinel"), []byte("unused public passphrase sentinel"))
	if key != nil || cleanup != nil || err == nil || !strings.Contains(err.Error(), guardErr.Error()) {
		t.Fatalf("native import bypassed swap guard: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused native import created signing state")
	}
}
