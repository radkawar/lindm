// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasekit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/custody"
)

func TestInitRefusesUnsafeHostSwapBeforeKeysOrOutput(t *testing.T) {
	guardErr := custody.ProtectNativeSigningSecrets()
	if guardErr == nil {
		// Production success is exercised by the dedicated VM integration lane.
		return
	}
	if !strings.Contains(guardErr.Error(), "production native signing refuses unencrypted swap") {
		t.Fatal(guardErr)
	}
	directory := filepath.Join(t.TempDir(), "new-kit")
	// Validate public roots normally; production refusal precedes private-key
	// generation and any operator output, not harmless public input parsing.
	_, err := Init(t.Context(), directory, nil, []byte("public test passphrase sentinel"), approvedCA(t))
	if err == nil || !strings.Contains(err.Error(), "production native signing refuses unencrypted swap") {
		t.Fatalf("init bypassed native swap guard: %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused init created operator output")
	}
}
