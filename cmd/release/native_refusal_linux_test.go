// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitNativeRefusalPrecedesCredentialInput(t *testing.T) {
	guardErr := protectSecrets()
	if guardErr == nil {
		// Production success is exercised by the dedicated VM integration lane.
		return
	}
	if !strings.Contains(guardErr.Error(), "production native signing refuses unencrypted swap") {
		t.Fatal(guardErr)
	}
	directory := filepath.Join(t.TempDir(), "new-keys")
	// The native policy refuses before trying this deliberately unreadable input.
	err := runInit(t.Context(), []string{"--keys", directory, "--passphrase-fd", "9999"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "production native signing refuses unencrypted swap") {
		t.Fatalf("credential input preceded refusal: %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused CLI created key output")
	}
}
