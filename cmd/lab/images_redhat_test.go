// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRedHatRegistrationCLIRequiresExplicitCleanupConfirmation(t *testing.T) {
	for _, args := range [][]string{
		{"cleanup"},
		{"cleanup", "-token-file", "/nonexistent/protected-token"},
		{"cleanup", "-token-file", "/nonexistent/protected-token", "-legacy-consumer-uuid", "11111111-1111-4111-8111-111111111111"},
		{"cleanup", "-confirm-delete-lab-registrations"},
	} {
		var stdout, stderr bytes.Buffer
		err := runRedHatImages(context.Background(), args, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "requires") || stdout.Len() != 0 {
			t.Fatal("cleanup omitted confirmation/token guard or emitted success evidence")
		}
		if strings.Contains(err.Error(), "cannot open offline token") {
			t.Fatal("cleanup authenticated before confirmation")
		}
	}
}

func TestRedHatInventoryRejectsMutationFlagsAndLegacyCommand(t *testing.T) {
	for _, args := range [][]string{
		{"inventory", "-token-file", "/nonexistent/protected-token", "-confirm-delete-lab-registrations"},
		{"inventory", "-token-file", "/nonexistent/protected-token", "-legacy-consumer-uuid", "11111111-1111-4111-8111-111111111111"},
		{"cleanup-keys", "-confirm-delete-lab-keys"},
	} {
		var stdout, stderr bytes.Buffer
		if err := runRedHatImages(context.Background(), args, &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatal("read-only inventory accepted mutation flag or obsolete command survived cutover")
		}
	}
}
