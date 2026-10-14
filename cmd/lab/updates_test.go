// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

// The host router injects -accelerator into hardware-capable lanes. The update
// lane must accept it and the pinned EFI flags an aarch64 guest requires, then
// refuse an unbootable selection before creating any work state.
func TestVMUpdatesAcceptsRoutedHardwareFlags(t *testing.T) {
	if !vmHasHardwareFlags("updates") {
		t.Fatal("updates lane is not routed as hardware-capable")
	}
	work := t.TempDir()
	err := runVMUpdates(context.Background(), []string{"-manifest", "../../lab/images/debian-12-arm64.json", "-repo", t.TempDir(), "-work-dir", work, "-accelerator", "tcg", "-storage-bus", "virtio-blk"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "explicit pinned EFI firmware") {
		t.Fatalf("runVMUpdates without firmware = %v", err)
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("refused lane created work state: %v, %v", entries, err)
	}
}
