// SPDX-License-Identifier: Apache-2.0
//go:build linux

package custody

import (
	"strings"
	"testing"
)

func TestNativeSigningSwapPolicyNeverOffersProcessLockBypass(t *testing.T) {
	if err := nativeSigningSwapPolicy(nil); err != nil {
		t.Fatal(err)
	}
	err := nativeSigningSwapPolicy([]string{"/swap device", "/swap'2"})
	if err == nil {
		t.Fatal("native helper accepted unencrypted swap")
	}
	for _, expected := range []string{"production native signing refuses", "sudo swapoff '/swap device' '/swap'\\''2'", "encrypted swap", "RAM-only zram", "native helper heap copies"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("missing exact native signing remedy %q: %v", expected, err)
		}
	}
	if strings.Contains(err.Error(), "prlimit") {
		t.Fatal("process-only memory lock offered for native helpers")
	}
}

func TestProtectNativeSigningRefusesActualUnsafeHostSwap(t *testing.T) {
	unsafe, err := unprotectedSwaps("/proc/swaps", "/sys")
	if err != nil {
		t.Fatal(err)
	}
	if len(unsafe) == 0 {
		if err := ProtectNativeSigningSecrets(); err != nil {
			t.Fatalf("safe host incorrectly refused: %v", err)
		}
		return
	}
	if err := ProtectNativeSigningSecrets(); err == nil {
		t.Fatal("actual unencrypted host swap bypassed by process lock allowance")
	} else {
		for _, path := range unsafe {
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("unsafe swap missing from refusal: %s: %v", path, err)
			}
		}
		if !strings.Contains(err.Error(), "sudo swapoff") || strings.Contains(err.Error(), "prlimit") {
			t.Fatalf("unsafe native remedy: %v", err)
		}
	}
}
