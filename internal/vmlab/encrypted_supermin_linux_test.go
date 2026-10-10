package vmlab

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedSuperminOverrideRequiresReadablePair(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "kernel")
	modules := filepath.Join(dir, "test-kernel-release")
	payload := []byte("private test kernel artifact")
	if err := os.WriteFile(kernel, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(modules, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kernel, modules string
		wantError             bool
	}{
		{"no override", "", "", false},
		{"explicit pair", kernel, modules, false},
		{"missing kernel", "", modules, true},
		{"missing modules", kernel, "", true},
		{"device kernel", "/dev/null", modules, true},
		{"missing kernel file", filepath.Join(dir, "absent"), modules, true},
		{"modules not directory", kernel, kernel, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUPERMIN_KERNEL", tc.kernel)
			t.Setenv("SUPERMIN_MODULES", tc.modules)
			evidence, err := encryptedSuperminKernelEvidence(t.Context())
			if (err != nil) != tc.wantError {
				t.Fatalf("override error = %v, want error %v", err, tc.wantError)
			}
			if tc.wantError {
				return
			}
			if tc.kernel == "" {
				if evidence != nil {
					t.Fatal("implicit kernel selection must not fabricate pinned kernel evidence")
				}
				return
			}
			want := sha256.Sum256(payload)
			if evidence == nil || evidence.KernelSHA256 != hex.EncodeToString(want[:]) || evidence.ModulesVersion != filepath.Base(modules) {
				t.Fatalf("incorrect explicit kernel evidence: %#v", evidence)
			}
		})
	}
}
