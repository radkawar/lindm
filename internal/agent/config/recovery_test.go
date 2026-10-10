//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestRecoveryBootPathsUseProtectedConfigurationBase(t *testing.T) {
	base := t.TempDir()
	cfg := &agentv1.RecoveryBootConfig{ImageFile: "images/recovery.efi", SignerCertificateFile: "signing.pem", EspDirectory: "esp", StateDirectory: "state"}
	if err := resolveRecoveryBoot(base, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.GetImageFile() != filepath.Join(base, "images/recovery.efi") || cfg.GetSignerCertificateFile() != filepath.Join(base, "signing.pem") || cfg.GetEspDirectory() != filepath.Join(base, "esp") || cfg.GetStateDirectory() != filepath.Join(base, "state") {
		t.Fatal("recovery paths did not resolve against protected configuration")
	}
}

func TestRecoveryBootRejectsAliasedDirectory(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "alias")); err != nil {
		t.Fatal(err)
	}
	cfg := &agentv1.RecoveryBootConfig{ImageFile: "image.efi", SignerCertificateFile: "signing.pem", EspDirectory: "alias", StateDirectory: "state"}
	if err := resolveRecoveryBoot(base, cfg); err == nil {
		t.Fatal("recovery ESP symlink was accepted")
	}
	cfg.EspDirectory = "/"
	if err := resolveRecoveryBoot(base, cfg); err == nil {
		t.Fatal("entire filesystem accepted as recovery ESP")
	}
}
