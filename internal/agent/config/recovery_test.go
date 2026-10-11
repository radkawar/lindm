//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"

	"buf.build/go/protovalidate"

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

// Regression: native Fedora measured staging was refused because the absent
// UKI signer path resolved to the configuration directory.
func TestMeasuredRecoveryBootKeepsSignerAbsent(t *testing.T) {
	base := t.TempDir()
	digest := make([]byte, 32)
	cfg := &agentv1.RecoveryBootConfig{ImageFile: "native-recovery.initrd", ImageSha256: digest, ImageSize: 1, EspDirectory: "boot", StateDirectory: "state", Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB, KernelSha256: digest}
	if err := resolveRecoveryBoot(base, cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.GetSignerCertificateFile() != "" {
		t.Fatalf("absent signer resolved to %q", cfg.GetSignerCertificateFile())
	}
	if err := protovalidate.Validate(cfg); err != nil {
		t.Fatalf("resolved measured configuration invalid: %v", err)
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
