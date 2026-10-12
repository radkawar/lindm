//go:build linux

package vmlab

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func archOwnerRecoveryManifest() *labv1.ImageManifest {
	return &labv1.ImageManifest{
		Distribution: "arch", Version: "rolling", Architecture: "x86_64",
		Edition: archRecoveryInstallerEdition, ImageFilename: "archlinux-2026.10.01-x86_64.iso",
		RepositorySnapshotDate: proto.String("2026-10-02"), ChecksumMode: labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE,
	}
}

// A noSB bootstrap must not accidentally boot archiso under enrolled firmware or
// carry the private run's owner certificate into the reusable baseline cache.
func TestArchOwnerRecoverySeparatesBootstrapTrust(t *testing.T) {
	selected := EncryptedFirmwareOptions{Code: "code.fd", Vars: "enrolled.fd", Package: "ovmf", Version: "pinned", SecureBoot: true, OwnedDBCertificate: "owner.pem"}
	bootstrap, err := recoveryBootstrapFirmware(archOwnerRecoveryManifest(), selected, "setup.fd", "")
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.SecureBoot || bootstrap.OwnedDBCertificate != "" || bootstrap.Vars != "setup.fd" || bootstrap.Code != selected.Code || bootstrap.Package != selected.Package || bootstrap.Version != selected.Version {
		t.Fatalf("bootstrap trust boundary lost: %+v", bootstrap)
	}
	if !selected.SecureBoot || selected.OwnedDBCertificate != "owner.pem" || selected.Vars != "enrolled.fd" {
		t.Fatal("final owner trust was mutated")
	}
}

func TestArchOwnerRecoveryRejectsImplicitTopologyOrTrust(t *testing.T) {
	for _, name := range []string{"grub", "encrypted", "cloud", "arm", "no_secure_boot", "no_owner", "no_bootstrap", "measured_grub", "no_repository_pin"} {
		t.Run(name, func(t *testing.T) {
			m := archOwnerRecoveryManifest()
			fw := EncryptedFirmwareOptions{SecureBoot: true, OwnedDBCertificate: "owner.pem"}
			bootstrap, mode := "setup.fd", ""
			switch name {
			case "grub":
				m.Edition = "grub-encrypted-lab"
			case "encrypted":
				m.Edition = "systemd-boot-encrypted-lab"
			case "cloud":
				m.Edition = "cloud"
			case "arm":
				m.Architecture = "aarch64"
			case "no_secure_boot":
				fw.SecureBoot = false
			case "no_owner":
				fw.OwnedDBCertificate = ""
			case "no_bootstrap":
				bootstrap = ""
			case "measured_grub":
				mode = recoveryBootMeasured
			case "no_repository_pin":
				m.RepositorySnapshotDate = nil
			}
			if _, err := recoveryBootstrapFirmware(m, fw, bootstrap, mode); err == nil {
				t.Fatal("unsafe or implicitly remapped owner recovery admitted")
			}
		})
	}
}

func TestArchRecoveryCacheBindsRepositorySnapshot(t *testing.T) {
	first := archOwnerRecoveryManifest()
	second := proto.CloneOf(first)
	second.RepositorySnapshotDate = proto.String("2026-10-03")
	a, err := installerImageFor(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := installerImageFor(second)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || b == nil || a.version == b.version {
		t.Fatal("separate repository snapshots alias the installer cache")
	}
}

func TestArchISORefusesEnforcedFirmwareBeforeAcquisition(t *testing.T) {
	m := archOwnerRecoveryManifest()
	spec, err := installerImageFor(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = installedImage(t.Context(), m, spec, nil, "", "", VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{SecureBoot: true}})
	if err == nil || !strings.Contains(err.Error(), "official archiso is unsigned") {
		t.Fatalf("unsigned installer was not refused before acquisition: %v", err)
	}
}

func TestBootstrapTrustDoesNotAffectVendorRecovery(t *testing.T) {
	m := &labv1.ImageManifest{Distribution: "ubuntu", Version: "24.04"}
	selected := EncryptedFirmwareOptions{SecureBoot: true, OwnedDBCertificate: "owner.pem"}
	if _, err := recoveryBootstrapFirmware(m, selected, "setup.fd", ""); err == nil {
		t.Fatal("vendor baseline admitted Arch bootstrap transition")
	}
	actual, err := recoveryBootstrapFirmware(m, selected, "", "")
	if err != nil || actual != selected {
		t.Fatalf("vendor flow changed: %+v, %v", actual, err)
	}
}

func TestBootstrapFirmwareCannotBeSilentlyIgnored(t *testing.T) {
	for _, phase := range []string{"", "live-actions", "live-erase"} {
		_, err := DeviceActionsVM(t.Context(), nil, VMDeviceActionsOptions{
			Scenario: "wipe", WipePhase: phase, BootstrapFirmwareVars: "setup.fd",
		})
		if err == nil || !strings.Contains(err.Error(), "explicit original-device recovery phase") {
			t.Fatalf("phase %q did not reject unused bootstrap trust: %v", phase, err)
		}
	}
}
