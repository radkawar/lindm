// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/deploylab"
	"lindm/internal/platform"
)

func TestDeploySetupCannotQualifyFullLifecycle(t *testing.T) {
	for _, runErr := range []error{nil, errors.New("owned cleanup failed")} {
		result := &VMDeploySetupResult{Scope: "deploy", LifecycleQualified: true, Passed: true, OwnedCleanupComplete: true, StartedAt: time.Now().UTC()}
		finishDeploySetupResult(result, runErr)
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal(body, &record); err != nil {
			t.Fatal(err)
		}
		qualified, present := record["lifecycle_qualified"]
		if record["scope"] != deploylab.FirstRunInstallScope || !present || qualified != false {
			t.Fatalf("first-owner result promoted to lifecycle evidence: %s", body)
		}
		if result.FinishedAt.IsZero() || (runErr != nil && (result.Passed || result.OwnedCleanupComplete)) {
			t.Fatalf("failed owned cleanup was promoted to success: %+v", result)
		}
	}
}

func TestDeploySetupOptionsDoNotAcceptPrivateBackupOrNewerRelease(t *testing.T) {
	options := reflect.TypeFor[VMDeploySetupOptions]()
	for _, name := range []string{"UpgradeRelease", "BackupIdentityFile", "BackupIdentityPassphrase", "VerifyBackup", "Recovery"} {
		if _, present := options.FieldByName(name); present {
			t.Errorf("first-run-only API exposes full lifecycle input %s", name)
		}
	}
}

func TestDeploySetupAirgapHardwareAndInstaller(t *testing.T) {
	for _, airgap := range []bool{false, true} {
		hardware, err := deployServerHardware(airgap, nil)
		if err != nil {
			t.Fatal(err)
		}
		if hardware.Architecture != "x86_64" || hardware.Accelerator != "kvm" || hardware.AllowNetwork == airgap || hardware.minimumDiskBytes != deployServerDiskBytes {
			t.Fatalf("wrong native server network policy for airgap=%t: %+v", airgap, hardware)
		}
		resolved, err := resolveVMHardware(hardware, "amd64")
		if err != nil || resolved.minimumDiskBytes != 32<<30 {
			t.Fatalf("server overlay budget was lost: %v", err)
		}
		command := deployInstallerCommand(VMDeployOptions{ReleaseKeyID: "independent-pin"}, "/root/signed-release", "https://localhost:18444", "https://localhost:18445", "0.2.1", airgap)
		if strings.Contains(command, " --airgap") != airgap {
			t.Fatalf("installer mode differs from guest network policy for airgap=%t", airgap)
		}
		for _, required := range []string{"--custody-passphrase-fd 0", "--release-key-file", "--release-key-id", "--backup-recipient-file", "cmp -s /root/lindm-deploy-input/tuf-root", "/root/signed-release/release-root.json", "--setup-code-file", "/usr/bin/lindmd version"} {
			if !strings.Contains(command, required) {
				t.Errorf("airgap=%t omitted existing protected native installer input %q", airgap, required)
			}
		}
		if strings.Contains(command, "--tuf-root-file") {
			t.Fatal("maintained installer caller passed a flag absent from the real installer")
		}
		if strings.Contains(command, "--tls-") || strings.Contains(command, "/tls.") || strings.Contains(command, "/tls-ca.") {
			t.Fatal("default native proof bypasses generated TLS with a laboratory certificate")
		}
	}
}

func TestDeployServerDiskFloorLeavesOtherNativeLanesUnchanged(t *testing.T) {
	server, err := deployServerHardware(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		hardware *VMHardwareOptions
		want     int64
	}{{server, 32 << 30}, {&VMHardwareOptions{Architecture: "x86_64", Accelerator: "kvm"}, 10 << 30}} {
		hardware, err := resolveVMHardware(test.hardware, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		size, err := guestOverlayBytes(1<<30, hardware.minimumDiskBytes)
		if err != nil || size != test.want {
			t.Fatalf("native overlay floor=%d want=%d: %v", size, test.want, err)
		}
	}
}

func TestDeployHardwarePreservesExplicitFirmwareAndNativePolicy(t *testing.T) {
	firmware := &EncryptedFirmwareOptions{Code: "/firmware/code.fd", Vars: "/firmware/vars.fd", Package: "ovmf", Version: "pinned"}
	for _, airgap := range []bool{false, true} {
		supplied := VMHardwareOptions{Architecture: "amd64", Firmware: firmware, StorageBus: "virtio-scsi", TPM: true, ExtraDisks: 1, AllowNetwork: airgap, minimumDiskBytes: 1}
		before := supplied
		hardware, err := deployServerHardware(airgap, &supplied)
		if err != nil {
			t.Fatal(err)
		}
		want := before
		want.Architecture, want.Accelerator = "x86_64", "kvm"
		want.AllowNetwork, want.minimumDiskBytes = !airgap, deployServerDiskBytes
		if !reflect.DeepEqual(*hardware, want) || !reflect.DeepEqual(supplied, before) {
			t.Fatalf("explicit firmware or fixed native/network/disk policy changed: got=%+v supplied=%+v", hardware, supplied)
		}
	}
	for _, supplied := range []*VMHardwareOptions{{Architecture: "aarch64"}, {Accelerator: "tcg"}} {
		if _, err := deployServerHardware(false, supplied); err == nil {
			t.Fatal("non-native deployment hardware admitted")
		}
	}
}

func TestDeploySetupAirgapEvidenceRemainsFirstRunOnly(t *testing.T) {
	result := &VMDeploySetupResult{AirgapServerInstall: true, Passed: true, OwnedCleanupComplete: true, StartedAt: time.Now().UTC()}
	finishDeploySetupResult(result, nil)
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var observed map[string]any
	if err := json.Unmarshal(body, &observed); err != nil {
		t.Fatal(err)
	}
	if observed["airgap_server_install"] != true || observed["scope"] != deploylab.FirstRunInstallScope || observed["lifecycle_qualified"] != false {
		t.Fatalf("air-gap server install promoted to full lifecycle evidence: %s", body)
	}
}

func TestDeploySetupAdmissionFollowsNativeServerRegistry(t *testing.T) {
	for _, key := range []string{"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13", "rhel-9", "rhel-10", "rocky-9", "rocky-10", "almalinux-9", "almalinux-10"} {
		t.Run(key, func(t *testing.T) {
			release, ok := platform.Lookup(key)
			if !ok || release.Server == nil {
				t.Fatal("native server registry entry missing")
			}
			manifest := testManifest([]byte("pinned image"), strings.Repeat("A", 40), labv1.ChecksumMode_CHECKSUM_MODE_DETACHED)
			manifest.Distribution, manifest.Version = release.ID, release.Version.Value
			if release.Version.Rule == platform.VersionMajor {
				manifest.Version += ".1"
			}
			options := VMDeploySetupOptions{
				Browser: func(context.Context, deploylab.BrowserRequest) (*deploylab.BrowserEvidence, error) {
					t.Fatal("admission must not invoke browser")
					return nil, nil
				},
				LabBinary: "lab", EvidenceDirectory: "evidence", FirstRelease: "release",
				ReleasePublicKey: "release-key", ReleaseKeyID: "independent-pin", TUFRootFile: "tuf-root",
				BackupRecipientFile: "backup-recipient", CustodyEscrowRecipientFile: "escrow-recipient",
			}
			if release.Lab.Entitlement {
				if err := validateDeploySetupOptions(manifest, options); err == nil || !strings.Contains(err.Error(), "Red Hat entitlement") {
					t.Fatalf("entitled host admitted without Red Hat input: %v", err)
				}
				options.RedHatTokenFile = "protected-token"
			} else {
				options.RedHatTokenFile = "unrelated-token"
				if err := validateDeploySetupOptions(manifest, options); err == nil || !strings.Contains(err.Error(), "only valid for subscription-entitled") {
					t.Fatalf("unentitled host accepted Red Hat input: %v", err)
				}
				options.RedHatTokenFile = ""
			}
			for _, architecture := range []string{"amd64", "x86_64"} {
				manifest.Architecture = architecture
				if err := validateDeploySetupOptions(manifest, options); err != nil {
					t.Fatalf("registry-supported connected %s host rejected: %v", architecture, err)
				}
			}
			manifest.Architecture = "arm64"
			if err := validateDeploySetupOptions(manifest, options); err == nil {
				t.Fatal("connected x86_64 server admission escaped to arm64")
			}
			manifest.Architecture = "amd64"
			options.Airgap, options.RedHatTokenFile = true, ""
			err := validateDeploySetupOptions(manifest, options)
			if release.Server.ConnectedOnly {
				if err == nil || !strings.Contains(err.Error(), "requires connected installation") {
					t.Fatalf("connected-only host admitted airgap installation: %v", err)
				}
			} else if err != nil {
				t.Fatalf("existing offline-capable host rejected: %v", err)
			}
		})
	}
}
