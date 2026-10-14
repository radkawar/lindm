// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"lindm/internal/deploylab"
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
		hardware := deploySetupHardware(airgap)
		if hardware.Architecture != "x86_64" || hardware.Accelerator != "kvm" || hardware.AllowNetwork == airgap {
			t.Fatalf("wrong native server network policy for airgap=%t: %+v", airgap, hardware)
		}
		command := deployInstallerCommand(VMDeployOptions{ReleaseKeyID: "independent-pin"}, "/root/signed-release", "https://localhost:18444", "https://localhost:18445", "0.2.1", airgap)
		if strings.Contains(command, " --airgap") != airgap {
			t.Fatalf("installer mode differs from guest network policy for airgap=%t", airgap)
		}
		for _, required := range []string{"--custody-passphrase-fd 0", "--release-key-file", "--release-key-id", "--tls-ca-file", "--backup-recipient-file", "--tuf-root-file", "--setup-code-file", "/usr/bin/lindmd version"} {
			if !strings.Contains(command, required) {
				t.Errorf("airgap=%t omitted existing protected native installer input %q", airgap, required)
			}
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
