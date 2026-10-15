// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"lindm/internal/labhost"
)

// A queued lane must boot the exact planned snapshot, not a newly edited pin.
func TestRetainMatrixManifestRejectsChangedPin(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	data := []byte(`{"repositorySnapshotDate":"2026-10-02"}`)
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	pinned := filepath.Join(dir, "retained.json")
	if err := retainMatrixManifest(source, pinned, digest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(`{"repositorySnapshotDate":"2026-10-09"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(pinned)
	if err != nil || string(retained) != string(data) {
		t.Fatalf("retained manifest changed: %q, %v", retained, err)
	}
	if err := retainMatrixManifest(source, filepath.Join(dir, "changed.json"), digest); err == nil {
		t.Fatal("queued manifest change was accepted")
	}
	if err := retainMatrixManifest(source, pinned, digest); err == nil {
		t.Fatal("existing evidence was overwritten")
	}
}

func TestMatrixOwnerSelectedBootTopology(t *testing.T) {
	selection := matrixSelection{root: "../..", platforms: "arch", cells: "encrypted", architecture: "x86_64", manifestID: "arch-20261001-encrypted-systemd-boot-x86-64"}
	_, cells, err := selection.plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].Manifest == nil || cells[0].Manifest.Image.GetId() != selection.manifestID {
		t.Fatal("matrix did not retain the owner's selected systemd-boot topology")
	}
	selection.architecture = "aarch64"
	if _, _, err := selection.plan(); err == nil {
		t.Fatal("a manifest from another architecture was accepted")
	}
}

func TestAdvisoryRecordScopeNeverInventsFullCoverage(t *testing.T) {
	for _, scope := range []string{"", "complete", "partial-feed matching"} {
		file := filepath.Join(t.TempDir(), "record.json")
		if err := os.WriteFile(file, []byte(fmt.Sprintf(`{"advisories":{"scope":%q}}`, scope)), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := advisoryRecordScope(file)
		if scope == "partial-feed matching" {
			if err != nil || got != scope {
				t.Fatalf("partial scope changed: %q %v", got, err)
			}
		} else if err == nil {
			t.Fatal("unqualified coverage scope was accepted")
		}
	}
}

func TestMatrixActionCellsRequireTheirCompleteNativeProof(t *testing.T) {
	for _, tc := range []struct{ cell, required string }{
		{"encrypted", "-scenario=encryption"},
		{"tpm-unattended-boots", "-tpm-boots=30"},
		{"tpm-reference-repair", "-encryption-phase=tpm-repair"},
		{"device-actions", "-wipe-phase=live-actions"},
		{"recovery-sanitize", "-wipe-phase=recovery-nvme"},
	} {
		selection := matrixSelection{root: "../..", platforms: "arch", cells: tc.cell, architecture: "x86_64"}
		_, cells, err := selection.plan()
		if err != nil {
			t.Fatal(err)
		}
		if len(cells) != 1 || cells[0].Spec.GetLane() != "device-actions" || !slices.Contains(cells[0].Spec.GetArgs(), tc.required) {
			t.Fatalf("%s omitted native proof %s", tc.cell, tc.required)
		}
	}
}

// Arch media has no vendor Secure Boot trust: its Secure Boot TPM cell boots the
// systemd-boot installer edition and enrolls a run-only owner signer, which
// needs the noSB bootstrap template.
func TestMatrixOwnerKeyTPMCellUsesOwnedBootTopology(t *testing.T) {
	selection := matrixSelection{root: "../..", platforms: "arch", cells: "tpm-unattended-boots", architecture: "x86_64"}
	in, cells, err := selection.plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 || cells[0].Manifest == nil || cells[0].Manifest.Image.GetEdition() != cells[0].Release.Lab.RecoveryInstallerEdition {
		t.Fatal("owner-key TPM cell did not select the systemd-boot installer edition")
	}
	run := &matrixRun{root: "../..", archArgs: in.Matrix.GetArchitectureArgs(), secureBootArgs: in.Matrix.GetSecureBootArgs()}
	if _, err := run.laneArgs(cells[0], t.TempDir()+"/cell"); err == nil {
		t.Fatal("owner-key Secure Boot cell ran without a bootstrap template")
	}
	run.bootstrapFirmwareVars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
	args, err := run.laneArgs(cells[0], t.TempDir()+"/cell")
	if err != nil {
		t.Fatal(err)
	}
	if labhost.FlagValue(args, "bootstrap-firmware-vars") != run.bootstrapFirmwareVars || !slices.Contains(args, "-secure-boot") {
		t.Fatalf("owner-key TPM cell args %v", args)
	}
}

func TestMatrixDeployRetainsExplicitHostFirmwareArguments(t *testing.T) {
	selection := matrixSelection{root: "../..", platforms: "debian-13", cells: "deploy", architecture: "x86_64"}
	in, cells, err := selection.plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 1 {
		t.Fatal("native deployment cell missing")
	}
	run := &matrixRun{root: "../..", archArgs: in.Matrix.GetArchitectureArgs(), deploy: &deployMatrixInputs{}}
	args, err := run.laneArgs(cells[0], t.TempDir()+"/cell")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"firmware-code", "firmware-vars", "firmware-package", "firmware-version"} {
		want := labhost.FlagValue(in.Matrix.GetArchitectureArgs()["x86_64"].GetArgs(), flag)
		if want == "" || labhost.FlagValue(args, flag) != want {
			t.Fatalf("native deployment lost host %s: %v", flag, args)
		}
	}
}

// Original-device signed recovery refuses non-Secure-Boot firmware, so the
// cell's Microsoft-enrolled template must override the default and come last.
func TestMatrixSecureBootCellOverridesFirmwareTemplate(t *testing.T) {
	for _, tc := range []struct{ architecture, vars string }{
		{"x86_64", "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"},
		{"aarch64", "/usr/share/AAVMF/AAVMF_VARS.ms.fd"},
	} {
		selection := matrixSelection{root: "../..", platforms: "ubuntu-24.04", cells: "recovery-sanitize", architecture: tc.architecture}
		in, cells, err := selection.plan()
		if err != nil {
			t.Fatal(err)
		}
		if len(cells) != 1 || !cells[0].Spec.GetSecureBoot() {
			t.Fatal("recovery-sanitize does not require Secure Boot")
		}
		run := &matrixRun{root: "../..", archArgs: in.Matrix.GetArchitectureArgs(), secureBootArgs: in.Matrix.GetSecureBootArgs()}
		args, err := run.laneArgs(cells[0], t.TempDir()+"/cell")
		if err != nil {
			t.Fatal(err)
		}
		var vars string
		for _, arg := range args {
			if value, ok := strings.CutPrefix(arg, "-firmware-vars="); ok {
				vars = value
			}
		}
		if vars != tc.vars || !slices.Contains(args, "-secure-boot") {
			t.Fatalf("%s: effective vars %q, args %v", tc.architecture, vars, args)
		}
		delete(run.secureBootArgs, tc.architecture)
		if _, err := run.laneArgs(cells[0], t.TempDir()+"/cell"); err == nil {
			t.Fatal("Secure Boot cell ran without Secure Boot firmware")
		}
	}
}
