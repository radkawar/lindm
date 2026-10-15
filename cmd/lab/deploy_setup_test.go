// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestDeploySetupRejectsFullLifecyclePrivateInputs(t *testing.T) {
	for _, flag := range []string{"-upgrade-release", "-backup-identity-file", "-backup-identity-passphrase-fd", "-lindmd", "-lindmctl"} {
		var output bytes.Buffer
		if err := runDeploySetupAdmitted(t.Context(), []string{flag, "unused"}, io.Discard, &output); err == nil {
			t.Errorf("setup accepted full lifecycle/private input %s", flag)
		}
	}
}

func TestDeploySetupRetainsSingleNativeGuestFootprint(t *testing.T) {
	if got := vmGuestCount("deploy-setup", nil); got != 1 {
		t.Fatalf("first-owner slice reserved %d guests, want one", got)
	}
	if got := vmGuestCount("deploy", nil); got != 3 {
		t.Fatalf("full lifecycle footprint changed to %d, want three", got)
	}
	cfg := &labv1.LabConfig{}
	for _, command := range []string{"deploy", "deploy-setup"} {
		if !vmHasHardwareFlags(command) {
			t.Fatalf("%s does not receive host firmware arguments", command)
		}
		for _, accelerator := range []string{"", "kvm", "tcg"} {
			if !vmRequiresKVM(cfg, command, accelerator, "amd64") {
				t.Fatal("native deployment allowed foreign TCG fallback")
			}
		}
	}
}

func TestDeployCommandsAcceptRoutedFirmwareFlags(t *testing.T) {
	for _, run := range []func(context.Context, []string, io.Writer, io.Writer) error{runDeployAdmitted, runDeploySetupAdmitted} {
		var diagnostics bytes.Buffer
		err := run(t.Context(), []string{"-firmware-code", "/firmware/code.fd", "-firmware-vars", "/firmware/vars.fd", "-firmware-package", "ovmf", "-firmware-version", "pinned", "-accelerator", "kvm"}, io.Discard, &diagnostics)
		if err == nil || !strings.Contains(err.Error(), "requires") || strings.Contains(diagnostics.String(), "flag provided but not defined") {
			t.Fatalf("deployment did not parse routed firmware before missing-input admission: %v %s", err, diagnostics.String())
		}
	}
}
