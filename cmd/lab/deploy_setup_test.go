// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"io"
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
	if !vmRequiresKVM(cfg, "deploy-setup", "tcg", "amd64") {
		t.Fatal("setup-only slice allowed foreign TCG fallback")
	}
}
