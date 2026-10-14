// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDeployBuildDoesNotAcceptHostPrivateSigningInputs(t *testing.T) {
	for _, flag := range []string{"-passphrase", "-passphrase-file", "-signer", "-identity-file", "-custody-key-file"} {
		if err := runDeployBuildAdmitted(context.Background(), []string{flag, "private-input"}, io.Discard, io.Discard); err == nil {
			t.Errorf("cold build accepted host secret input %s", flag)
		}
	}
}

func TestColdGuestDoesNotAcceptPrivateSigningArguments(t *testing.T) {
	for _, flag := range []string{"-passphrase", "-passphrase-file", "-signer", "-identity-file", "-custody-key-file"} {
		if err := runDeployColdGuest(context.Background(), []string{flag, "private-input"}, io.Discard); err == nil {
			t.Errorf("cold guest accepted secret input %s", flag)
		}
	}
	if err := runDeployColdGuest(context.Background(), []string{"private-input"}, io.Discard); err == nil {
		t.Fatal("cold guest accepted a positional private input")
	}
}

func TestColdGuestRaisesOwnMemoryAllowanceBeforeCustody(t *testing.T) {
	const child = "LINDM_TEST_COLD_GUEST_MEMORY"
	if os.Getenv(child) == "1" {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		args := []string{"-revision", strings.Repeat("0", 40), "-epoch", "1791962681", "-first-version", "0.2.0", "-newer-version", "0.2.1"}
		err := runDeployColdGuest(ctx, args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "deploy requires authorized noninteractive sudo/prlimit") {
			t.Fatalf("custody ran before process-only memory preparation: %v", err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestColdGuestRaisesOwnMemoryAllowanceBeforeCustody$")
	command.Env = append(os.Environ(), child+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated memory-allowance regression: %v\n%s", err, output)
	}
}

func TestColdBuildEvidenceCannotQualifyDeployOrLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cold.json")
	if err := os.WriteFile(path, []byte(`{"scope":"production-cold-release-build-only","lifecycle_qualified":false,"passed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cell := range []string{"deploy", "lifecycle"} {
		for _, scope := range []string{"", "production-cold-release-build-only"} {
			if _, err := matrixImportEvidenceSHA256(path, cell, scope); err == nil {
				t.Errorf("cold build qualified %s with scope %q", cell, scope)
			}
		}
	}
}
