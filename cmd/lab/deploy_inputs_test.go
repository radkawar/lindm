// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDeployMatrixInputsRequirePrivateIndependentArtifacts(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	input := deployMatrixInputs{FirstRelease: "/private/N", UpgradeRelease: "/private/N-plus-one", ReleasePublicKey: "/custody/attestation.pub", ReleaseKeyID: strings.Repeat("1", 64), TUFRootFile: "/custody/release-root.json", BackupRecipientFile: "/custody/backup-recipient", BackupIdentityFile: "/custody/backup-identity", Lindmd: "/private/bin/lindmd", Lindmctl: "/private/bin/lindmctl"}
	input.CustodyEscrowRecipientFile = "/protected-lab-escrow/recipient.txt"
	path := filepath.Join(directory, "inputs.json")
	put := func() {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	put()
	read, err := readMatrixDeployInputs(path)
	if err != nil {
		t.Fatal(err)
	}
	args := read.args()
	for _, flag := range []string{"-first-release", "-upgrade-release", "-release-public-key", "-release-key-id", "-tuf-root-file", "-backup-recipient-file", "-custody-escrow-recipient-file", "-backup-identity-file", "-lindmd", "-lindmctl"} {
		if !slices.Contains(args, flag) {
			t.Errorf("missing required signed lifecycle input %s", flag)
		}
	}
	input.FirstRelease = "relative-export"
	put()
	if _, err := readMatrixDeployInputs(path); err == nil {
		t.Fatal("accepted relative independently trusted release reference")
	}
	input.FirstRelease = "/private/N"
	input.BackupIdentityFile = ""
	put()
	if _, err := readMatrixDeployInputs(path); err == nil {
		t.Fatal("accepted missing offline backup custody")
	}
	input.BackupIdentityFile = "/custody/backup-identity"
	put()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMatrixDeployInputs(path); err == nil {
		t.Fatal("accepted public-writable/public-readable protected inputs")
	}
}
