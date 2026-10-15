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
	if slices.Contains(args, "-device-manifest") {
		t.Fatal("default matrix deployment changed its managed-device image")
	}
	input.DeviceManifest = "relative-device.json"
	put()
	if _, err := readMatrixDeployInputs(path); err == nil {
		t.Fatal("accepted relative independent managed-device manifest")
	}
	input.DeviceManifest = "/images/managed-device.json"
	put()
	read, err = readMatrixDeployInputs(path)
	if err != nil {
		t.Fatal(err)
	}
	args = read.args()
	if args[len(args)-2] != "-device-manifest" || args[len(args)-1] != input.DeviceManifest {
		t.Fatalf("matrix lost independent device image: %v", args)
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
	for _, images := range []map[string]string{
		{"15": "docker.io/library/postgres@sha256:" + strings.Repeat("a", 64)},
		{"017": "docker.io/library/postgres@sha256:" + strings.Repeat("a", 64)},
		{"17": "postgres:17"},
		{"18": ""},
	} {
		input.DrillImages = images
		put()
		if _, err := readMatrixDeployInputs(path); err == nil {
			t.Fatal("accepted unpinned or unsupported recovery client image")
		}
	}
	input.DrillImages = map[string]string{"17": "docker.io/library/postgres@sha256:" + strings.Repeat("a", 64)}
	put()
	if _, err := readMatrixDeployInputs(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMatrixDeployInputs(path); err == nil {
		t.Fatal("accepted public-writable/public-readable protected inputs")
	}
}
