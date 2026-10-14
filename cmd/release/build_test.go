// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCustodyCannotEnterCapturedSource(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(t.Context(), "git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	git("init", "--quiet")
	keys := filepath.Join(root, "release-keys")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "custody.age"), []byte("encrypted custody fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refuseCapturedCustody(t.Context(), root, keys); err == nil {
		t.Fatal("unignored private custody selected for source capture was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("/release-keys/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refuseCapturedCustody(t.Context(), root, keys); err != nil {
		t.Fatalf("untracked ignored custody was refused: %v", err)
	}
	git("add", "--force", "release-keys/custody.age")
	if err := refuseCapturedCustody(t.Context(), root, keys); err == nil {
		t.Fatal("tracked ignored private custody selected for source capture was accepted")
	}
	if err := refuseCapturedCustody(t.Context(), root, root); err == nil {
		t.Fatal("source root accepted as custody directory")
	}
	if err := refuseCapturedCustody(t.Context(), root, t.TempDir()); err != nil {
		t.Fatalf("independent external custody was refused: %v", err)
	}
}

func TestOfflineSnapshotSelectionIsExplicit(t *testing.T) {
	connected, err := installerInputs("", "", "", "")
	if err != nil || connected.UbuntuSnapshot != "" || connected.RHELSnapshot != "" {
		t.Fatalf("connected build unexpectedly needs snapshot custody: %v", err)
	}
	ubuntu, err := installerInputs("ubuntu-24.04", "/approved/cache", "independent-ubuntu-pin", "")
	if err != nil || ubuntu.UbuntuSnapshot == "" || ubuntu.RHELSnapshot != "" {
		t.Fatalf("Ubuntu-only selection changed: %v", err)
	}
	for _, item := range [][4]string{
		{"rhel-9", "", "", ""},
		{"ubuntu-24.04", "/approved/cache", "", ""},
		{"", "/approved/cache", "", ""},
		{"", "", "unselected-pin", ""},
		{"ubuntu-24.04,ubuntu-24.04", "/approved/cache", "pin", ""},
		{"unknown", "/approved/cache", "pin", ""},
	} {
		if _, err := installerInputs(item[0], item[1], item[2], item[3]); err == nil {
			t.Fatalf("incomplete or unselected snapshot inputs accepted: %v", item)
		}
	}
}
