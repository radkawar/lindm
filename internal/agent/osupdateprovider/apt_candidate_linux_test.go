// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdateprovider

import (
	"os"
	"path/filepath"
	"testing"
)

// The scratch tree is the input to apt-config; APT's own parsing of it is
// qualified on Ubuntu guests, not here.
func TestAPTCandidateTreeReplacesOnlyTheOwnedPart(t *testing.T) {
	parts, scratch := t.TempDir(), t.TempDir()
	for name, content := range map[string]string{"20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n", "99lindm-os-update": "stale\n", "99zz-local": "x\n"} {
		if err := os.WriteFile(filepath.Join(parts, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(parts, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	tree, err := buildAPTCandidateTree(scratch, parts, renderAPTPeriodic())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(tree.parts)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("candidate tree has %d entries", len(entries))
	}
	for _, name := range []string{"20auto-upgrades", "99zz-local"} {
		target, err := os.Readlink(filepath.Join(tree.parts, name))
		if err != nil || target != filepath.Join(parts, name) {
			t.Fatalf("%s is not a link to the real part: %q %v", name, target, err)
		}
	}
	owned := filepath.Join(tree.parts, "99lindm-os-update")
	info, err := os.Lstat(owned)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("owned part is not the candidate file: %v %v", info, err)
	}
	if content, err := os.ReadFile(owned); err != nil || string(content) != string(renderAPTPeriodic()) {
		t.Fatalf("owned part = %q, %v", content, err)
	}
	if config, err := os.ReadFile(tree.config); err != nil || string(config) != "Dir::Etc::parts \""+tree.parts+"/\";\n" {
		t.Fatalf("APT_CONFIG = %q, %v", config, err)
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	if left, err := os.ReadDir(scratch); err != nil || len(left) != 0 {
		t.Fatalf("scratch tree not removed: %v %v", left, err)
	}
	if content, err := os.ReadFile(filepath.Join(parts, "99lindm-os-update")); err != nil || string(content) != "stale\n" {
		t.Fatal("candidate tree touched the real configuration part")
	}
}

func TestAPTCandidateTreeFailureLeavesNoScratch(t *testing.T) {
	scratch := t.TempDir()
	if _, err := buildAPTCandidateTree(scratch, filepath.Join(scratch, "missing"), renderAPTPeriodic()); err == nil {
		t.Fatal("missing APT parts directory accepted")
	}
	if left, err := os.ReadDir(scratch); err != nil || len(left) != 0 {
		t.Fatalf("failed build left scratch entries: %v %v", left, err)
	}
}
