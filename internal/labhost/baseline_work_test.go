// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaselineWorkDirectoryPrivacy(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(parent, "lab")
	run := func() ([]byte, error) { return exec.Command("bash", "-euc", baselineWorkScript(work)).CombinedOutput() }
	data, err := run()
	if err != nil || strings.TrimSpace(string(data)) != "true" {
		t.Fatalf("create: %s: %v", data, err)
	}
	data, err = run()
	if err != nil || strings.TrimSpace(string(data)) != "false" {
		t.Fatalf("reuse: %s: %v", data, err)
	}
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	if data, err = run(); err == nil {
		t.Fatalf("accepted writable ancestry: %s", data)
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0770 {
		t.Fatalf("changed shared parent: %v, %v", info, err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(work, 0755); err != nil {
		t.Fatal(err)
	}
	if data, err = run(); err == nil {
		t.Fatalf("accepted nonprivate work: %s", data)
	}
}
