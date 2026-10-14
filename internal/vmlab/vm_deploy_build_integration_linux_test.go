// SPDX-License-Identifier: Apache-2.0
//go:build linux && integration

package vmlab

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This verifies already-built real signed exports after private transport. It
// does not change a failed SDK record into a cold-build or lifecycle pass.
func TestColdProductionExportsVerifyAfterPrivateTransport(t *testing.T) {
	directory := os.Getenv("LINDM_TEST_COLD_RELEASE_EXPORTS")
	if directory == "" {
		t.Skip("requires protected exports and the original real cold VM record")
	}
	body, err := os.ReadFile(directory + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var original VMDeployBuildResult
	if err := json.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	paths := []string{"keys/custody.age", "keys/pins.sig", "first/release.json.dsse", "newer/release.json.dsse", "first/agent-repository/release.json.dsse", "newer/agent-repository/release.json.dsse", "first/install.sh", "newer/install.sh", "first/installer.sha256.sig", "newer/installer.sha256.sig"}
	before := make(map[string][32]byte, len(paths))
	for _, name := range paths {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = sha256.Sum256(content)
	}
	custodyBefore, err := os.Stat(filepath.Join(directory, "keys/custody.age"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "newer"} {
		for _, executable := range []string{"install.sh", "lindm-install"} {
			if err := os.Chmod(filepath.Join(directory, name, executable), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	options := VMDeployBuildOptions{EvidenceDirectory: directory, Revision: original.SourceRevision, FirstVersion: original.FirstVersion, NewerVersion: original.NewerVersion}
	result := original
	if err := verifyColdReleaseExports(t.Context(), &result, options); err != nil {
		t.Fatal(err)
	}
	if result.Passed != original.Passed || result.LifecycleQualified || result.ReleaseKeyID != original.ReleaseKeyID {
		t.Fatal("artifact verification promoted the original SDK scope or changed its pin")
	}
	for _, name := range paths {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || sha256.Sum256(content) != before[name] {
			t.Fatalf("transport normalization changed custody or signed bytes: %s: %v", name, err)
		}
	}
	custodyAfter, err := os.Stat(filepath.Join(directory, "keys/custody.age"))
	if err != nil || custodyAfter.Mode() != custodyBefore.Mode() {
		t.Fatalf("public normalization changed custody mode: %v", err)
	}
	for _, name := range []string{"first", "newer"} {
		for _, executable := range []string{"install.sh", "lindm-install"} {
			info, err := os.Stat(filepath.Join(directory, name, executable))
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatalf("signed public executable lacks its canonical mode: %s/%s: %v", name, executable, err)
			}
		}
	}
	options.Revision = strings.Repeat("0", 40)
	if err := verifyColdReleaseExports(t.Context(), &result, options); err == nil {
		t.Fatal("signed export accepted a different source revision")
	}
}
