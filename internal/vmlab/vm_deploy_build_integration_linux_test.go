// SPDX-License-Identifier: Apache-2.0
//go:build linux && integration

package vmlab

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lindm/internal/releasebuild"
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
	script, err := os.ReadFile("../../deploy/server/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	var copyCommand string
	for _, line := range strings.Split(string(script), "\n") {
		if strings.HasPrefix(line, "cp -R ") {
			copyCommand = line
		}
	}
	if copyCommand == "" {
		t.Fatal("missing actual installer snapshot command")
	}
	for _, preserve := range []bool{false, true} {
		t.Run("snapshot_preserves_mode_"+strconv.FormatBool(preserve), func(t *testing.T) {
			work := t.TempDir()
			snapshot := filepath.Join(work, "bundle")
			if err := os.Mkdir(snapshot, 0700); err != nil {
				t.Fatal(err)
			}
			statement := copyCommand
			if !preserve {
				statement = strings.Replace(statement, "--preserve=mode ", "", 1)
			}
			command := exec.CommandContext(t.Context(), "sh", "-eu", "-c", "umask 077; "+statement+"\nchmod -R go-w -- \"$work/bundle\"")
			command.Env = append(os.Environ(), "bundle="+filepath.Join(directory, "first"), "work="+work)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("copy actual signed export: %v: %s", err, output)
			}
			_, err := releasebuild.Verify(t.Context(), snapshot, filepath.Join(directory, "keys/attestation.pub"), original.ReleaseKeyID)
			if preserve && err != nil {
				t.Fatalf("preserved public snapshot failed unchanged verification: %v", err)
			}
			if !preserve && (err == nil || !strings.Contains(err.Error(), "canonical agent repository provenance mismatch")) {
				t.Fatalf("private umask control did not reproduce native provenance failure: %v", err)
			}
		})
	}
}
