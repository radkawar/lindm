//go:build linux && integration

package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Actual APT and dpkg install a script-free fixture into a disposable root. No
// host package state, configuration, hooks, cache or network sources are used.
func TestAPTCanonicalStagingInstallsOfflineIntoPrivateRoot(t *testing.T) {
	for _, tool := range []string{"apt-get", "dpkg-deb", "dpkg-query"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("native archive regression requires %s: %v", tool, err)
		}
	}
	work := t.TempDir()
	root, transaction, packageRoot := filepath.Join(work, "root"), filepath.Join(work, "transaction"), filepath.Join(work, "package")
	state, logs, empty := filepath.Join(work, "apt-state"), filepath.Join(work, "apt-log"), filepath.Join(work, "empty")
	for _, directory := range []string{root, transaction, filepath.Join(transaction, "partial"), packageRoot, filepath.Join(packageRoot, "DEBIAN"), filepath.Join(packageRoot, "usr/share/lindm-update-test"), state, logs, empty, filepath.Join(root, "var/lib/dpkg/info"), filepath.Join(root, "var/lib/dpkg/updates")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(packageRoot, "DEBIAN"), 0755); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(root, "var/lib/dpkg/status")
	config := filepath.Join(work, "apt.conf")
	tx := &agentv1.AgentUpdateTransaction{Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, NativeVersion: "2:0.2.0-1", Architecture: runtime.GOARCH}
	payload := "native offline archive resolution evidence\n"
	for name, content := range map[string]string{
		status: "",
		filepath.Join(packageRoot, "DEBIAN/control"):                       "Package: lindm-agent\nVersion: " + tx.NativeVersion + "\nArchitecture: " + tx.Architecture + "\nMaintainer: Lindm test <test@invalid>\nDescription: script-free isolated update archive regression\n",
		filepath.Join(packageRoot, "usr/share/lindm-update-test/evidence"): payload,
		config: "Dir::Etc::main \"/dev/null\";\nDir::Etc::parts \"" + empty + "\";\nDir::Etc::sourcelist \"/dev/null\";\nDir::Etc::sourceparts \"" + empty + "\";\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + work, "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "APT_CONFIG=" + config}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private native %s failed: %v\n%s", name, err, output)
		}
		return output
	}
	archive := packagePath(transaction, tx)
	run("dpkg-deb", "--build", "--root-owner-group", packageRoot, archive)
	if err := os.Chmod(archive, 0600); err != nil {
		t.Fatal(err)
	}
	run("apt-get", "--assume-yes", "--no-download", "--no-remove", "--no-install-recommends",
		"-o", "Dir::Cache::archives="+transaction,
		"-o", "Dir::State="+state,
		"-o", "Dir::State::status="+status,
		"-o", "Dir::Log="+logs,
		"-o", "Dir::Cache::pkgcache=",
		"-o", "Dir::Cache::srcpkgcache=",
		"-o", "Dpkg::Options::=--root="+root,
		"-o", "Dpkg::Options::=--force-not-root",
		"-o", "Dpkg::Options::=--log="+filepath.Join(logs, "dpkg.log"),
		"install", archive)
	installed := run("dpkg-query", "--admindir="+filepath.Join(root, "var/lib/dpkg"), "--show", "--showformat=${Version}\t${Status}", "lindm-agent")
	if strings.TrimSpace(string(installed)) != tx.NativeVersion+"\tinstall ok installed" {
		t.Fatalf("private native installation not configured: %s", installed)
	}
	actual, err := os.ReadFile(filepath.Join(root, "usr/share/lindm-update-test/evidence"))
	if err != nil || string(actual) != payload {
		t.Fatalf("private native payload mismatch: %v", err)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("APT removed protected recovery archive: %v", err)
	}
}
