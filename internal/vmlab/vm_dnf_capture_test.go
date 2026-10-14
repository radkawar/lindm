// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration && dnfcapture

package vmlab

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

// CaptureDNFNativeForTest exposes the owned guest lifecycle only to the external
// integration test, where labhost admission does not create an import cycle.
func CaptureDNFNativeForTest(t *testing.T, ctx context.Context, manifest *labv1.ImageManifest, manifestPath, cache, work, output string, host *labv1.LabHost) {
	t.Helper()
	var helper []byte
	if path := os.Getenv("LINDM_DNF_CAPTURE_HELPER"); path != "" {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		helper, err = io.ReadAll(io.LimitReader(file, (64<<10)+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(helper) > 64<<10 {
			t.Fatalf("bounded helper snapshot: read %v; close %v; bytes %d", err, closeErr, len(helper))
		}
	}
	hardware := &VMHardwareOptions{}
	if code := os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_CODE"); code != "" {
		hardware.Firmware = &EncryptedFirmwareOptions{
			Code: code, Vars: os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_VARS"),
			Package: os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_PACKAGE"), Version: os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_VERSION"),
		}
	}
	vm, verified, err := newVerifiedGuestWithHardware(ctx, manifest, cache, work, false, hardware)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := vm.close(); err != nil {
			t.Error(err)
		}
	}()
	if err := vm.connect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	provenance := map[string]string{
		"captured_at": time.Now().UTC().Format(time.RFC3339),
		"manifest":    manifestPath, "image_id": manifest.GetId(),
		"image_sha256": verified.SHA256, "host": host.GetName(),
		"package_changes": "none", "purpose": "native interface research, not agent qualification",
		"firmware_code":    os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_CODE"),
		"firmware_vars":    os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_VARS"),
		"firmware_package": os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_PACKAGE"),
		"firmware_version": os.Getenv("LINDM_DNF_CAPTURE_FIRMWARE_VERSION"),
	}
	writeDNFCapture(t, filepath.Join(output, "provenance.json"), provenance)
	if os.Getenv("LINDM_CPU_CAPTURE") == "1" {
		captureCPUNative(t, ctx, vm, output)
		return
	}
	if os.Getenv("LINDM_SESSION_CAPTURE") == "1" {
		result, err := vm.runResult(ctx, "sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C python3 -I -", strings.NewReader(sessionCaptureScript), 1<<20, time.Minute)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("session capture: %v, exit %d: %s", err, result.ExitCode, result.Stderr)
		}
		if err := os.WriteFile(filepath.Join(output, "sessions.json"), result.Stdout, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	type captureProbe struct {
		name    string
		command string
		input   string
	}
	probes := []captureProbe{
		{"versions", "rpm -q dnf5 libdnf5 libdnf5-cli python3 python3-libdnf5 python3-dnf python3-rpm fedora-release-common fedora-repos", ""},
		{"dnf5-version", "dnf5 --version", ""},
		{"variables", "dnf5 --dump-variables", ""},
		{"repo-config", "dnf5 --dump-repo-config='*'", ""},
		{"python-bindings", "python3 -I -", dnfCaptureBindings},
		{"repo-info-config-only", "dnf5 --noplugins --cacheonly --disable-repo='*' repo info --all --json", ""},
		{"repo-list-enabled", "dnf5 --noplugins --cacheonly repo list --enabled --json", ""},
		{"repo-info-cacheonly", "dnf5 --cacheonly repo info --json", ""},
		{"repo-info", "dnf5 repo info --json", ""},
		{"module-help", "dnf5 module --help", ""},
		{"module-list-json", "dnf5 --cacheonly module list --enabled --json", ""},
		{"module-list", "dnf5 --cacheonly module list --enabled", ""},
	}
	if len(helper) != 0 {
		probes = append(probes, captureProbe{"collector-helper", "python3 -I - dnf5", string(helper)})
	}
	for _, probe := range probes {
		result, err := vm.runResult(ctx, "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/"+labUser+" LANG=C LC_ALL=C "+probe.command, strings.NewReader(probe.input), 1<<20, 3*time.Minute)
		if err != nil {
			t.Fatalf("%s transport: %v", probe.name, err)
		}
		writeDNFCapture(t, filepath.Join(output, probe.name+".json"), struct {
			Command  string `json:"command"`
			Input    string `json:"input,omitempty"`
			ExitCode int    `json:"exit_code"`
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
		}{probe.command, probe.input, result.ExitCode, string(result.Stdout), string(result.Stderr)})
		if probe.name == "versions" {
			t.Logf("native package versions:\n%s", result.Stdout)
		}
	}
}

// captureCPUNative shares the explicit dnfcapture admission and owned guest
// lifecycle. It records native evidence only; agent qualification is separate.
func captureCPUNative(t *testing.T, ctx context.Context, vm *guestVM, output string) {
	t.Helper()
	for _, probe := range []struct{ name, command string }{
		{"cpuinfo.txt", "cat /proc/cpuinfo"},
		{"midr_el1.txt", "cat /sys/devices/system/cpu/cpu0/regs/identification/midr_el1"},
		{"DMI.bin", "sudo -n cat /sys/firmware/dmi/tables/DMI"},
		{"dmidecode.txt", "sudo -n dmidecode --type 4"},
		{"lscpu.json", "lscpu --json"},
		{"lscpu.txt", "lscpu"},
		{"versions.txt", "rpm -q kernel-core util-linux dmidecode fedora-release-common; uname -a"},
	} {
		result, err := vm.runResult(ctx, "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c "+nativeQuote(probe.command), nil, 4<<20, time.Minute)
		if err != nil {
			t.Fatalf("%s transport: %v", probe.name, err)
		}
		writeDNFCapture(t, filepath.Join(output, probe.name+".result.json"), struct {
			Command  string `json:"command"`
			ExitCode int    `json:"exit_code"`
			Stderr   string `json:"stderr"`
		}{probe.command, result.ExitCode, string(result.Stderr)})
		if result.ExitCode == 0 {
			if err := os.WriteFile(filepath.Join(output, probe.name), result.Stdout, 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("CPU capture %s: exit %d, bytes %d", probe.name, result.ExitCode, len(result.Stdout))
	}
}

func writeDNFCapture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("capture write: %v; close: %v", writeErr, closeErr)
	}
}

// Only the owned ephemeral guest's logind records are captured. Each subprocess
// has a deadline and output bound, as does the outer native runner.
const sessionCaptureScript = `import json, subprocess, tempfile
def run(args):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.run(args, stdout=out, stderr=err, timeout=5, check=False)
        out.seek(0); err.seek(0)
        stdout = out.read(262145); stderr = err.read(4097)
        if p.returncode or len(stdout) > 262144 or len(stderr) > 4096:
            raise RuntimeError("bounded native command failed: " + args[0])
        return {"command": args, "stdout": stdout.decode(), "stderr": stderr.decode(), "exit_code": p.returncode}
base = ["busctl", "--system", "--json=short", "--timeout=5s", "--auto-start=no", "call", "org.freedesktop.login1"]
listing = run(base + ["/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListSessions"])
rows = json.loads(listing["stdout"])["data"][0]
if len(rows) > 32:
    raise RuntimeError("capture session bound exceeded")
records = []
for row in rows:
    native = run(base + [row[4], "org.freedesktop.DBus.Properties", "GetAll", "s", "org.freedesktop.login1.Session"])
    properties = json.loads(native["stdout"])["data"][0]
    if properties["Active"]["data"] is not True:
        continue
    loginctl = run(["loginctl", "show-session", "--all", "--no-pager", "-p", "Active", "-p", "Name", "-p", "Class", "-p", "Type", "-p", "Seat", "-p", "Remote", "--", row[0]])
    records.append({"busctl": native, "loginctl": loginctl})
print(json.dumps({"list_sessions": listing, "active_sessions": records}, indent=2))
`

const dnfCaptureBindings = `import importlib.util
import json

def optional_string(option):
    return "" if option.empty() else option.get_value()

availability = {name: importlib.util.find_spec(name) is not None for name in ("libdnf5", "dnf", "rpm")}
print(json.dumps({"bindings": availability}, sort_keys=True), flush=True)
if availability["libdnf5"]:
    import libdnf5
    base = libdnf5.base.Base()
    base.load_config()
    base.setup()
    print(json.dumps({"releasever": base.get_vars().get_value("releasever")}), flush=True)
    base.get_repo_sack().create_repos_from_system_configuration()
    repositories = []
    for repo in libdnf5.repo.RepoQuery(base):
        config = repo.get_config()
        repositories.append({"id": repo.get_id(), "enabled": config.get_enabled_option().get_value(), "base_urls": list(config.get_baseurl_option().get_value()), "metalink": optional_string(config.get_metalink_option()), "mirrorlist": optional_string(config.get_mirrorlist_option()), "gpgcheck": config.get_pkg_gpgcheck_option().get_value(), "gpg_keys": list(config.get_gpgkey_option().get_value())})
    print(json.dumps({"repositories": repositories}, sort_keys=True), flush=True)
    print(json.dumps({"module_api": hasattr(libdnf5, "module"), "module_sack_api": hasattr(base, "get_module_sack")}), flush=True)
    if hasattr(base, "get_module_sack"):
        sack = base.get_module_sack()
        print(json.dumps({"module_sack_methods": [name for name in dir(sack) if not name.startswith("_")]}), flush=True)
`
