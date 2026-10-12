//go:build linux

package vmlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"lindm/internal/platform"
)

// debian13-arm64-dgx21-device-actions-encryption-03: packagekitd held the APT
// lists lock right after login and apt-get update failed at once. The lab
// stops PackageKit for this boot before APT and waits for dpkg's lock.
// pop2404-lock-quarantine-01: a vendor boot-time apt-get held the lists lock;
// the lab waits for running apt processes before its own update.
func TestLabAPTInstallStopsPackageKitFirst(t *testing.T) {
	release, ok := platform.Lookup("debian-13")
	if !ok {
		t.Fatal("registry lacks debian-13")
	}
	command, err := labInstallCommand(release, []string{"curl"})
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	running := filepath.Join(t.TempDir(), "running")
	for _, name := range []string{"systemctl", "apt-get", "sleep"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho "+name+" \"$*\" >> "+nativeQuote(calls)+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A boot-time apt-get is visible to the first two checks, then exits.
	pgrep := "#!/bin/sh\n[ \"$2\" = apt-get ] || exit 1\necho x >> " + nativeQuote(running) + "\n[ $(wc -l < " + nativeQuote(running) + ") -le 2 ]\n"
	if err := os.WriteFile(filepath.Join(bin, "pgrep"), []byte(pgrep), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "dpkg-query"), []byte("#!/bin/sh\necho not-installed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-eu", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{
		"systemctl cat packagekit.service",
		"systemctl mask --runtime --now packagekit.service",
		"sleep 1",
		"sleep 1",
		"apt-get -q -o DPkg::Lock::Timeout=600 update",
		"apt-get -q -y -o DPkg::Lock::Timeout=600 install curl",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("calls = %q, want %q", lines, want)
	}
}

// ubuntu24-tier1-07: a first-boot unattended-upgrades run outlasted the setup
// bound although the golden already had every witness package. Installed
// packages skip the APT wait and refresh entirely.
func TestLabAPTInstallSkipsInstalledPackages(t *testing.T) {
	release, ok := platform.Lookup("debian-13")
	if !ok {
		t.Fatal("registry lacks debian-13")
	}
	command, err := labInstallCommand(release, []string{"curl", "jq"})
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	for _, name := range []string{"systemctl", "apt-get", "sleep", "pgrep"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho "+name+" >> "+nativeQuote(calls)+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for status, wantCalls := range map[string]bool{"installed\ninstalled": false, "installed\nnot-installed": true, "installed": true} {
		_ = os.Remove(calls)
		if err := os.WriteFile(filepath.Join(bin, "dpkg-query"), []byte("#!/bin/sh\nprintf '"+status+"\\n'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-eu", "-c", command)
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%q: %v: %s", status, err, output)
		}
		if _, err := os.Stat(calls); (err == nil) != wantCalls {
			t.Errorf("dpkg status %q: APT ran = %t, want %t", status, err == nil, wantCalls)
		}
	}
}

// Debian's GNOME task does not pull in gst-launch-1.0, so assistance ended
// gst_launch_missing (debian13-arm64-dgx20-assistance-02). The installed
// capture stack must include the tools the session helper executes.
func TestDebianCaptureStackIncludesGStreamerTools(t *testing.T) {
	for _, key := range []string{"debian-12", "debian-13"} {
		release, _ := platform.Lookup(key)
		if !slices.Contains(release.Lab.Session.Capture, "gstreamer1.0-tools") {
			t.Errorf("%s capture stack lacks gstreamer1.0-tools: %q", key, release.Lab.Session.Capture)
		}
	}
}
