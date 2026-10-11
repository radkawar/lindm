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
	for _, name := range []string{"systemctl", "apt-get"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho "+name+" \"$*\" >> "+nativeQuote(calls)+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
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
		"apt-get -q -o DPkg::Lock::Timeout=600 update",
		"apt-get -q -y -o DPkg::Lock::Timeout=600 install curl",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("calls = %q, want %q", lines, want)
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
