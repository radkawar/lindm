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

// debian13-arm64-dgx21-device-actions-encryption-02: trixie's dracut writes
// progress to stderr, which the strict guest runner rejected. The oracle must
// rebuild exactly the registry initrd of the running kernel and judge success
// by exit status.
func TestCryptsetupConsoleRebuildsRegistryInitrd(t *testing.T) {
	root, bin := t.TempDir(), t.TempDir()
	args := filepath.Join(root, "dracut.args")
	for name, body := range map[string]string{
		"uname":  "echo 6.12.107+deb13-arm64\n",
		"dracut": "printf '%s\\n' \"$@\" > " + nativeQuote(args) + "\necho 'dracut: Generating initrd' >&2\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// ubuntu2604-amd64-local-encryption-03: resolute's systemd 259 left the
	// retired-key boot silent on the serial console, like trixie's 257.
	for _, test := range []struct{ release, want string }{
		{"debian-13", "/boot/initrd.img-6.12.107+deb13-arm64"},
		{"fedora-44", "/boot/initramfs-6.12.107+deb13-arm64.img"},
		{"ubuntu-26.04", "/boot/initrd.img-6.12.107+deb13-arm64"},
	} {
		release, ok := platform.Lookup(test.release)
		if !ok || !release.Lab.Guest.CryptsetupConsole {
			t.Fatalf("%s does not route rejected cryptsetup keys to the console", test.release)
		}
		script := strings.ReplaceAll(cryptsetupConsoleScript(release.Lab.Guest.Initrd), "/etc/", root+"/etc/")
		cmd := exec.Command("/bin/sh", "-eu", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", test.release, err, output)
		}
		data, err := os.ReadFile(args)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Split(strings.TrimSpace(string(data)), "\n")
		if !slices.Contains(got, "--quiet") || got[len(got)-2] != test.want || got[len(got)-1] != "6.12.107+deb13-arm64" {
			t.Fatalf("%s dracut arguments = %q", test.release, got)
		}
	}
	for _, key := range []string{"debian-12", "ubuntu-24.04"} {
		if release, _ := platform.Lookup(key); release.Lab.Guest.CryptsetupConsole {
			t.Fatalf("%s prints the rejection itself; it needs no initrd rebuild", key)
		}
	}
}

// QMP send-key needs a keyboard: q35 always has i8042, aarch64 virt has none,
// so Escape never closed Debian GNOME's login overview on the Sparks.
func TestEncryptedDesktopHasKeyboardOnEveryArchitecture(t *testing.T) {
	if devices := encryptedDesktopInputDevices("aarch64"); !slices.Contains(devices, "usb-kbd,bus=usb.0") {
		t.Fatalf("aarch64 desktop has no keyboard: %q", devices)
	}
	if devices := encryptedDesktopInputDevices("x86_64"); slices.Contains(devices, "usb-kbd,bus=usb.0") {
		t.Fatalf("x86_64 desktop tuple changed: %q", devices)
	}
}
