//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebianPreseedBindsUnencryptedTargetAndCredentials(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, version := range []string{"12", "13"} {
		for _, architecture := range []string{"x86_64", "aarch64"} {
			t.Run(version+"/"+architecture, func(t *testing.T) {
				digest := strings.Repeat("a", 64)
				recipe, err := debianInstallerRecipe(version, "/dev/vda", architecture, digest, login, private, public)
				if err != nil {
					t.Fatal(err)
				}
				values := make(map[string]string)
				for _, line := range strings.Split(string(recipe), "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						values[fields[1]] = strings.Join(fields[3:], " ")
					}
				}
				for name, want := range map[string]string{
					"partman-auto/method": "regular", "partman-auto/disk": "/dev/vda", "partman-auto/choose_recipe": "atomic",
					"passwd/root-login": "false", "passwd/user-password-crypted": "!", "passwd/username": "lindm-lab",
					"grub-installer/force-efi-extra-removable": "true", "debian-installer/exit/poweroff": "true",
				} {
					if values[name] != want {
						t.Fatalf("preseed %s=%q, want %q", name, values[name], want)
					}
				}
				suite := "trixie"
				if version == "12" {
					suite = "bookworm"
				}
				if values["mirror/suite"] != suite || values["mirror/http/hostname"] != "deb.debian.org" || !strings.Contains(values["pkgsel/include"], "cloud-init") {
					t.Fatal("installer lost suite, official repository or NoCloud provisioning")
				}
				late := values["preseed/late_command"]
				fields := strings.Split(late, "'")
				if len(fields) < 4 {
					t.Fatal("missing quoted late-command payload")
				}
				payload, err := base64.StdEncoding.DecodeString(fields[3])
				if err != nil {
					t.Fatal(err)
				}
				console := "ttyS0"
				if architecture == "aarch64" {
					console = "ttyAMA0"
				}
				for _, want := range []string{base64.StdEncoding.EncodeToString([]byte(login)), base64.StdEncoding.EncodeToString([]byte(private)), base64.StdEncoding.EncodeToString([]byte(public)), "console=" + console, "datasource_list: [ NoCloud ]", digest, "cloud-init clean", "update-grub"} {
					if !bytes.Contains(payload, []byte(want)) {
						t.Fatalf("installed provisioning lost %q", want)
					}
				}
				for _, script := range []string{late, string(payload)} {
					cmd := exec.Command("/bin/sh", "-n")
					cmd.Stdin = strings.NewReader(script)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("invalid provisioning shell: %v: %s", err, output)
					}
				}
			})
		}
	}
}

func TestDebianPreseedRejectsWrongAuthorityAndTarget(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, test := range []struct{ version, disk, arch, digest, login, private, public string }{
		{"11", "/dev/vda", "x86_64", strings.Repeat("a", 64), login, private, public},
		{"13", "/dev/host", "x86_64", strings.Repeat("a", 64), login, private, public},
		{"13", "/dev/vda", "riscv64", strings.Repeat("a", 64), login, private, public},
		{"13", "/dev/vda", "x86_64", "';false", login, private, public},
		{"13", "/dev/vda", "x86_64", strings.Repeat("a", 64), "invalid", private, public},
		{"13", "/dev/vda", "x86_64", strings.Repeat("a", 64), login, private, login},
	} {
		if _, err := debianInstallerRecipe(test.version, test.disk, test.arch, test.digest, test.login, test.private, test.public); err == nil {
			t.Fatal("invalid installer authority/target accepted")
		}
	}
}

func TestDebianGRUBPreservesVendorKernelAndInitrd(t *testing.T) {
	original := []byte("set default=0\nset timeout=30\nmenuentry 'Install' {\n linux /install.amd/vmlinuz quiet ---\n initrd /install.amd/initrd.gz\n}\n")
	for _, arch := range []string{"x86_64", "aarch64"} {
		patched, err := encryptedInstallerGRUBForMachine(original, "debian", arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"set default='Install'", "linux /install.amd/vmlinuz", "initrd /install.amd/initrd.gz", "preseed/file=/cdrom/lindm-seed/preseed.cfg", "auto=true priority=critical", "net.ifnames=0"} {
			if !bytes.Contains(patched, []byte(want)) {
				t.Fatalf("installer lost vendor payload/preseed argument %q", want)
			}
		}
		console := "console=ttyS0"
		if arch == "aarch64" {
			console = "console=ttyAMA0"
		}
		if !bytes.Contains(patched, []byte(console)) {
			t.Fatalf("missing architecture console: %s", patched)
		}
	}
	if _, err := prepareInstallerFileForMachine(t.Context(), t.TempDir(), nil, "debian", []byte("preseed"), "x86_64"); err == nil {
		t.Fatal("nil borrowed media accepted")
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	if _, err := prepareInstallerFileForMachine(t.Context(), t.TempDir(), dir, "debian", []byte("preseed"), "x86_64"); err == nil {
		t.Fatal("nonregular media accepted")
	}
}

func TestDebianInstalledCacheRejectsCorruptionAndSymlinks(t *testing.T) {
	root, err := openCache(t.Context(), filepath.Join(t.TempDir(), "cache"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.Mkdir("entry", 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("local installed disk fixture")
	if err := root.WriteFile("entry/image", data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if err := root.WriteFile("entry/sha256", []byte(fmt.Sprintf("%x\n", digest)), 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := loadInstalledImage(t.Context(), root, "entry"); err != nil || result.Size != int64(len(data)) {
		t.Fatalf("load integrity-bound local image: %v", err)
	}
	data[0] ^= 1
	if err := root.WriteFile("entry/image", data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstalledImage(t.Context(), root, "entry"); err == nil {
		t.Fatal("same-size cache corruption accepted")
	}
	if err := root.Symlink("entry", "link"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstalledImage(t.Context(), root, "link"); err == nil {
		t.Fatal("symlink cache entry accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadInstalledImage(ctx, root, "entry"); err == nil {
		t.Fatal("cancelled cache verification accepted")
	}
}

func TestDebianSourceMarkerProbePreservesPrivateMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root-only marker's digest")
	digest := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(digest+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path, digest string
		accepted           bool
	}{
		{"matching source", path, digest, true},
		{"wrong source", path, strings.Repeat("b", 64), false},
		{"missing marker", path + ".missing", digest, false},
		{"quoted input", path, "'; exit 0; #", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Execute the actual probe under the marker-owning account. Runtime
			// obtains that authority with sudo, not by making the marker public.
			cmd := exec.Command("/bin/sh", "-eu", "-c", installerSourceMarkerProbe(test.path, test.digest))
			if output, err := cmd.CombinedOutput(); (err == nil) != test.accepted {
				t.Fatalf("accepted=%t: %v: %s", test.accepted, err, output)
			}
		})
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("probe relaxed private marker permissions: %v", info.Mode())
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != digest+"\n" {
		t.Fatalf("probe changed source marker: %v", err)
	}
}
