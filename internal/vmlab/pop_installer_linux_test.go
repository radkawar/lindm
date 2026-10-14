// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"

	"lindm/internal/platform"
)

// popProvision decodes the base64 provisioning payload executed in the target.
func popProvision(t *testing.T, script string) string {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		encoded, ok := strings.CutSuffix(line, `' | base64 -d > "$target/root/lindm-provision"`)
		if !ok {
			continue
		}
		encoded, ok = strings.CutPrefix(encoded, "printf '%s' '")
		if !ok {
			t.Fatal("malformed provisioning payload")
		}
		payload, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return string(payload)
	}
	t.Fatal("install script has no provisioning payload")
	return ""
}

func popShellSyntax(t *testing.T, script []byte) {
	t.Helper()
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(string(script))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install script is not valid POSIX shell: %v: %s", err, out)
	}
}

// popTestMedia is the registry media of the pinned encrypted Pop manifest.
func popTestMedia(t *testing.T) encryptedMedia {
	t.Helper()
	m, err := LoadManifest("../../lab/images/pop-os-24.04-encrypted-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	return encryptedInstallerMedia(m)
}

func TestPopInstallerMirrorsVendorEraseLayout(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	digest := strings.Repeat("b", 64)
	plain, err := popInstallerRecipe("/dev/vda", "x86_64", digest, login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encryptedInstallerRecipeForMachine(popTestMedia(t), "lab-passphrase", login, private, public, "cosmic", false, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string][]byte{"plain": plain, "encrypted": encrypted} {
		t.Run(name, func(t *testing.T) {
			popShellSyntax(t, script)
			text := string(script)
			for _, want := range []string{
				`-n "$disk:primary:start:2097152:fat32:mount=/boot/efi:flags=esp"`,
				`-n "$disk:primary:2097152:10485760:fat32:mount=/recovery"`,
				`-n "$disk:primary:-8388608:end:swap"`,
				"--modify-boot --hardware-support",
				`sfdisk --no-reread --part-label "$disk" 2 recovery`,
				"systemctl is-active --quiet display-manager.service",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("install script lacks %q", want)
				}
			}
			root := `-n "$disk:primary:10485760:-8388608:ext4:mount=/"`
			if name == "encrypted" {
				root = `-n "$disk:primary:10485760:-8388608:enc=cryptdata,data,pass=lab-passphrase"`
				if !strings.Contains(text, "--logical data:root:end:ext4:mount=/") {
					t.Fatal("encrypted root lost the vendor LVM volume")
				}
			} else if strings.Contains(text, "enc=") || strings.Contains(text, "cryptsetup") {
				t.Fatal("unencrypted golden requested LUKS")
			}
			if !strings.Contains(text, root) {
				t.Fatalf("install script lacks root %q", root)
			}
			provision := popProvision(t, text)
			popShellSyntax(t, []byte(provision))
			if !strings.Contains(provision, "kernelstub") || !strings.Contains(provision, "'console=tty0 console=ttyS0,115200n8'") {
				t.Fatal("serial console is not configured through kernelstub")
			}
			if !strings.Contains(provision, "usermod -p '!' lindm-lab") || !strings.Contains(provision, "/etc/sudoers.d/lindm-lab") {
				t.Fatal("lab account is not locked or lacks sudo provisioning")
			}
			// Regression: an inherited umask 077 made distinst's /etc/hosts,
			// /etc/default/locale and the reset /etc/machine-id root-only, so
			// D-Bus activation of polkit, NetworkManager and accounts-daemon
			// timed out on the first installed boot.
			if before, _, _ := strings.Cut(text, "\ndistinst "); strings.Contains(before, "umask") {
				t.Fatal("distinst inherits a non-default umask")
			}
			if last := strings.LastIndex(provision, "\numask "); last < 0 || !strings.HasPrefix(provision[last:], "\numask 022\n") {
				t.Fatal("provisioning does not restore umask 022 after the credential files")
			}
			if name == "plain" {
				if !strings.Contains(provision, "apt-get -q -y install openssh-server cloud-init") || !strings.Contains(provision, "datasource_list: [ NoCloud ]") || !strings.Contains(provision, digest) {
					t.Fatal("unencrypted golden lacks NoCloud provisioning or its source marker")
				}
				if strings.Contains(provision, "initial_session") {
					t.Fatal("unencrypted golden enabled autologin")
				}
				return
			}
			if !strings.Contains(provision, "--delete-options '"+popVendorBootOptions+"'") {
				t.Fatal("encrypted golden keeps splash in front of the serial unlock prompt")
			}
			if !strings.Contains(provision, "[initial_session]\ncommand = \"start-cosmic\"\nuser = \"lindm-lab\"") {
				t.Fatal("COSMIC desktop golden lacks greetd autologin")
			}
		})
	}
	headless, err := encryptedInstallerRecipeForMachine(popTestMedia(t), "lab-passphrase", login, private, public, "", false, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(popProvision(t, string(headless)), "initial_session") {
		t.Fatal("headless encrypted golden enabled autologin")
	}
}

func TestPopInstallerRejectsUnrepresentableInputs(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, passphrase := range []string{"a:b", "a,b", "a b", "a'b"} {
		if _, err := encryptedInstallerRecipeForMachine(popTestMedia(t), passphrase, login, private, public, "", false, "x86_64"); err == nil {
			t.Fatalf("passphrase %q accepted although distinst would split or misquote it", passphrase)
		}
	}
	if _, err := encryptedInstallerRecipeForMachine(popTestMedia(t), "lab-passphrase", login, private, public, "gnome", false, "x86_64"); err == nil {
		t.Fatal("non-COSMIC desktop accepted")
	}
	if _, err := encryptedInstallerRecipeForMachine(popTestMedia(t), "lab-passphrase", login, private, public, "", false, "aarch64"); err == nil {
		t.Fatal("arm64 accepted for the x86_64-only row")
	}
	if _, err := popInstallerRecipe("/dev/vdb", "x86_64", strings.Repeat("b", 64), login, private, public); err == nil {
		t.Fatal("unowned disk accepted")
	}
	if _, err := popInstallerRecipe("/dev/vda", "x86_64", "unverified", login, private, public); err == nil {
		t.Fatal("unverified source digest accepted")
	}
}

func TestPopManifestsSelectInstallerLanes(t *testing.T) {
	plain, err := LoadManifest("../../lab/images/pop-os-24.04-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := LoadManifest("../../lab/images/pop-os-24.04-encrypted-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := installerImageFor(plain)
	if err != nil || spec == nil || spec.installer != platform.Distinst || spec.cache != "pop-installed" {
		t.Fatalf("plain Pop manifest did not select the distinst installer: %v", err)
	}
	if _, err := installerImageFor(encrypted); err == nil {
		t.Fatal("encrypted-lab Pop manifest booted as an unencrypted installer")
	}
	if _, err := popManifest(encrypted, popEncryptedInstallerEdition); err != nil {
		t.Fatal(err)
	}
	if _, err := popManifest(plain, popEncryptedInstallerEdition); err == nil {
		t.Fatal("encrypted lane admits the wrong Pop edition")
	}
}

func TestPopGRUBBootsSeedThroughSystemdRun(t *testing.T) {
	// The vendor ISO's single menu entry (generic build 28), verbatim.
	vendor := `set timeout=10
set timeout_style=menu
menuentry "Try or Install Pop_OS" --class pop-os {
	set gfxpayload=keep
	linux /casper_pop-os_24.04_amd64_generic_debug_681/vmlinuz.efi boot=casper live-media-path=/casper_pop-os_24.04_amd64_generic_debug_681 hostname=pop-os username=pop-os noprompt quiet splash $extra_kernel_parameters ---
	initrd /casper_pop-os_24.04_amd64_generic_debug_681/initrd.gz
}
`
	patched, err := encryptedInstallerGRUBForMachine([]byte(vendor), platform.Distinst, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	var linux string
	for _, line := range strings.Split(string(patched), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "linux ") {
			linux = strings.TrimSpace(line)
		}
	}
	want := `linux /casper_pop-os_24.04_amd64_generic_debug_681/vmlinuz.efi boot=casper live-media-path=/casper_pop-os_24.04_amd64_generic_debug_681 hostname=pop-os username=pop-os noprompt $extra_kernel_parameters "systemd.run=/bin/sh -eu /cdrom/lindm-seed/install.sh" systemd.run_success_action=poweroff systemd.run_failure_action=poweroff console=tty0 console=ttyS0,115200n8 ---`
	if linux != want {
		t.Fatalf("patched kernel line\n got %s\nwant %s", linux, want)
	}
	if !strings.Contains(string(patched), "set timeout=1\n") || strings.Contains(string(patched), "set timeout=10") {
		t.Fatal("vendor menu timeout was not shortened")
	}
}
