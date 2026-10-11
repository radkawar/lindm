//go:build linux

package vmlab

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"lindm/internal/platform"
)

// elRebuildVendorGRUB is the vendor EFI/BOOT/grub.cfg published in the Rocky
// 9.8 aarch64 BaseOS boot tree (identical in layout for Rocky 10.2 and
// AlmaLinux 9.8/10.2; only the volume label differs). @VOLID@ is substituted.
const elRebuildVendorGRUB = `set default="1"

load_video
set gfxpayload=keep
insmod gzio
insmod part_gpt
insmod ext2

set timeout=60
### END /etc/grub.d/00_header ###

search --no-floppy --set=root -l '@VOLID@'

### BEGIN /etc/grub.d/10_linux ###
menuentry 'Install' --class red --class gnu-linux --class gnu --class os {
	linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=@VOLID@ ro
	initrd /images/pxeboot/initrd.img
}
menuentry 'Test this media & install' --class red --class gnu-linux --class gnu --class os {
	linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=@VOLID@ rd.live.check
	initrd /images/pxeboot/initrd.img
}
`

// Rocky Linux and AlmaLinux install GNOME from the vendor DVD only. The
// AppStream comps of all eight pinned Rocky/AlmaLinux 9.8/10.2 DVDs carry
// graphical-server-environment with gnome-desktop (gdm, gnome-shell); the
// aarch64 comps have no workstation-product-environment, and the first Rocky
// 10.2 aarch64 install stopped at Anaconda's "missing groups or modules:
// @workstation-product-environment" prompt. The x86_64 and aarch64 recipes are
// therefore the same Server-with-GUI kickstart apart from the console.
func TestEncryptedELRebuildDVDRecipes(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	firmware := EncryptedFirmwareOptions{Code: "code.fd", Vars: "vars.fd", Package: "qemu-efi-aarch64", Version: "pinned"}
	for _, tc := range []struct{ distribution, version, label, terminal string }{
		{"rocky", "9.8", "Rocky-9-8-aarch64-dvd", "gnome-terminal"},
		{"rocky", "10.2", "Rocky-10-2-aarch64-dvd", "ptyxis"},
		{"almalinux", "9.8", "AlmaLinux-9-8-aarch64-dvd", "gnome-terminal"},
		{"almalinux", "10.2", "AlmaLinux-10-2-aarch64-dvd", "ptyxis"},
	} {
		release := platform.ForManifest(tc.distribution, tc.version)
		media := encryptedMedia{release: release}
		for _, c := range []platform.Capability{platform.Encryption, platform.Wipe, platform.ReportLoss, platform.Lock, platform.Assistance} {
			if err := release.Gate(c); err != nil {
				t.Errorf("%s: %v", release.Name, err)
			}
		}
		if err := release.Gate(platform.RecoverySanitize); err == nil {
			t.Errorf("%s: recovery sanitize admitted without a native pass", release.Name)
		}
		if release.Lab.Entitlement || len(release.Lab.Session.Terminal) == 0 || release.Lab.Session.Terminal[0] != tc.terminal {
			t.Errorf("%s: entitlement %t, terminal %q", release.Name, release.Lab.Entitlement, release.Lab.Session.Terminal)
		}
		if _, err := encryptedInstallerRecipeWithOptions(media, "lab-passphrase", login, private, public, "kde", true); err == nil {
			t.Errorf("%s accepted a desktop absent from its DVD", release.Name)
		}
		manifest, err := LoadManifest(fmt.Sprintf("../../lab/images/%s-%s-encrypted-aarch64.json", tc.distribution, tc.version))
		if err != nil {
			t.Fatal(err)
		}
		if manifest.GetArchitecture() != "aarch64" || !strings.HasSuffix(manifest.GetImageFilename(), ".iso") || manifest.GetImageSizeBytes() < 1<<30 || manifest.GetSignerProvenanceUrl() == "" || !strings.Contains(manifest.GetImageUrl(), "/isos/aarch64/") || !strings.Contains(manifest.GetReleaseProvenanceUrl(), "/isos/aarch64/") {
			t.Fatalf("%s aarch64 installer acquisition lacks a pinned vendor DVD and provenance", release.Name)
		}
		hardware, err := encryptedMachineHardware(manifest, EncryptedVMOptions{Firmware: firmware, Hardware: &VMHardwareOptions{Accelerator: "tcg", TPM: true}})
		if err != nil || hardware.Architecture != "aarch64" || !encryptedGuestTPMObservable(manifest, hardware.Architecture) {
			t.Fatalf("%s DVD did not select a TPM-observable aarch64 machine: %+v, %v", release.Name, hardware, err)
		}
		for _, architecture := range []string{"x86_64", "aarch64"} {
			t.Run(fmt.Sprintf("%s-%s/%s", tc.distribution, tc.version, architecture), func(t *testing.T) {
				recipe, err := encryptedInstallerRecipeForMachine(media, "lab-passphrase", login, private, public, "gnome", true, architecture)
				if err != nil {
					t.Fatal(err)
				}
				text := string(recipe)
				packagesText, post, ok := strings.Cut(text, "%post --erroronfail --interpreter=/bin/sh\n")
				if !ok {
					t.Fatal("missing installed-root provisioning")
				}
				_, packageList, ok := strings.Cut(packagesText, "%packages\n")
				if !ok {
					t.Fatal("missing package selection")
				}
				selected := strings.Fields(strings.TrimSuffix(packageList, "%end\n"))
				if selected[0] != "@^graphical-server-environment" || slices.Contains(selected, "@^workstation-product-environment") {
					t.Errorf("GNOME environment is not the DVD's Server with GUI: %q", selected)
				}
				for _, required := range []string{"@core", "cryptsetup", "nftables", "iproute", "iputils", "systemd-udev", "tpm2-tools", "tpm2-tss", "bind-utils", "curl", "openssh-server", "sudo"} {
					if !slices.Contains(selected, required) {
						t.Errorf("golden omits %q", required)
					}
				}
				for _, forbidden := range []string{"dnf5", "--repofrompath", "#version=", "group install", "busybox", "sbsigntool", "epel"} {
					if strings.Contains(text, forbidden) {
						t.Errorf("DVD kickstart contains %q", forbidden)
					}
				}
				for _, required := range []string{"\ncdrom\n", "\nfirstboot --disable\n", "\nselinux --enforcing\n", "--luks-version=luks2", "\npoweroff\n"} {
					if !strings.Contains(packagesText, required) {
						t.Errorf("kickstart lacks %q", required)
					}
				}
				script := strings.TrimSuffix(post, "%end\n")
				// EL 9's dracut 057 has no split module; EL 10's ships it.
				modules := `add_dracutmodules+=" systemd crypt tpm2-tss lvm "`
				if tc.version == "10.2" {
					modules = `add_dracutmodules+=" systemd crypt tpm2-tss lvm systemd-cryptsetup "`
				}
				console := map[string]string{"x86_64": "console=ttyS0,115200n8", "aarch64": "console=ttyAMA0,115200"}[architecture]
				for _, required := range []string{modules, "tpm2-device=auto", "/etc/gdm/custom.conf", "systemctl enable --force gdm.service", "restorecon -RF /etc/gdm /var/lib/AccountsService", "systemctl set-default graphical.target", console} {
					if !strings.Contains(script, required) {
						t.Errorf("provisioning lacks %q", required)
					}
				}
				if architecture == "aarch64" && (strings.Contains(text, "ttyS0") || strings.Contains(text, "GRUB_SERIAL_COMMAND")) {
					t.Error("aarch64 guest retained the x86 UART")
				}
				cmd := exec.Command("/bin/sh", "-n")
				cmd.Stdin = strings.NewReader(script)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("invalid guest shell syntax: %v: %s", err, out)
				}
			})
		}
		patched, err := encryptedInstallerGRUBForMachine([]byte(strings.ReplaceAll(elRebuildVendorGRUB, "@VOLID@", tc.label)), release.Lab.Installer, "aarch64")
		if err != nil {
			t.Fatal(err)
		}
		grub := string(patched)
		for _, required := range []string{"set default=0\n", "set timeout=1\n", "linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=" + tc.label + " ro inst.ks=cdrom:/lindm-seed/ks.cfg inst.text console=tty0 console=ttyAMA0,115200\n", "search --no-floppy --set=root -l '" + tc.label + "'"} {
			if !strings.Contains(grub, required) {
				t.Errorf("%s aarch64 DVD boot lacks %q", release.Name, required)
			}
		}
		for _, unwanted := range []string{"set default=\"1\"", "set timeout=60", "rd.live.check", "ttyS0", "serial --unit"} {
			if strings.Contains(grub, unwanted) {
				t.Errorf("%s aarch64 DVD boot retained %q", release.Name, unwanted)
			}
		}
	}
}
