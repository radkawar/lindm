//go:build linux

package vmlab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

func releaseMedia(distribution, version string) encryptedMedia {
	return encryptedInstallerMedia(&labv1.ImageManifest{Distribution: distribution, Version: version})
}

func debianPreseedValues(t *testing.T, recipe []byte) map[string]string {
	t.Helper()
	values := make(map[string]string)
	for _, line := range strings.Split(string(recipe), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			if _, duplicate := values[fields[1]]; duplicate {
				t.Fatalf("duplicate preseed answer %s", fields[1])
			}
			values[fields[1]] = strings.Join(fields[3:], " ")
		}
	}
	return values
}

func debianLatePayload(t *testing.T, late string) string {
	t.Helper()
	fields := strings.Split(late, "'")
	if len(fields) < 4 {
		t.Fatal("missing quoted late-command payload")
	}
	payload, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{late, string(payload)} {
		cmd := exec.Command("/bin/sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid provisioning shell: %v: %s", err, output)
		}
	}
	return string(payload)
}

func TestDebianEncryptedPreseedUsesGuidedLUKSAndRelease(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	passphrase := strings.Repeat("0123456789abcdef", 4)
	for _, tc := range []struct {
		version, suite, tcti, dracut string
		cryptsetup                   bool
	}{
		{"12", "bookworm", "libtss2-tcti-device0 ", "tpm2-tss lvm \"", false},
		{"13", "trixie", "libtss2-tcti-device0t64 ", "lvm systemd-cryptsetup \"", true},
	} {
		media := releaseMedia("debian", tc.version)
		if err := media.release.Gate(platform.Encryption); err != nil {
			t.Fatal(err)
		}
		for _, tpmBoot := range []bool{false, true} {
			recipe, err := encryptedInstallerRecipeForMachine(media, passphrase, login, private, public, "gnome", tpmBoot, "x86_64")
			if err != nil {
				t.Fatal(err)
			}
			values := debianPreseedValues(t, recipe)
			for name, want := range map[string]string{
				"partman-auto/method": "crypto", "partman-auto/disk": "/dev/vda", "partman-auto/choose_recipe": "atomic",
				"partman-crypto/passphrase": passphrase, "partman-crypto/passphrase-again": passphrase,
				"partman-auto-crypto/erase_disks": "false", "partman-auto-lvm/guided_size": "max",
				"passwd/user-password-crypted": "!", "debian-installer/exit/poweroff": "true",
				"tasksel/first": "standard, ssh-server, desktop, gnome-desktop", "mirror/suite": tc.suite,
			} {
				if values[name] != want {
					t.Fatalf("debian %s preseed %s=%q, want %q", tc.version, name, values[name], want)
				}
			}
			if strings.Contains(values["pkgsel/include"], "cloud-init") {
				t.Fatal("encrypted golden must not depend on NoCloud provisioning")
			}
			payload := debianLatePayload(t, values["preseed/late_command"])
			if strings.Contains(payload, passphrase) {
				t.Fatal("LUKS passphrase leaked into the installed provisioning script")
			}
			for _, want := range []string{"/etc/gdm3/daemon.conf", "AutomaticLogin=lindm-lab", "Session=gnome", "systemctl enable --force gdm3.service", "console=ttyS0,115200n8", "update-grub", base64.StdEncoding.EncodeToString([]byte(public))} {
				if !strings.Contains(payload, want) {
					t.Fatalf("debian %s provisioning lost %q", tc.version, want)
				}
			}
			if !tpmBoot {
				if strings.Contains(payload, "dracut") || !strings.Contains(payload, "update-initramfs -u -k all") {
					t.Fatal("stock initramfs-tools unlock path changed without TPM boot")
				}
				continue
			}
			if !strings.Contains(payload, tc.tcti) || strings.Contains(payload, "systemd-cryptsetup cryptsetup-initramfs-") != tc.cryptsetup || !strings.Contains(payload, tc.dracut) {
				t.Fatalf("debian %s TPM boot stack lacks its release packages or dracut modules", tc.version)
			}
			if !strings.Contains(payload, "tpm2-device=auto") || !strings.Contains(payload, `dracut --force "/boot/initrd.img-$kernel"`) {
				t.Fatal("TPM-capable initramfs not rebuilt for the installed kernels")
			}
			// late_command precedes finish-install's apt-cdrom-setup: the
			// netinst disc source must be disabled before the late apt-get,
			// whose stdin is closed so a "Media change" prompt fails fast.
			disable, install := strings.Index(payload, `sed -i '/^deb cdrom:/s/^/#/' /etc/apt/sources.list`), strings.Index(payload, "apt-get -y install")
			if disable < 0 || install < disable || !strings.Contains(payload, "cryptsetup-initramfs- </dev/null\n") || !strings.HasPrefix(payload, "set -eu\nexec 2>/dev/console\n") {
				t.Fatalf("debian %s late apt can block on the netinst disc source", tc.version)
			}
		}
	}
	media := releaseMedia("debian", "13")
	if _, err := encryptedInstallerRecipeForMachine(media, passphrase+" ", login, private, public, "", false, "x86_64"); err == nil {
		t.Fatal("passphrase debconf would trim was accepted")
	}
	if _, err := encryptedInstallerRecipeForMachine(media, "a\nd-i preseed/late_command string false", login, private, public, "", false, "x86_64"); err == nil {
		t.Fatal("passphrase line injection accepted")
	}
	if err := releaseMedia("debian", "11").release.Gate(platform.Encryption); err == nil {
		t.Fatal("unmaintained Debian release admitted")
	}
}

func TestDebianUnencryptedPreseedUnchangedByEncryptedVariant(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	recipe, err := debianInstallerRecipe("13", "/dev/vda", "x86_64", strings.Repeat("a", 64), login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(recipe, []byte("partman-crypto")) || !bytes.Contains(recipe, []byte(" d-i partman-auto/method string regular\n d-i partman-auto/choose_recipe select atomic\n")) {
		t.Fatal("unencrypted Debian golden recipe changed")
	}
}

func TestUbuntuJammyTPMBootCarriesTSS2WithoutTPM2TSSModule(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, tc := range []struct{ version, tcti string }{{"22.04", "libtss2-tcti-device0 "}, {"24.04", "libtss2-tcti-device0t64 "}} {
		media := releaseMedia("ubuntu", tc.version)
		for _, architecture := range []string{"x86_64", "aarch64"} {
			recipe, err := encryptedInstallerRecipeForMachine(media, "lab-passphrase", login, private, public, "gnome", true, architecture)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Autoinstall struct {
					LateCommands [][]string `json:"late-commands"`
				} `json:"autoinstall"`
			}
			if err := json.Unmarshal(bytes.TrimPrefix(recipe, []byte("#cloud-config\n")), &config); err != nil || len(config.Autoinstall.LateCommands) != 1 {
				t.Fatalf("invalid autoinstall: %v", err)
			}
			late := config.Autoinstall.LateCommands[0]
			if !bytes.Contains(recipe, []byte(tc.tcti)) || !bytes.Contains(recipe, []byte("ubuntu-desktop-minimal")) || !strings.HasPrefix(late[len(late)-1], "exec 2>/dev/console\n") {
				t.Fatalf("ubuntu %s TPM boot stack lacks %q or late-command diagnostics", tc.version, tc.tcti)
			}
			// Jammy's dracut 051 has no tpm2-tss module: naming it is fatal,
			// so its initramfs carries the TSS2 libraries systemd 249 dlopens.
			jammy := tc.version == "22.04"
			multiarch := map[string]string{"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}[architecture]
			if bytes.Contains(recipe, []byte("tpm2-tss lvm")) == jammy || bytes.Contains(recipe, []byte("/usr/lib/"+multiarch+"/libtss2-tcti-device.so.0")) != jammy || bytes.Contains(recipe, []byte("tpm_tis tpm_crb")) != jammy {
				t.Fatalf("ubuntu %s %s selected the wrong dracut TPM2 integration", tc.version, architecture)
			}
		}
	}
	// Jammy's recovery sanitize is measured GRUB only: its owned-boot UKI
	// fixture is refused for lack of ukify, the measured lane is admitted.
	jammy := releaseMedia("ubuntu", "22.04").release
	if err := ownedBootFixtureAvailable(jammy, "x86_64", "wipe", "recovery-nvme", ""); err == nil {
		t.Fatal("Jammy admitted to the owned-boot recovery fixture without ukify")
	}
	if err := errors.Join(jammy.Gate(platform.RecoverySanitize), ownedBootFixtureAvailable(jammy, "x86_64", "wipe", "recovery-sata", recoveryBootMeasured), ownedBootFixtureAvailable(jammy, "x86_64", "wipe", "lock-quarantine", "")); err != nil {
		t.Fatalf("Jammy measured recovery or unrelated lanes refused: %v", err)
	}
	// Noble's arm64 vendor kernel is a gzip-compressed Image: only its owned
	// UKI fixture is refused, on that architecture alone.
	noble := releaseMedia("ubuntu", "24.04").release
	if err := ownedBootFixtureAvailable(noble, "arm64", "wipe", "recovery-nvme", ""); err == nil {
		t.Fatal("Noble arm64 admitted to the owned-boot recovery fixture with a compressed kernel")
	}
	if err := errors.Join(ownedBootFixtureAvailable(noble, "aarch64", "wipe", "recovery-nvme", recoveryBootMeasured), ownedBootFixtureAvailable(noble, "x86_64", "wipe", "recovery-nvme", "")); err != nil {
		t.Fatalf("Noble measured arm64 or owned x86_64 recovery refused: %v", err)
	}
}

func TestUbuntuJammyLateCommandsNeverReferenceFirstBootAccount(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, tc := range []struct {
		version   string
		firstBoot bool
	}{{"22.04", true}, {"24.04", false}} {
		recipe, err := encryptedInstallerRecipeForMachine(releaseMedia("ubuntu", tc.version), "lab-passphrase", login, private, public, "gnome", true, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Autoinstall struct {
				SSH struct {
					Keys []string `json:"authorized-keys"`
				} `json:"ssh"`
				LateCommands  [][]string `json:"late-commands"`
				ErrorCommands [][]string `json:"error-commands"`
			} `json:"autoinstall"`
		}
		if err := json.Unmarshal(bytes.TrimPrefix(recipe, []byte("#cloud-config\n")), &config); err != nil {
			t.Fatal(err)
		}
		late := config.Autoinstall.LateCommands[0]
		script := late[len(late)-1]
		// Jammy's subiquity creates lindm-lab only on first boot through
		// cloud-init, so a late-command chown to it fails the install.
		if strings.Contains(script, "lindm-lab:lindm-lab") == tc.firstBoot || strings.Contains(script, "/home/lindm-lab/.ssh") == tc.firstBoot {
			t.Fatalf("ubuntu %s late commands reference the lab account inconsistently with its creation time", tc.version)
		}
		if len(config.Autoinstall.SSH.Keys) != 1 || strings.TrimSpace(config.Autoinstall.SSH.Keys[0]) != strings.TrimSpace(login) {
			t.Fatal("pinned login key must still arrive through the autoinstall identity")
		}
		if len(config.Autoinstall.ErrorCommands) != 1 || strings.Contains(strings.Join(config.Autoinstall.ErrorCommands[0], " "), base64.StdEncoding.EncodeToString([]byte(private))) {
			t.Fatal("installer failure diagnostics missing or carry key material")
		}
	}
}

func TestEncryptedGoldenTPMAbsentTupleIsSeparateAndEnforced(t *testing.T) {
	debianArm := &labv1.ImageManifest{Distribution: "debian", Version: "13", Architecture: "arm64", Sha256: strings.Repeat("a", 64)}
	if encryptedGuestTPMObservable(debianArm, "aarch64") || !encryptedGuestTPMObservable(debianArm, "x86_64") {
		t.Fatal("Debian arm64 kernels cannot bind QEMU virt's TIS TPM; x86_64 can")
	}
	if !encryptedGuestTPMObservable(&labv1.ImageManifest{Distribution: "ubuntu", Version: "24.04"}, "aarch64") {
		t.Fatal("TPM-absent tuple leaked to an unrelated release")
	}
	opts := EncryptedVMOptions{Desktop: "gnome", TPMBoot: true}
	if encryptedGoldenID(debianArm, opts, "c", "v", "", true) == encryptedGoldenID(debianArm, opts, "c", "v", "", false) {
		t.Fatal("TPM-absent golden shares a cache identity with the TPM golden")
	}
	if _, err := encryptedMachineHardware(debianArm, EncryptedVMOptions{Hardware: &VMHardwareOptions{TPM: true}}); err == nil || !strings.Contains(err.Error(), "-tpm=false") {
		t.Fatalf("attached-but-unobservable TPM accepted: %v", err)
	}
}
