//go:build linux

package vmlab

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// Pop!_OS publishes one casper live ISO per hardware channel. Its graphical
// installer (pop-installer, io.elementary.installer) and the distinst CLI
// shipped beside it in the live image drive the same libdistinst Installer;
// Pop has no preseed, autoinstall or other unattended installer mode. The lab
// therefore boots the unchanged vendor live system with systemd's own
// kernel-command-line service (systemd-run-generator), which replaces the
// default target so neither the greeter nor the graphical installer starts,
// and runs the vendor distinst CLI with the GUI's "Clean Install" layout.
const (
	popInstallerEdition          = "cosmic"
	popEncryptedInstallerEdition = "cosmic-encrypted-lab"
	popInstallerDesktop          = "cosmic"
	// Bump when the driver script, provisioning or machine layout changes.
	popInstallerRecipeVersion = "pop-distinst-v1"
	// popVendorBootOptions are distinst's BOOT_OPTIONS for the ISO's
	// libdistinst 0.3.2 (chroot_conf.rs); kernelstub owns this command line.
	popVendorBootOptions = "quiet loglevel=0 systemd.show_status=false splash"
	popSerialConsole     = "ttyS0,115200n8"
)

// popInstallerImage builds the unencrypted COSMIC golden. Only the signed Pop
// and Ubuntu archives configured by the installed system add openssh-server
// and cloud-init; everything else comes from the authenticated ISO.
func popInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	release, err := popManifest(m, popInstallerEdition)
	if err != nil {
		return nil, err
	}
	return &installerImage{
		label:     release.Name,
		installer: platform.Distinst,
		cache:     "pop-installed",
		version:   popInstallerRecipeVersion,
		memoryMiB: 4096,
		recipe:    popInstallerRecipe,
		probes: []installedProbe{
			{"distribution", ". /etc/os-release; test \"$ID\" = " + nativeQuote(release.ID)},
			{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(m.GetVersion())},
			{"ubuntu_base", ". /etc/os-release; test \"$VERSION_CODENAME\" = noble"},
			{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.GetSha256())},
			{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = ext4"},
			{"package_tool", "command -v dpkg-query >/dev/null && command -v apt-get >/dev/null"},
			{"privilege_tool", "command -v sudo >/dev/null"},
			{"systemd_boot", "test -f /boot/efi/EFI/systemd/systemd-bootx64.efi && test -f /boot/efi/EFI/BOOT/BOOTX64.EFI"},
			{"kernelstub", "test -f /etc/kernelstub/configuration && grep -q 'console=" + popSerialConsole + "' /proc/cmdline"},
			{"recovery_partition", "test \"$(findmnt -n -o FSTYPE /recovery)\" = vfat && test -f /recovery/recovery.conf && test \"$(lsblk -n -o PARTLABEL \"$(findmnt -n -o SOURCE /recovery)\")\" = recovery"},
			{"cosmic_session", "test -f /usr/share/wayland-sessions/cosmic.desktop && systemctl is-enabled --quiet cosmic-greeter.service"},
		},
	}, nil
}

// popManifest admits exactly a signed generic amd64 ISO of a distinst
// release with the given edition.
func popManifest(m *labv1.ImageManifest, edition string) (*platform.Release, error) {
	release := manifestRelease(m)
	if release.Lab.Installer != platform.Distinst || m.GetEdition() != edition || m.GetArchitecture() != "amd64" ||
		!strings.HasPrefix(m.GetImageFilename(), "pop-os_"+m.GetVersion()+"_amd64_generic_") ||
		!strings.HasSuffix(m.GetImageFilename(), ".iso") || m.GetChecksumMode() != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED {
		return nil, fmt.Errorf("distinst installer requires a signed Pop!_OS generic amd64 ISO manifest with edition %s", edition)
	}
	return release, nil
}

func popInstallerRecipe(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
	if len(sourceDigest) != 64 || strings.Trim(sourceDigest, "0123456789abcdef") != "" {
		return nil, errors.New("pop installer requires verified source SHA256")
	}
	login, hostPublic, err := popKeys(login, hostPrivate, hostPublic)
	if err != nil {
		return nil, err
	}
	if err := popArchitecture(architecture); err != nil {
		return nil, err
	}
	provision := "apt-get -q update\napt-get -q -y install openssh-server cloud-init\n"
	// Credential files need umask 077, but everything after them must keep
	// the vendor's 022: a root-only /etc/machine-id or /etc/hosts breaks
	// D-Bus activation for every unprivileged system service.
	provision += encryptedInstallerProvision(login, hostPrivate, hostPublic) + "umask 022\n"
	provision += "install -d -m 0755 /etc/cloud/cloud.cfg.d\nprintf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg\n"
	provision += "kernelstub --add-options " + nativeQuote("console=tty0 console="+popSerialConsole) + "\n"
	provision += "install -m 0600 /dev/null " + installerSourceMarkerPath + "\nprintf '%s\\n' '" + sourceDigest + "' > " + installerSourceMarkerPath + "\n"
	provision += "systemctl enable ssh\ncloud-init clean --logs\nrm -f /etc/machine-id /var/lib/dbus/machine-id\ntouch /etc/machine-id\n"
	return popInstallScript(disk, "", provision)
}

// popEncryptedInstallerRecipe installs LVM on LUKS exactly as the vendor
// installer's "Encrypt drive" choice does (physical volume cryptdata, volume
// group data). SSH material is baked as in the Ubuntu encrypted golden. The
// serial console is configured through kernelstub, never by editing loader
// entries. COSMIC autologin through greetd is lab-only.
func popEncryptedInstallerRecipe(release *platform.Release, passphrase, login, hostPrivate, hostPublic, desktop string, tpmBoot bool, architecture string) ([]byte, error) {
	if err := popArchitecture(architecture); err != nil {
		return nil, err
	}
	if passphrase == "" || len(passphrase) > 4096 {
		return nil, errors.New("encrypted installer: invalid passphrase")
	}
	if desktop != "" && desktop != popInstallerDesktop {
		return nil, errors.New("encrypted installer: Pop!_OS provides only its COSMIC desktop")
	}
	login, hostPublic, err := popKeys(login, hostPrivate, hostPublic)
	if err != nil {
		return nil, err
	}
	packages := []string{"openssh-server"}
	if tpmBoot {
		// Pop's distinst reverted dracut for this release; the TPM tuple
		// replaces initramfs-tools exactly as on Ubuntu, after distinst's own
		// initramfs work, and kernelstub then copies the result to the ESP.
		packages = append(packages, release.Lab.TPM.Packages...)
	}
	provision := "apt-get -q update\napt-get -q -y install " + strings.Join(packages, " ") + "\n"
	provision += encryptedInstallerProvision(login, hostPrivate, hostPublic) + "umask 022\n"
	provision += "kernelstub --delete-options " + nativeQuote(popVendorBootOptions) + " --add-options " + nativeQuote("console=tty0 console="+popSerialConsole) + "\n"
	if desktop != "" {
		// greetd's own autologin: the initial session runs once per greeter
		// start through the cosmic-greeter PAM service; later sessions and
		// unlock still need local authentication.
		provision += `cat >> /etc/greetd/cosmic-greeter.toml <<'LINDM_GREETD'

[initial_session]
command = "start-cosmic"
user = "lindm-lab"
LINDM_GREETD
systemctl set-default graphical.target
`
	}
	if tpmBoot {
		provision += encryptedInstallerTPMProvision(release.Lab.TPM, architecture) + encryptedInstallerDracutKernels + "kernelstub\n"
	} else {
		provision += "update-initramfs -u -k all\n"
	}
	provision += "systemctl enable ssh\n"
	return popInstallScript("/dev/vda", passphrase, provision)
}

func popKeys(login, hostPrivate, hostPublic string) (string, string, error) {
	login, err := encryptedInstallerPublicKey(login)
	if err != nil {
		return "", "", err
	}
	hostPublic, err = encryptedInstallerPublicKey(hostPublic)
	if err != nil {
		return "", "", err
	}
	host, err := ssh.ParsePrivateKey([]byte(hostPrivate))
	if err != nil || host.PublicKey().Type() != ssh.KeyAlgoED25519 || string(ssh.MarshalAuthorizedKey(host.PublicKey())) != hostPublic {
		return "", "", errors.New("pop installer SSH host key must be a matching Ed25519 pair")
	}
	return login, hostPublic, nil
}

func popArchitecture(architecture string) error {
	canonical, _, err := encryptedInstallerArchitecture(architecture)
	if err != nil || canonical != "x86_64" {
		return errors.New("pop installer requires x86_64; the arm64 Pop!_OS image is not part of this row")
	}
	return nil
}

// popInstallScript drives the vendor distinst CLI with pop-installer's erase
// layout for libdistinst 0.3.2: a 1 GiB ESP, a 4 GiB FAT recovery partition
// named "recovery", the root (ext4, or LVM on LUKS) and a 4 GiB swap at the end
// (sector units, as in distinst's erase_config). pop-installer passes
// MODIFY_BOOT_ORDER|INSTALL_HARDWARE_SUPPORT, mirrored by --modify-boot and
// --hardware-support. distinst's user creation requires a password; a random
// one satisfies it and is locked before the first boot. Provisioning runs as
// root in the installed target after distinst's own bootloader and recovery
// work. Any failure fails the systemd service, which also powers off, so
// first-boot validation, never the installer exit, is the success authority.
func popInstallScript(disk, passphrase, provision string) ([]byte, error) {
	if disk != "/dev/vda" && disk != "/dev/sda" && disk != "/dev/nvme0n1" {
		return nil, errors.New("pop installer requires an owned guest root disk")
	}
	root := "ext4:mount=/"
	if passphrase != "" {
		// distinst's CLI separates fields with ':' and ','; a printable
		// passphrase without them, spaces or quotes stays one argument.
		for _, c := range []byte(passphrase) {
			if c <= ' ' || c > '~' || c == ':' || c == ',' || c == '\'' {
				return nil, errors.New("pop installer passphrase must be printable ASCII without spaces, quotes, ':' or ','")
			}
		}
		root = "enc=cryptdata,data,pass=" + passphrase
	}
	inner := "set -eu\nexport DEBIAN_FRONTEND=noninteractive\n" + provision + "usermod -p '!' lindm-lab\n"
	var script strings.Builder
	script.WriteString(`set -eu
exec </dev/null >/dev/console 2>&1
disk=` + nativeQuote(disk) + `
part() { case "$disk" in *[0-9]) printf '%sp%s' "$disk" "$1" ;; *) printf '%s%s' "$disk" "$1" ;; esac; }
# systemd.run replaced the default target: refuse to race a vendor frontend.
if systemctl is-active --quiet display-manager.service || pgrep -f io.elementary.installer >/dev/null; then
    echo 'lindm: graphical session or installer is running' >&2
    exit 1
fi
systemctl start NetworkManager.service
nm-online -q --timeout=180
udevadm settle
test -b "$disk"
casper=/cdrom/casper
test -f "$casper/filesystem.squashfs"
test -f "$casper/filesystem.manifest-remove"
set -- -s "$casper/filesystem.squashfs" -r "$casper/filesystem.manifest-remove" -h pop-os -k us -l en_US.UTF-8 \
    -b "$disk" -t "$disk:gpt" \
    -n "$disk:primary:start:2097152:fat32:mount=/boot/efi:flags=esp" \
    -n "$disk:primary:2097152:10485760:fat32:mount=/recovery" \
    -n "$disk:primary:10485760:-8388608:` + root + `" \
    -n "$disk:primary:-8388608:end:swap"
`)
	if passphrase != "" {
		script.WriteString("set -- \"$@\" --logical data:root:end:ext4:mount=/\n")
	}
	// pop-installer's user page defaults to this vendor icon; the CLI
	// requires one whenever it creates the account.
	script.WriteString(`distinst "$@" --username lindm-lab --realname 'Lindm Lab' --profile_icon /usr/share/pixmaps/faces/pop-robot.png --password ` + nativeQuote(rand.Text()) + ` --modify-boot --hardware-support
set --
udevadm settle
# libdistinst names the erase layout's recovery partition; its CLI cannot.
sfdisk --no-reread --part-label "$disk" 2 recovery
udevadm settle
target=/run/lindm-target
install -d -m 0700 "$target"
`)
	if passphrase != "" {
		script.WriteString(`if ! test -b /dev/mapper/data-root; then
    printf '%s' ` + nativeQuote(passphrase) + ` | cryptsetup open --key-file=- "$(part 3)" cryptdata
    vgchange -ay data
fi
mount /dev/mapper/data-root "$target"
`)
	} else {
		script.WriteString("mount \"$(part 3)\" \"$target\"\n")
	}
	script.WriteString(`mount "$(part 1)" "$target/boot/efi"
mount "$(part 2)" "$target/recovery"
for d in dev dev/pts proc sys sys/firmware/efi/efivars run; do
    mount --bind "/$d" "$target/$d"
done
# distinst and the vendor configuration keep the service's default umask
# 022; only the credential-bearing payload is created private.
install -m 0600 /dev/null "$target/root/lindm-provision"
printf '%s' '` + base64.StdEncoding.EncodeToString([]byte(inner)) + `' | base64 -d > "$target/root/lindm-provision"
chroot "$target" /bin/sh -eu /root/lindm-provision
rm -f "$target/root/lindm-provision"
for d in run sys/firmware/efi/efivars sys proc dev/pts dev recovery boot/efi; do
    umount "$target/$d"
done
umount "$target"
`)
	if passphrase != "" {
		script.WriteString("vgchange -an data\ncryptsetup close cryptdata\n")
	}
	script.WriteString("sync\n")
	return []byte(script.String()), nil
}
