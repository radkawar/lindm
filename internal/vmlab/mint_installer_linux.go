// SPDX-License-Identifier: Apache-2.0

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

// Linux Mint publishes one hybrid live ISO per edition; its Ubiquity installer
// copies the authenticated live filesystem. Mint ships no Subiquity
// autoinstall. Ubiquity's maintained unattended path is debconf preseeding
// with the casper "noninteractive" boot argument: start-ubiquity-dm then runs
// "ubiquity noninteractive" (automatic mode, no X session) before the display
// manager. That frontend can only reboot when it finishes, so the installer
// QEMU exits on that reboot request.
const (
	mintInstallerEdition          = "cinnamon"
	mintEncryptedInstallerEdition = "cinnamon-encrypted-lab"
	mintInstallerDesktop          = "cinnamon"
	// Bump when the preseed, provisioning or machine layout of the unencrypted
	// golden changes.
	mintInstallerRecipeVersion = "linuxmint-ubiquity-v3"
	// mintEncryptedRecipeVersion binds the encrypted golden; bump it when the
	// preseed or the encrypted provisioning changes. v2 is the identity the
	// first published encrypted golden used.
	mintEncryptedRecipeVersion = "linuxmint-ubiquity-v2"
)

// mintInstallerImage builds the unencrypted Cinnamon golden. Only the signed
// Ubuntu/Mint archives configured by the live system add openssh-server and
// cloud-init; everything else comes from the authenticated ISO.
func mintInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	release, err := mintManifest(m, mintInstallerEdition)
	if err != nil {
		return nil, err
	}
	return &installerImage{
		label:        release.Name,
		installer:    platform.Ubiquity,
		cache:        "linuxmint-installed",
		version:      mintInstallerRecipeVersion,
		memoryMiB:    4096,
		exitOnReboot: true,
		recipe:       mintInstallerRecipe,
		probes: []installedProbe{
			{"distribution", ". /etc/os-release; test \"$ID\" = " + nativeQuote(release.ID)},
			{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(m.GetVersion())},
			{"ubuntu_base", ". /etc/os-release; test \"$UBUNTU_CODENAME\" = noble"},
			{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.GetSha256())},
			{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = ext4"},
			{"package_tool", "command -v dpkg-query >/dev/null && command -v apt-get >/dev/null"},
			{"privilege_tool", "command -v sudo >/dev/null"},
			{"removable_boot_path", "test -f /boot/efi/EFI/BOOT/BOOTX64.EFI"},
			{"cinnamon_session", "test -f /usr/share/xsessions/cinnamon.desktop"},
		},
	}, nil
}

// mintManifest admits exactly a signed amd64 Cinnamon ISO of a release the
// registry maintains with Ubiquity.
func mintManifest(m *labv1.ImageManifest, edition string) (*platform.Release, error) {
	release := manifestRelease(m)
	if release.Lab.Installer != platform.Ubiquity || m.GetEdition() != edition || m.GetArchitecture() != "amd64" ||
		m.GetImageFilename() != release.ID+"-"+m.GetVersion()+"-cinnamon-64bit.iso" ||
		m.GetChecksumMode() != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED {
		return nil, fmt.Errorf("ubiquity installer requires a signed Cinnamon amd64 ISO manifest with edition %s", edition)
	}
	return release, nil
}

func mintInstallerRecipe(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
	if len(sourceDigest) != 64 || strings.Trim(sourceDigest, "0123456789abcdef") != "" {
		return nil, errors.New("linux mint installer requires verified source SHA256")
	}
	host, err := ssh.ParsePrivateKey([]byte(hostPrivate))
	if err != nil {
		return nil, errors.New("linux mint installer SSH host key pair differs")
	}
	login, err = encryptedInstallerPublicKey(login)
	if err != nil {
		return nil, err
	}
	hostPublic, err = encryptedInstallerPublicKey(hostPublic)
	if err != nil || string(ssh.MarshalAuthorizedKey(host.PublicKey())) != hostPublic {
		return nil, errors.New("linux mint installer SSH host key pair differs")
	}
	_, console, err := mintArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	provision := "apt-get update\nDEBIAN_FRONTEND=noninteractive apt-get -y install openssh-server cloud-init\n"
	provision += encryptedInstallerProvision(login, hostPrivate, hostPublic)
	// The credential writer leaves umask 077; system files, including the
	// emptied machine-id the first boot fills, must stay world-readable.
	provision += "umask 022\n"
	// Ubuntu's cloud-init apt module renders Ubuntu archive sources with the
	// os-release VERSION_CODENAME; on Mint that is "zena", whose Ubuntu suites
	// do not exist and make every apt-get update exit 100 (observed). Keep
	// Mint's own official-package-repositories list untouched.
	provision += "install -d -m 0755 /etc/cloud/cloud.cfg.d /etc/default/grub.d\nprintf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' 'apt: {preserve_sources_list: true}' > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg\n"
	provision += "printf '%s\\n' 'GRUB_CMDLINE_LINUX=\"console=tty0 console=" + console + "\"' > /etc/default/grub.d/99-lindm-lab.cfg\nupdate-grub\n"
	provision += "(umask 077 && printf '%s\\n' '" + sourceDigest + "' > " + installerSourceMarkerPath + ")\n"
	provision += "systemctl enable ssh\ncloud-init clean --logs\nrm -f /etc/machine-id\ntouch /etc/machine-id\nln -sf /etc/machine-id /var/lib/dbus/machine-id\n"
	return mintPreseed(disk, "", provision)
}

// mintEncryptedInstallerRecipe installs LVM on LUKS through Ubiquity's
// partman-crypto option, the layout Mint's installer offers as "Encrypt the
// new Linux Mint installation". SSH material is baked as in the Ubuntu
// encrypted golden; the desktop autologin is lab-only. The live media install
// their own Cinnamon session, so no other desktop is accepted.
func mintEncryptedInstallerRecipe(release *platform.Release, passphrase, loginPublicKey, hostPrivate, hostPublicKey, desktop string, tpmBoot bool, architecture string) ([]byte, error) {
	if desktop != mintInstallerDesktop {
		return nil, fmt.Errorf("encrypted installer: %s media install only their Cinnamon desktop", release.Name)
	}
	_, console, err := mintArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	login, err := encryptedInstallerPublicKey(loginPublicKey)
	if err != nil {
		return nil, err
	}
	hostPublic, err := encryptedInstallerPublicKey(hostPublicKey)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(hostPrivate))
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 || string(ssh.MarshalAuthorizedKey(signer.PublicKey())) != hostPublic {
		return nil, errors.New("encrypted installer: host key must be a matching Ed25519 pair")
	}
	if passphrase == "" || len(passphrase) > 4096 {
		return nil, errors.New("encrypted installer: invalid passphrase")
	}
	packages := []string{"openssh-server"}
	if tpmBoot {
		// The base's dracut conflicts with initramfs-tools; it replaces it only
		// after Ubiquity's own initramfs work, exactly as on the base release.
		packages = append(packages, release.Lab.TPM.Packages...)
	}
	provision := "apt-get update\nDEBIAN_FRONTEND=noninteractive apt-get -y install " + strings.Join(packages, " ") + "\n"
	provision += encryptedInstallerProvision(login, hostPrivate, hostPublic)
	provision += `umask 022
install -d -m 0755 /etc/default/grub.d /etc/cryptsetup-initramfs /etc/lightdm/lightdm.conf.d
cat > /etc/default/grub.d/99-lindm-lab.cfg <<'LINDM_GRUB'
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX="console=tty0 console=` + console + `"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=1
LINDM_GRUB
cat > /etc/lightdm/lightdm.conf.d/90-lindm-lab.conf <<'LINDM_LIGHTDM'
[Seat:*]
autologin-user=lindm-lab
autologin-user-timeout=0
autologin-session=` + mintInstallerDesktop + `
LINDM_LIGHTDM
`
	if tpmBoot {
		provision += encryptedInstallerTPMProvision(release.Lab.TPM, architecture) + encryptedInstallerDracutKernels
	} else {
		provision += "printf '%s\\n' 'CRYPTSETUP=y' > /etc/cryptsetup-initramfs/conf-hook\nupdate-initramfs -u -k all\n"
	}
	provision += "update-grub\nsystemctl enable ssh\nsystemctl set-default graphical.target\n"
	return mintPreseed("/dev/vda", passphrase, provision)
}

func mintArchitecture(architecture string) (string, string, error) {
	canonical, console, err := encryptedInstallerArchitecture(architecture)
	if err != nil || canonical != "x86_64" {
		return "", "", errors.New("linux mint installer requires x86_64; Mint publishes no other architecture")
	}
	return canonical, console, nil
}

// mintPreseed answers every Ubiquity question for an automatic install of
// the whole owned disk. Ubiquity requires a user password; a random one is
// set only to satisfy the page and is locked before the first boot.
// Provisioning runs as root inside the installed target from
// ubiquity/success_command, after Ubiquity's own work; then Ubiquity reboots,
// which ends the installer machine.
func mintPreseed(disk, passphrase, provision string) ([]byte, error) {
	if disk != "/dev/vda" && disk != "/dev/sda" && disk != "/dev/nvme0n1" {
		return nil, errors.New("linux mint installer requires an owned guest root disk")
	}
	method := "regular"
	if passphrase != "" {
		method = "crypto"
		for _, c := range []byte(passphrase) {
			if c <= ' ' || c > '~' {
				return nil, errors.New("linux mint installer passphrase must be printable ASCII without spaces")
			}
		}
	}
	password := rand.Text()
	inner := "set -eu\nexport DEBIAN_FRONTEND=noninteractive\n" + provision + "passwd -l lindm-lab\n"
	// The live system's /target lost its API filesystems in Ubiquity's cleanup.
	// Bind them for the chroot (including /run for systemd-resolved) and always
	// unmount, so the installed disk is left exactly as Ubiquity finished it.
	outer := `set -eu
printf '%s' '` + base64.StdEncoding.EncodeToString([]byte(inner)) + `' | base64 -d > /target/root/lindm-provision
mounted=
cleanup() { for d in $mounted; do umount -l "/target/$d"; done; rm -f /target/root/lindm-provision; }
trap cleanup EXIT
for d in dev dev/pts proc sys sys/firmware/efi/efivars run; do
    test -d "/$d" || continue
    if ! mountpoint -q "/target/$d"; then mount --bind "/$d" "/target/$d"; mounted="$d $mounted"; fi
done
chroot /target /bin/sh -eu /root/lindm-provision
`
	// Ubiquity powers off even when this command fails, so first-boot
	// validation, never the installer exit, is the only success authority.
	success := "printf '%s' '" + base64.StdEncoding.EncodeToString([]byte(outer)) + "' | base64 -d > /tmp/lindm-success && sh -eu /tmp/lindm-success"
	lines := []string{
		"d-i debian-installer/locale string en_US.UTF-8",
		"d-i debian-installer/language string en",
		"d-i debian-installer/country string US",
		"d-i localechooser/supported-locales multiselect en_US.UTF-8",
		"d-i keyboard-configuration/xkb-keymap select us",
		"d-i keyboard-configuration/layoutcode string us",
		"d-i console-setup/ask_detect boolean false",
		"d-i time/zone string Etc/UTC",
		"d-i clock-setup/utc boolean true",
		"d-i clock-setup/ntp boolean false",
		"d-i netcfg/get_hostname string lindm-mint",
		"d-i netcfg/get_domain string invalid",
		"d-i passwd/user-fullname string Lindm Lab",
		"d-i passwd/username string lindm-lab",
		"d-i passwd/user-password password " + password,
		"d-i passwd/user-password-again password " + password,
		"d-i user-setup/allow-password-weak boolean true",
		"d-i user-setup/encrypt-home boolean false",
		"d-i passwd/auto-login boolean false",
		"d-i partman-auto/disk string " + disk,
		"d-i partman-auto/method string " + method,
		"d-i partman-auto/choose_recipe select atomic",
		"d-i partman-auto-lvm/guided_size string max",
		"d-i partman-lvm/device_remove_lvm boolean true",
		"d-i partman-md/device_remove_md boolean true",
		"d-i partman-lvm/confirm boolean true",
		"d-i partman-lvm/confirm_nooverwrite boolean true",
	}
	if passphrase != "" {
		lines = append(lines,
			"d-i partman-crypto/passphrase password "+passphrase,
			"d-i partman-crypto/passphrase-again password "+passphrase,
			"d-i partman-crypto/weak_passphrase boolean true",
			"d-i partman-crypto/confirm boolean true",
		)
	}
	lines = append(lines,
		"d-i partman-partitioning/confirm_write_new_label boolean true",
		"d-i partman/choose_partition select finish",
		"d-i partman/confirm boolean true",
		"d-i partman/confirm_nooverwrite boolean true",
		"d-i partman-efi/non_efi_system boolean true",
		"d-i grub-installer/only_debian boolean true",
		"d-i grub-installer/with_other_os boolean true",
		"d-i grub-installer/bootdev string "+disk,
		"ubiquity ubiquity/use_nonfree boolean false",
		"ubiquity ubiquity/download_updates boolean false",
		"ubiquity ubiquity/reboot boolean true",
		// Noninteractive Ubiquity runs neither failure_command nor a reboot
		// after a failed step (observed); the installer deadline then applies.
		"ubiquity ubiquity/success_command string "+success,
	)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
