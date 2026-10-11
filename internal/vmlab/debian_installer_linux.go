//go:build linux

package vmlab

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"lindm/internal/platform"
)

const debianInstallerRecipeVersion = "debian-netinst-v2"

func debianSuite(version string) (string, error) {
	switch version {
	case "12":
		return "bookworm", nil
	case "13":
		return "trixie", nil
	default:
		return "", errors.New("debian installer requires version 12 or 13")
	}
}

func debianInstallerRecipe(version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
	suite, err := debianSuite(version)
	if err != nil {
		return nil, err
	}
	if disk != "/dev/vda" && disk != "/dev/sda" && disk != "/dev/nvme0n1" {
		return nil, errors.New("debian installer requires an owned guest root disk")
	}
	_, console, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	login, err = encryptedInstallerPublicKey(login)
	if err != nil {
		return nil, err
	}
	hostPublic, err = encryptedInstallerPublicKey(hostPublic)
	if err != nil {
		return nil, err
	}
	host, err := ssh.ParsePrivateKey([]byte(hostPrivate))
	if err != nil || string(ssh.MarshalAuthorizedKey(host.PublicKey())) != hostPublic {
		return nil, errors.New("debian installer SSH host key pair differs")
	}
	if len(sourceDigest) != 64 || strings.Trim(sourceDigest, "0123456789abcdef") != "" {
		return nil, errors.New("debian installer requires verified source SHA256")
	}
	provision := "set -eu\n" + encryptedInstallerProvision(login, hostPrivate, hostPublic)
	// The credential writer leaves umask 077; system files, including the
	// emptied machine-id the first boot fills, must stay world-readable.
	provision += "umask 022\n"
	provision += "install -d -m 0755 /etc/cloud/cloud.cfg.d /etc/default/grub.d\nprintf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg\n"
	provision += "printf '%s\\n' 'GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0 console=" + console + "\"' > /etc/default/grub.d/99-lindm-lab.cfg\nupdate-grub\n"
	provision += "(umask 077 && printf '%s\\n' '" + sourceDigest + "' > " + installerSourceMarkerPath + ")\n"
	provision += "systemctl enable ssh\ncloud-init clean --logs\nrm -f /etc/machine-id\ntouch /etc/machine-id\n"
	return debianPreseed(suite, disk, "regular", "", "standard, ssh-server", "openssh-server sudo cloud-init ca-certificates", provision), nil
}

// debianEncryptedInstallerRecipe installs Debian's own guided LVM-on-LUKS
// layout (partman-crypto, LUKS2 in bookworm and trixie) on the golden's virtio
// root. Packages come from the release's signed suite through APT; the netinst
// media authenticates only the installer itself. The passphrase is validated by
// the caller as printable ASCII and never reaches a shell token: debconf reads
// it as the remainder of its own line. Session.Desktops name tasksel tasks.
func debianEncryptedInstallerRecipe(release *platform.Release, architecture, passphrase, login, hostPrivate, hostPublic, desktop string, tpmBoot bool) ([]byte, error) {
	if release.Codename == "" {
		return nil, fmt.Errorf("encrypted installer: %s has no suite codename", release.Name)
	}
	architecture, console, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(passphrase) != passphrase {
		// debconf strips surrounding whitespace from preseeded values.
		return nil, errors.New("encrypted installer: Debian passphrase must not have surrounding whitespace")
	}
	tasks := append([]string{"standard", "ssh-server"}, release.Lab.Session.Desktops[desktop]...)
	// d-i keeps late_command output only in its syslog; stderr (never the
	// base64 credential payloads) also goes to the serial console.
	provision := "set -eu\nexec 2>/dev/console\n" + encryptedInstallerProvision(login, hostPrivate, hostPublic)
	if desktop != "" {
		provision += encryptedInstallerDesktopProvision(release, desktop, architecture)
	}
	grubTerminal := "GRUB_TERMINAL=\"console serial\"\nGRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\"\n"
	if architecture == "aarch64" {
		grubTerminal = "GRUB_TERMINAL=\"console\"\n"
	}
	provision += `install -d -m 0755 /etc/default/grub.d
cat > /etc/default/grub.d/99-lindm-lab.cfg <<'LINDM_GRUB'
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 console=tty0 console=` + console + `"
` + grubTerminal + `GRUB_TIMEOUT=1
LINDM_GRUB
`
	if tpmBoot {
		// preseed/late_command runs before finish-install's apt-cdrom-setup
		// comments out the netinst disc source. trixie's netinst carries some
		// of these dependencies, so apt would block on a "Media change"
		// prompt; apply the hook's own edit first and fail any prompt fast.
		provision += "if [ -f /etc/apt/sources.list ]; then sed -i '/^deb cdrom:/s/^/#/' /etc/apt/sources.list; fi\n" +
			encryptedInstallerTPMProvision(release.Lab.TPM, architecture) +
			"DEBIAN_FRONTEND=noninteractive apt-get -y install " + strings.Join(release.Lab.TPM.Packages, " ") + " </dev/null\n" +
			encryptedInstallerDracutKernels
	} else {
		provision += "update-initramfs -u -k all\n"
	}
	provision += "update-grub\nsystemctl enable ssh\n"
	crypto := " d-i partman-auto-lvm/guided_size string max\n" +
		" d-i partman-auto-crypto/erase_disks boolean false\n" +
		" d-i partman-crypto/passphrase password " + passphrase + "\n" +
		" d-i partman-crypto/passphrase-again password " + passphrase + "\n" +
		" d-i partman-crypto/weak_passphrase boolean true\n" +
		" d-i partman-lvm/confirm boolean true\n" +
		" d-i partman-lvm/confirm_nooverwrite boolean true\n"
	return debianPreseed(release.Codename, "/dev/vda", "crypto", crypto, strings.Join(tasks, ", "), "openssh-server sudo ca-certificates", provision), nil
}

// debianPreseed renders the shared unattended netinst answers. Base64 keeps
// the provisioning script outside debconf and shell token syntax.
func debianPreseed(suite, disk, method, partitioning, tasks, include, provision string) []byte {
	late := "printf '%s' '" + base64.StdEncoding.EncodeToString([]byte(provision)) + "' | base64 -d > /target/tmp/lindm-provision && in-target /bin/sh -eu /tmp/lindm-provision && rm -f /target/tmp/lindm-provision"
	return []byte(fmt.Sprintf(`d-i debian-installer/locale string en_US.UTF-8
 d-i keyboard-configuration/xkb-keymap select us
 d-i netcfg/choose_interface select auto
 d-i netcfg/get_hostname string lindm-debian
 d-i netcfg/get_domain string invalid
 d-i mirror/country string manual
 d-i mirror/http/hostname string deb.debian.org
 d-i mirror/http/directory string /debian
 d-i mirror/http/proxy string
 d-i mirror/suite string %s
 d-i apt-setup/use_mirror boolean true
 d-i passwd/root-login boolean false
 d-i passwd/make-user boolean true
 d-i passwd/user-fullname string Lindm Lab
 d-i passwd/username string lindm-lab
 d-i passwd/user-password-crypted password !
 d-i clock-setup/utc boolean true
 d-i time/zone string UTC
 d-i clock-setup/ntp boolean true
 d-i partman-auto/disk string %s
 d-i partman-auto/method string %s
%s d-i partman-auto/choose_recipe select atomic
 d-i partman-lvm/device_remove_lvm boolean true
 d-i partman-md/device_remove_md boolean true
 d-i partman-partitioning/confirm_write_new_label boolean true
 d-i partman/choose_partition select finish
 d-i partman/confirm boolean true
 d-i partman/confirm_nooverwrite boolean true
 d-i partman-efi/non_efi_system boolean true
 tasksel tasksel/first multiselect %s
 d-i pkgsel/include string %s
 d-i pkgsel/upgrade select none
 popularity-contest popularity-contest/participate boolean false
 d-i grub-installer/only_debian boolean true
 d-i grub-installer/with_other_os boolean false
 d-i grub-installer/bootdev string %s
 d-i grub-installer/force-efi-extra-removable boolean true
 d-i preseed/late_command string %s
 d-i finish-install/reboot_in_progress note
 d-i cdrom-detect/eject boolean false
 d-i debian-installer/exit/poweroff boolean true
`, suite, disk, method, partitioning, tasks, include, disk, late))
}
