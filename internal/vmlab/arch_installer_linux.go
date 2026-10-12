//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// archEncryptedInstallerRecipe uses the official archiso startup-script hook and
// pacstrap. Only the VM's owned virtio disk is partitioned. The repository date
// is a separate manifest pin; package signatures remain mandatory. Both owner
// selections keep an unencrypted boot partition and a LUKS2 root unlocked by
// mkinitcpio's systemd sd-encrypt hook, never the legacy encrypt hook.
func archEncryptedInstallerRecipe(media encryptedMedia, architecture, passphrase, login, hostPrivate, hostPublic, desktop string) ([]byte, error) {
	if architecture != "x86_64" {
		return nil, errors.New("official Arch installer is x86_64 only; Arch Linux ARM is a separate platform")
	}
	date, err := time.Parse("2006-01-02", media.manifest.GetRepositorySnapshotDate())
	if err != nil {
		return nil, errors.New("arch installer requires a pinned Archive repository date")
	}
	if media.release.RollingUpdate == nil || media.release.RollingUpdate.ArchiveURL == "" {
		return nil, errors.New("arch installer requires a registered Archive repository")
	}
	var boot string
	switch media.manifest.GetEdition() {
	case "systemd-boot-encrypted-lab":
		boot = `bootctl --esp-path=/boot/efi --boot-path=/boot install --no-variables
install -d -m 0755 /boot/loader/entries
printf '%s\n' 'default arch.conf' 'timeout 1' > /boot/efi/loader/loader.conf
printf '%s\n' 'title Arch Linux' 'linux /vmlinuz-linux' 'initrd /initramfs-linux.img' "options rd.luks.name=$luks=lindm-root root=/dev/mapper/lindm-root rw console=tty0 console=ttyS0,115200n8" > /boot/loader/entries/arch.conf
`
	case "grub-encrypted-lab":
		boot = `grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Arch --removable --no-nvram
printf '%s\n' 'GRUB_TIMEOUT=1' 'GRUB_TERMINAL="console serial"' 'GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"' "GRUB_CMDLINE_LINUX=\"rd.luks.name=$luks=lindm-root console=tty0 console=ttyS0,115200n8\"" >> /etc/default/grub
grub-mkconfig -o /boot/grub/grub.cfg
`
	default:
		return nil, errors.New("arch encrypted installer requires explicit systemd-boot or GRUB manifest edition")
	}
	lab := media.release.Lab
	if len(lab.InstallerPackages) == 0 {
		return nil, errors.New("arch installer requires registry base package facts")
	}
	packages := strings.Join(lab.InstallerPackages, " ") + " " + strings.Join(lab.Guest.Actions, " ")
	packages += " " + strings.Join(lab.Guest.OwnedBoot, " ") + " " + strings.Join(lab.Guest.MeasuredBoot, " ")
	if desktop != "" {
		packages += " " + strings.Join(lab.Session.Desktops[desktop], " ")
	}
	provision := `set -eu
useradd -m -s /bin/bash lindm-lab
passwd -l root
printf '%s\n' 'en_US.UTF-8 UTF-8' > /etc/locale.gen
locale-gen
printf '%s\n' 'LANG=en_US.UTF-8' > /etc/locale.conf
printf '%s\n' 'lindm-lab' > /etc/hostname
ln -sf /usr/share/zoneinfo/UTC /etc/localtime
install -d -m 0755 /etc/mkinitcpio.conf.d
printf '%s\n' 'MODULES=(virtio_pci virtio_blk virtio_scsi tpm_crb tpm_tis)' 'HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems fsck)' > /etc/mkinitcpio.conf.d/99-lindm.conf
luks=$(cryptsetup luksUUID /dev/vda3)
printf 'lindm-root UUID=%s none tpm2-device=auto\n' "$luks" > /etc/crypttab.initramfs
cp /etc/crypttab.initramfs /etc/crypttab
mkinitcpio -P
systemctl enable sshd.service NetworkManager.service
rm -f /etc/machine-id
install -m 0644 /dev/null /etc/machine-id
` + encryptedInstallerProvision(login, hostPrivate, hostPublic) + "umask 022\n" + boot
	if desktop != "" {
		provision += encryptedInstallerDesktopProvision(media.release, desktop, architecture)
	}
	// Only the key and credential writers run under umask 077. pacstrap's
	// `mkdir -p -m` creates /etc and /var with the caller's umask and pacman
	// keeps existing directory modes, so an inherited 077 leaves them
	// root-only and unprivileged D-Bus cannot read /etc/machine-id.
	return []byte(fmt.Sprintf(`#!/bin/bash
set -euo pipefail
umask 022
# archiso starts this on tty1 before all services necessarily finish.
systemctl start pacman-init.service
systemctl start network-online.target
test -b /dev/vda
test "$(lsblk -dn -o TYPE /dev/vda)" = disk
sfdisk /dev/vda <<'LINDM_PARTITIONS'
label: gpt
size=1G, type=U
size=1G, type=bc13c2ff-59e6-4262-a352-b275fd6f7172
type=L
LINDM_PARTITIONS
udevadm settle
(umask 077 && printf '%%s' %s > /run/lindm-install-key)
cryptsetup luksFormat --batch-mode --type luks2 --key-file /run/lindm-install-key /dev/vda3
cryptsetup open --key-file /run/lindm-install-key /dev/vda3 lindm-root
rm -f /run/lindm-install-key
mkfs.ext4 /dev/mapper/lindm-root
mkfs.fat -F32 /dev/vda1
mkfs.fat -F32 /dev/vda2
mount /dev/mapper/lindm-root /mnt
mount --mkdir -o fmask=0077,dmask=0077 /dev/vda2 /mnt/boot
mount --mkdir -o fmask=0077,dmask=0077 /dev/vda1 /mnt/boot/efi
printf '%%s\n' %s > /etc/pacman.d/mirrorlist
pacstrap -K /mnt %s
genfstab -U /mnt > /mnt/etc/fstab
cp /etc/pacman.d/mirrorlist /mnt/etc/pacman.d/mirrorlist
(
umask 077
%s)
arch-chroot /mnt /bin/bash -eu /root/lindm-provision
rm -f /mnt/root/lindm-provision
sync
umount -R /mnt
cryptsetup close lindm-root
systemctl poweroff
`, nativeQuote(passphrase), nativeQuote("Server = "+media.release.RollingUpdate.ArchiveURL+date.Format("2006/01/02")+"/$repo/os/$arch"), packages, encryptedInstallerProvisionFile("/mnt/root/lindm-provision", provision))), nil
}

// This edition is deliberately separate from both encrypted owner selections.
// Original-device sanitize qualifies an unencrypted installed systemd-boot disk,
// not a silent conversion of the owner's GRUB baseline.
const archRecoveryInstallerEdition = "systemd-boot-lab"

func archRecoveryInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	release := platform.ForManifest(m.GetDistribution(), m.GetVersion())
	if release.Lab.Installer != platform.ArchISO || m.GetArchitecture() != "x86_64" ||
		m.GetEdition() != archRecoveryInstallerEdition || !strings.HasSuffix(m.GetImageFilename(), ".iso") ||
		m.GetChecksumMode() != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE {
		return nil, errors.New("arch recovery requires the explicit signed archiso systemd-boot-lab manifest")
	}
	date, err := time.Parse("2006-01-02", m.GetRepositorySnapshotDate())
	if err != nil || release.RollingUpdate == nil || release.RollingUpdate.ArchiveURL == "" {
		return nil, errors.New("arch recovery installer requires an Archive repository date")
	}
	return &installerImage{
		label: "arch-systemd-boot", installer: platform.ArchISO,
		cache: "arch-installed", version: "arch-systemd-boot-v3\n" + date.Format("2006-01-02"),
		memoryMiB: 4096, firstBootDiagnostics: true, consoleDiagnostics: true,
		recipe: func(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
			return archRecoveryInstallerRecipe(release, date, disk, architecture, sourceDigest, login, hostPrivate, hostPublic)
		},
		probes: []installedProbe{
			{"distribution", ". /etc/os-release; test \"$ID\" = " + nativeQuote(release.ID)},
			{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.GetSha256())},
			{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = ext4"},
			{"boot_topology", "bootctl --esp-path=/boot/efi is-installed; test -s /boot/efi/EFI/BOOT/BOOTX64.EFI"},
		},
	}, nil
}

func archRecoveryInstallerRecipe(release *platform.Release, date time.Time, disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
	if architecture != "x86_64" || (disk != "/dev/vda" && disk != "/dev/sda" && disk != "/dev/nvme0n1") {
		return nil, errors.New("arch recovery installer requires an owned x86_64 guest disk")
	}
	login, err := encryptedInstallerPublicKey(login)
	if err != nil {
		return nil, err
	}
	hostPublic, err = encryptedInstallerPublicKey(hostPublic)
	if err != nil {
		return nil, err
	}
	host, err := ssh.ParsePrivateKey([]byte(hostPrivate))
	if err != nil || string(ssh.MarshalAuthorizedKey(host.PublicKey())) != hostPublic {
		return nil, errors.New("arch installer SSH host key pair differs")
	}
	if len(sourceDigest) != 64 || strings.Trim(sourceDigest, "0123456789abcdef") != "" {
		return nil, errors.New("arch installer requires verified source SHA256")
	}
	partition := disk
	if strings.HasPrefix(disk, "/dev/nvme") {
		partition += "p"
	}
	lab := release.Lab
	// The ordinary recovery baseline is provisioned through NoCloud like a cloud
	// image; the encrypted goldens configure their guests without cloud-init.
	packages := strings.Join(lab.InstallerPackages, " ") + " cloud-init " + strings.Join(lab.Guest.OwnedBoot, " ") + " " + strings.Join(lab.Guest.Actions, " ")
	provision := `set -eu
useradd -m -s /bin/bash lindm-lab
passwd -l root
printf '%s\n' 'en_US.UTF-8 UTF-8' > /etc/locale.gen
locale-gen
printf '%s\n' 'LANG=en_US.UTF-8' > /etc/locale.conf
printf '%s\n' 'lindm-lab' > /etc/hostname
ln -sf /usr/share/zoneinfo/UTC /etc/localtime
install -d -m0755 /etc/mkinitcpio.conf.d /etc/cloud/cloud.cfg.d
printf '%s\n' 'MODULES=(virtio_pci virtio_blk virtio_scsi nvme ahci)' 'HOOKS=(base systemd autodetect microcode modconf keyboard block filesystems fsck)' > /etc/mkinitcpio.conf.d/99-lindm.conf
mkinitcpio -P
bootctl --esp-path=/boot/efi --boot-path=/boot install --no-variables
install -d -m0755 /boot/loader/entries
printf '%s\n' 'default arch.conf' 'timeout 1' > /boot/efi/loader/loader.conf
root=$(findmnt -n -o UUID /)
test -n "$root"
printf '%s\n' 'title Arch Linux' 'linux /vmlinuz-linux' 'initrd /initramfs-linux.img' "options root=UUID=$root rw console=tty0 console=ttyS0,115200n8" > /boot/loader/entries/arch.conf
printf '%s\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lindm.cfg
systemctl enable sshd.service NetworkManager.service cloud-init-main.service cloud-init-local.service cloud-config.service cloud-final.service
cloud-init clean --logs
rm -f /etc/machine-id
install -m 0644 /dev/null /etc/machine-id
` + encryptedInstallerProvision(login, hostPrivate, hostPublic) +
		"printf '%s\\n' " + nativeQuote(sourceDigest) + " > " + nativeQuote(installerSourceMarkerPath) + "\n"
	// See archEncryptedInstallerRecipe: credentials alone use umask 077.
	// archiso runs the script on tty1; stderr and the failing line also reach
	// the serial console for the bounded, redacted installer diagnostics.
	return []byte(fmt.Sprintf(`#!/bin/bash
set -euo pipefail
umask 022
exec 2> >(tee /dev/console >&2)
trap 'echo "lindm installer failed at line $LINENO" >&2' ERR
systemctl start pacman-init.service
systemctl start network-online.target
test -b %[1]s
test "$(lsblk -dn -o TYPE %[1]s)" = disk
sfdisk %[1]s <<'LINDM_PARTITIONS'
label: gpt
size=1G, type=U
size=1G, type=bc13c2ff-59e6-4262-a352-b275fd6f7172
type=L
LINDM_PARTITIONS
udevadm settle
mkfs.fat -F32 %[2]s1
mkfs.fat -F32 %[2]s2
mkfs.ext4 %[2]s3
mount %[2]s3 /mnt
mount --mkdir -o fmask=0077,dmask=0077 %[2]s2 /mnt/boot
mount --mkdir -o fmask=0077,dmask=0077 %[2]s1 /mnt/boot/efi
printf '%%s\n' %[3]s > /etc/pacman.d/mirrorlist
pacstrap -K /mnt %[4]s
genfstab -U /mnt > /mnt/etc/fstab
cp /etc/pacman.d/mirrorlist /mnt/etc/pacman.d/mirrorlist
(
umask 077
%[5]s)
arch-chroot /mnt /bin/bash -eu /root/lindm-provision
rm -f /mnt/root/lindm-provision
sync
umount -R /mnt
systemctl poweroff
`, disk, partition, nativeQuote("Server = "+release.RollingUpdate.ArchiveURL+date.Format("2006/01/02")+"/$repo/os/$arch"), packages, encryptedInstallerProvisionFile("/mnt/root/lindm-provision", provision))), nil
}
