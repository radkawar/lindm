//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"strings"
	"time"
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
