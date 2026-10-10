//go:build linux

package vmlab

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const debianInstallerRecipeVersion = "debian-netinst-v1"

func debianInstallerRecipe(version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
	var suite string
	switch version {
	case "12":
		suite = "bookworm"
	case "13":
		suite = "trixie"
	default:
		return nil, errors.New("debian installer requires version 12 or 13")
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
	provision += "install -d -m 0755 /etc/cloud/cloud.cfg.d /etc/default/grub.d\nprintf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg\n"
	provision += "printf '%s\\n' 'GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0 console=" + console + "\"' > /etc/default/grub.d/99-lindm-lab.cfg\nupdate-grub\n"
	provision += "printf '%s\\n' '" + sourceDigest + "' > /etc/lindm-lab-installer-source\n"
	provision += "systemctl enable ssh\ncloud-init clean --logs\nrm -f /etc/machine-id\ntouch /etc/machine-id\n"
	// Base64 keeps credential bytes outside debconf and shell token syntax.
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
 d-i partman-auto/method string regular
 d-i partman-auto/choose_recipe select atomic
 d-i partman-lvm/device_remove_lvm boolean true
 d-i partman-md/device_remove_md boolean true
 d-i partman-partitioning/confirm_write_new_label boolean true
 d-i partman/choose_partition select finish
 d-i partman/confirm boolean true
 d-i partman/confirm_nooverwrite boolean true
 d-i partman-efi/non_efi_system boolean true
 tasksel tasksel/first multiselect standard, ssh-server
 d-i pkgsel/include string openssh-server sudo cloud-init ca-certificates
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
`, suite, disk, disk, late)), nil
}

func debianInstallerDisk(storage string) string {
	switch storage {
	case "virtio-blk":
		return "/dev/vda"
	case "nvme":
		return "/dev/nvme0n1"
	default:
		return "/dev/sda"
	}
}

// runDebianInstaller boots vendor EFI/kernel payloads from privately remastered
// media. Only the disposable guest receives network access and disk writes.
func runDebianInstaller(ctx context.Context, dir, installer string, hardware VMHardwareOptions) (err error) {
	relative, err := filepath.Rel(dir, installer)
	if err != nil || !filepath.IsLocal(relative) || strings.ContainsAny(relative, ",\r\n") {
		return errors.New("debian installer media must remain inside private staging")
	}
	machine, cpu := "q35", "max"
	if hardware.Architecture == "aarch64" {
		machine = "virt"
	}
	if hardware.Accelerator == "kvm" {
		cpu = "host"
	}
	machine += ",accel=" + hardware.Accelerator
	if hardware.Architecture == "x86_64" && hardware.Firmware.SecureBoot {
		machine += ",smm=on"
	}
	// Keep the guest UART present for Debian's text frontend, but discard
	// serial bytes rather than retaining credential-bearing installer output.
	args := []string{"-no-user-config", "-nodefaults", "-display", "none", "-serial", "null", "-monitor", "none", "-machine", machine, "-cpu", cpu, "-m", "2048", "-smp", "2",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=firmware-code.fd", "-drive", "if=pflash,format=raw,unit=1,file=nvram.fd",
		"-drive", "if=none,id=disk,format=qcow2,file=image", "-device", "virtio-rng-pci",
		"-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0,id=nic0",
		"-drive", "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=" + relative,
		"-device", "virtio-scsi-pci,id=installer-scsi", "-device", "scsi-cd,bus=installer-scsi.0,drive=installer,bootindex=0"}
	if hardware.Architecture == "x86_64" && hardware.Firmware.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}
	args = append(args, vmStorageArguments(hardware, []string{"disk"}, 1)...)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	process, err := startEncryptedProcess(ctx, dir, "qemu-system-"+hardware.Architecture, args...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, process.stop()) }()
	select {
	case <-ctx.Done():
		return fmt.Errorf("debian installer deadline: %w", ctx.Err())
	case <-process.done:
		if process.err != nil {
			return fmt.Errorf("debian installer failed: %w; %s", process.err, process.log.diagnostic(dir))
		}
		return nil
	}
}
