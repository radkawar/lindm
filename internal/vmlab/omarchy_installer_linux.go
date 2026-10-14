// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
	"lindm/internal/platform"
)

// Omarchy 4 installs only from its signed ISO. The vendor's documented
// unattended path (manual/51-unattended-installs.md at v4.0.4) needs no
// remaster: a second drive labeled cidata carrying the configurator's own
// output files (user_configuration.json, user_credentials.json, optional
// authorized_keys and user_encrypt_installation.txt) replaces the wizard, the
// ISO's orchestrator installs from its bundled offline mirror and reboots.
// The lab attaches the authenticated ISO byte-for-byte and stops QEMU on that
// reboot. A minimal, documented provisioning step then adds only what the lab
// needs: a pinned SSH host key, NOPASSWD sudo for the lab account and the
// source marker are written offline; one provisioning boot installs signed
// cloud-init from the same ISO's offline repository (unencrypted golden) or
// adds the serial console and portable storage modules to the vendor's own
// Limine/mkinitcpio drop-ins (encrypted golden).
const (
	omarchyVersion                   = "4.0.4"
	omarchyInstallerEdition          = "hyprland"
	omarchyEncryptedInstallerEdition = "hyprland-encrypted-lab"
	omarchyInstallerImageFilename    = "omarchy-" + omarchyVersion + ".iso"
	// Bump when the cidata seed, provisioning or machine layout changes.
	omarchyInstallerRecipeVersion = "omarchy-cidata-v1"
	// The cloud golden additionally installs the registry's resource
	// prerequisites from the ISO; bump with its own provisioning changes.
	omarchyCloudRecipeVersion = omarchyInstallerRecipeVersion + "+resources-v1"
	// The configurator's fixed partition object IDs (root/configurator at the
	// pinned ISO); the encryption block names the root partition by this ID.
	omarchyBootPartitionID = "ea21d3f2-82bb-49cc-ab5d-6f81ae94e18d"
	omarchyRootPartitionID = "8c2c2b92-1070-455d-b76a-56263bab24aa"
	omarchyDiskBytes       = 24 << 30
	omarchyHostname        = "omarchy"
	omarchySudoers         = "/etc/sudoers.d/90-lindm-lab"
	omarchyConsoleDropIn   = "/etc/limine-entry-tool.d/90-lindm-lab-console.conf"
	omarchyStorageDropIn   = "/etc/mkinitcpio.conf.d/zz-lindm-lab.conf"
	omarchyCloudConfig     = "/etc/cloud/cloud.cfg.d/90-lindm-lab.cfg"
	// The last console is /dev/console, where the LUKS prompt appears.
	omarchySerialConsole = "console=tty0 console=ttyS0,115200"
)

// omarchyManifest accepts only the signed, image-signature-authenticated
// Omarchy 4.0.4 x86_64 ISO under the named edition, for the registry release
// whose lab installer is the Omarchy cidata mode.
func omarchyManifest(m *labv1.ImageManifest, edition string) error {
	if platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab.Installer != platform.OmarchyCidata ||
		m.GetVersion() != omarchyVersion || m.GetEdition() != edition ||
		m.GetRelease() != omarchyVersion || m.GetArchitecture() != "x86_64" ||
		m.GetImageFilename() != omarchyInstallerImageFilename ||
		m.GetChecksumMode() != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED_IMAGE {
		return fmt.Errorf("omarchy %s lab requires the signed Omarchy %s x86_64 ISO manifest", edition, omarchyVersion)
	}
	return nil
}

// omarchyInstallerImage builds the unencrypted golden for cloud-style lanes.
func omarchyInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	if err := omarchyManifest(m, omarchyInstallerEdition); err != nil {
		return nil, err
	}
	return &installerImage{
		label:     "Omarchy",
		installer: platform.OmarchyCidata,
		cache:     "omarchy-installed",
		version:   omarchyCloudRecipeVersion,
		memoryMiB: 4096,
		install: func(ctx context.Context, dir string, iso *os.File, digest string, hardware VMHardwareOptions) error {
			return omarchyInstallGolden(ctx, dir, "image", iso, digest, hardware, omarchyGoldenSecrets{actions: omarchyCloudPackages(m)})
		},
		probes: omarchyProbes(m, false),
	}, nil
}

func omarchyProbes(m *labv1.ImageManifest, encrypted bool) []installedProbe {
	probes := []installedProbe{
		{"distribution", ". /etc/os-release; test \"$ID\" = " + nativeQuote(platform.ForManifest(m.GetDistribution(), m.GetVersion()).ID)},
		{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(omarchyVersion)},
		{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.GetSha256())},
		{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = btrfs"},
		{"package_tool", "command -v pacman >/dev/null"},
		{"privilege_tool", "command -v sudo >/dev/null"},
		// The offline install leaves no sync databases; query only the local one.
		{"omarchy_runtime", "test \"$(pacman --config /dev/null -Q omarchy)\" = " + nativeQuote("omarchy "+omarchyVersion+"-1")},
		// A fresh NVRAM boots only the vendor's removable Limine fallback.
		{"removable_boot_path", "test -s /boot/EFI/BOOT/BOOTX64.EFI"},
		// omarchy-settings installs the uwsm-managed session here.
		{"hyprland_session", "test -f /usr/local/share/wayland-sessions/omarchy.desktop"},
	}
	if encrypted {
		return append(probes,
			installedProbe{"luks_root", "test \"$(lsblk -n -o TYPE \"$(findmnt -n -o SOURCE / | sed 's/\\[.*//')\")\" = crypt"},
			installedProbe{"serial_console", "grep -qw console=ttyS0,115200 /proc/cmdline"},
			installedProbe{"autologin", "grep -qx User=lindm-lab /etc/sddm.conf.d/autologin.conf"})
	}
	release := platform.ForManifest(m.GetDistribution(), m.GetVersion())
	return append(probes, installedProbe{"cloud_init", "pacman --config /dev/null -Q cloud-init >/dev/null"},
		installedProbe{"resource_prerequisites", "pacman --config /dev/null -Q " + strings.Join(release.Lab.ResourcePackages, " ") + " >/dev/null"})
}

// omarchyGoldenSecrets carries the encrypted golden's lab-only credentials
// and the registry's device-action prerequisites the golden installs from the
// ISO. An empty passphrase selects the unencrypted cloud-init golden.
type omarchyGoldenSecrets struct {
	passphrase string
	loginKey   []byte
	hostKey    []byte
	actions    []string
}

func omarchyActions(m *labv1.ImageManifest) []string {
	return platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab.Guest.Actions
}

// omarchyCloudPackages are the cloud golden's ISO-installed prerequisites:
// device actions plus the resource lane's native tools, deduplicated.
func omarchyCloudPackages(m *labv1.ImageManifest) []string {
	lab := platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab
	packages := slices.Clone(lab.Guest.Actions)
	for _, name := range lab.ResourcePackages {
		if !slices.Contains(packages, name) {
			packages = append(packages, name)
		}
	}
	return packages
}

// omarchySeed is the configurator-equivalent input written to the cidata drive.
type omarchySeed struct {
	disk          string
	diskBytes     int64
	passwordHash  string
	passphrase    string
	authorizedKey string
}

// omarchyCidataFiles reproduces the pinned configurator's output files. The
// configuration carries the LUKS passphrase in plaintext for encrypted
// installs; the drive therefore stays inside private staging.
func omarchyCidataFiles(seed omarchySeed) (map[string][]byte, error) {
	if !strings.HasPrefix(seed.disk, "/dev/") || seed.diskBytes < 8<<30 {
		return nil, errors.New("omarchy seed requires a whole target disk of at least 8 GiB")
	}
	if !strings.HasPrefix(seed.passwordHash, "$6$") || strings.ContainsAny(seed.passwordHash, "\r\n") {
		return nil, errors.New("omarchy seed requires a SHA-512 crypt password hash")
	}
	if strings.ContainsAny(seed.passphrase, "\r\n\x00") {
		return nil, errors.New("omarchy seed passphrase must be a single line")
	}
	key, err := encryptedInstallerPublicKey(seed.authorizedKey)
	if err != nil {
		return nil, err
	}
	const mib, gib = int64(1 << 20), int64(1 << 30)
	diskMiB := seed.diskBytes / mib * mib
	bootStart, bootSize := mib, 2*gib
	mainStart := bootStart + bootSize
	mainSize := diskMiB - mainStart - mib
	size := func(value int64) map[string]any {
		return map[string]any{"sector_size": map[string]any{"unit": "B", "value": 512}, "unit": "B", "value": value}
	}
	disk := map[string]any{
		"config_type": "default_layout",
		"device_modifications": []any{map[string]any{
			"device": seed.disk,
			"partitions": []any{
				map[string]any{"btrfs": []any{}, "dev_path": nil, "flags": []string{"boot", "esp"}, "fs_type": "fat32", "mount_options": []string{}, "mountpoint": "/boot", "obj_id": omarchyBootPartitionID, "size": size(bootSize), "start": size(bootStart), "status": "create", "type": "primary"},
				map[string]any{"btrfs": []any{
					map[string]string{"mountpoint": "/", "name": "@"},
					map[string]string{"mountpoint": "/home", "name": "@home"},
					map[string]string{"mountpoint": "/var/log", "name": "@log"},
					map[string]string{"mountpoint": "/var/cache/pacman/pkg", "name": "@pkg"},
				}, "dev_path": nil, "flags": []string{}, "fs_type": "btrfs", "mount_options": []string{"compress=zstd"}, "mountpoint": nil, "obj_id": omarchyRootPartitionID, "size": size(mainSize), "start": size(mainStart), "status": "create", "type": "primary"},
			},
			"wipe": true,
		}},
	}
	credentials := map[string]any{
		"root_enc_password": seed.passwordHash,
		"users":             []any{map[string]any{"enc_password": seed.passwordHash, "groups": []string{}, "sudo": true, "username": labUser}},
	}
	encrypt := "false\n"
	if seed.passphrase != "" {
		disk["disk_encryption"] = map[string]any{"encryption_type": "luks", "lvm_volumes": []any{}, "iter_time": 2000, "partitions": []string{omarchyRootPartitionID}, "encryption_password": seed.passphrase}
		credentials["encryption_password"] = seed.passphrase
		encrypt = "true\n"
	}
	configuration := map[string]any{
		"app_config": nil, "archinstall-language": "English", "auth_config": map[string]any{},
		"audio_config":      map[string]any{"audio": "pipewire"},
		"bootloader_config": map[string]any{"bootloader": "Limine", "uki": false, "removable": false},
		"custom_commands":   []any{},
		"omarchy_install": map[string]any{
			"mode": "full_disk", "defer_provisioning": false, "target_mount": "/mnt",
			"boot":    map[string]any{"esp_mount": "/boot", "esp_path": "/EFI/limine", "efi_binary": "limine_x64.efi", "enable_fallback": true},
			"storage": map[string]any{"kernel": "linux-omarchy"},
		},
		"disk_config": disk,
		"hostname":    omarchyHostname, "kernels": []string{"linux-omarchy"},
		"network_config": map[string]any{"type": "iso"}, "ntp": true, "parallel_downloads": 8,
		"script": nil, "services": []any{}, "swap": true, "timezone": "UTC",
		"locale_config": map[string]any{"kb_layout": "us", "sys_enc": "UTF-8", "sys_lang": "en_US.UTF-8"},
		"mirror_config": map[string]any{
			"custom_repositories": []any{},
			"custom_servers": []any{
				map[string]string{"url": "https://mirror.omarchy.org/$repo/os/$arch"},
				map[string]string{"url": "https://mirror.rackspace.com/archlinux/$repo/os/$arch"},
				map[string]string{"url": "https://geo.mirror.pkgbuild.com/$repo/os/$arch"},
			},
			"mirror_regions": map[string]any{}, "optional_repositories": []any{},
		},
		"packages":       []string{"base-devel", "git", "omarchy-keyring", "omarchy-settings", "omarchy"},
		"profile_config": map[string]any{"gfx_driver": nil, "greeter": nil, "profile": map[string]any{}},
		"version":        "3.0.9",
	}
	config, err := json.MarshalIndent(configuration, "", "    ")
	if err != nil {
		return nil, err
	}
	creds, err := json.MarshalIndent(credentials, "", "    ")
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"user_configuration.json":       append(config, '\n'),
		"user_credentials.json":         append(creds, '\n'),
		"user_encrypt_installation.txt": []byte(encrypt),
		"authorized_keys":               []byte(key),
	}, nil
}

// omarchyPasswordHash hashes a random lab-only account password with the
// vendor-documented `openssl passwd -6`. The plaintext is never retained.
func omarchyPasswordHash(ctx context.Context, dir string) (string, error) {
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	out := nativeexec.NewBuffer(4096)
	if err := labexec.Run(ctx, labexec.Command{Path: "openssl", Args: []string{"passwd", "-6", "-stdin"}, Dir: dir, Env: []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}, Stdin: strings.NewReader(hex.EncodeToString(secret) + "\n"), Stdout: out, Timeout: time.Minute}); err != nil {
		return "", fmt.Errorf("openssl passwd -6: %w", err)
	}
	hash := strings.TrimSpace(out.String())
	if !strings.HasPrefix(hash, "$6$") || strings.ContainsAny(hash, " \r\n") {
		return "", errors.New("openssl passwd -6 returned no SHA-512 crypt hash")
	}
	return hash, nil
}

// omarchyInstallGolden installs into dir/disk from the borrowed verified ISO,
// then provisions it. dir must already hold firmware-code.fd and nvram.fd.
func omarchyInstallGolden(ctx context.Context, dir, disk string, iso *os.File, digest string, hardware VMHardwareOptions, secrets omarchyGoldenSecrets) error {
	if hardware.Architecture != "x86_64" || hardware.Firmware == nil {
		return errors.New("omarchy installer requires x86_64 UEFI firmware")
	}
	if len(secrets.actions) == 0 {
		return errors.New("omarchy golden requires the registry's device-action prerequisites")
	}
	if strings.ContainsAny(dir, ",\r\n") {
		return errors.New("omarchy staging path must not contain commas or newlines")
	}
	encrypted := secrets.passphrase != ""
	loginKey, loginPublic := secrets.loginKey, ""
	hostKey := secrets.hostKey
	var err error
	if encrypted {
		login, parseErr := ssh.ParsePrivateKey(loginKey)
		if parseErr != nil {
			return parseErr
		}
		loginPublic = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(login.PublicKey())))
	} else {
		// The unencrypted golden's install credentials exist only for the
		// provisioning boot; validation and every lane use fresh NoCloud keys.
		if loginKey, loginPublic, err = encryptedKey(); err != nil {
			return err
		}
		if hostKey, _, err = encryptedKey(); err != nil {
			return err
		}
	}
	hash, err := omarchyPasswordHash(ctx, dir)
	if err != nil {
		return err
	}
	files, err := omarchyCidataFiles(omarchySeed{disk: installerDisk(hardware.StorageBus), diskBytes: omarchyDiskBytes, passwordHash: hash, passphrase: secrets.passphrase, authorizedKey: loginPublic})
	if err != nil {
		return err
	}
	if err := omarchyCidataImage(ctx, dir, files); err != nil {
		return err
	}
	if err := omarchyRunInstaller(ctx, dir, disk, iso, hardware); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "cidata.img")); err != nil {
		return err
	}
	if err := omarchyOfflineProvision(ctx, dir, disk, digest, secrets.passphrase, hostKey); err != nil {
		return err
	}
	return omarchyProvisionBoot(ctx, dir, disk, iso, hardware, loginKey, hostKey, secrets.passphrase, secrets.actions)
}

// omarchyCidataImage writes the seed as a FAT drive labeled CIDATA, the
// vendor's own integration-test form.
func omarchyCidataImage(ctx context.Context, dir string, files map[string][]byte) (err error) {
	source, err := os.MkdirTemp(dir, "cidata-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(source)) }()
	args := []string{"-i", "cidata.img"}
	for name, data := range files {
		path := filepath.Join(source, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		args = append(args, path)
	}
	if _, err := hostCommand(ctx, dir, "mkfs.vfat", nil, "-C", "-n", "CIDATA", "cidata.img", "8192"); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(dir, "cidata.img"), 0600); err != nil {
		return err
	}
	_, err = hostCommand(ctx, dir, "mcopy", nil, append(args, "::/")...)
	return err
}

func omarchyMachine(hardware VMHardwareOptions) (machine, cpu string) {
	machine, cpu = "q35,accel="+hardware.Accelerator, "max"
	if hardware.Accelerator == "kvm" {
		cpu = "host"
	}
	if hardware.Firmware.SecureBoot {
		machine += ",smm=on"
	}
	return machine, cpu
}

func omarchyFirmwareArguments(hardware VMHardwareOptions) []string {
	args := []string{"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + "firmware-code.fd", "-drive", "if=pflash,format=raw,unit=1,file=nvram.fd"}
	if hardware.Firmware.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}
	return args
}

// omarchyRunInstaller boots the unmodified ISO with the cidata drive. The
// vendor dashboard reboots after an unattended success; -no-reboot turns that
// into a successful QEMU exit so the media never boots twice. Installer
// failures stop on the vendor failure menu and hit the deadline instead.
func omarchyRunInstaller(ctx context.Context, dir, disk string, iso *os.File, hardware VMHardwareOptions) (err error) {
	machine, cpu := omarchyMachine(hardware)
	args := []string{"-no-user-config", "-nodefaults", "-display", "none", "-serial", "null", "-monitor", "none", "-no-reboot",
		"-machine", machine, "-cpu", cpu, "-m", "4096", "-smp", "4"}
	args = append(args, omarchyFirmwareArguments(hardware)...)
	args = append(args,
		"-drive", "if=none,id=disk,format=qcow2,file="+disk, "-device", "virtio-rng-pci",
		"-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0,id=nic0",
		"-drive", "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=/proc/self/fd/3",
		"-device", "ide-cd,drive=installer,bootindex=0",
		"-drive", "if=none,id=cidata,format=raw,file=cidata.img",
		"-device", "qemu-xhci,id=usb", "-device", "usb-storage,bus=usb.0,drive=cidata")
	args = append(args, vmStorageArguments(hardware, []string{"disk"}, 1)...)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	process, err := startEncryptedProcessFiles(ctx, dir, []*os.File{iso}, "qemu-system-x86_64", args...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, process.stop()) }()
	select {
	case <-ctx.Done():
		return fmt.Errorf("omarchy installer deadline (vendor failure menu or stalled install): %w", ctx.Err())
	case <-process.done:
		if process.err != nil {
			return fmt.Errorf("omarchy installer failed: %w; %s", process.err, process.log.diagnostic(dir))
		}
		return nil
	}
}

// omarchyOfflineProvision writes lab-only files into the stopped installed
// root (Btrfs subvolume @, inside LUKS when encrypted) with libguestfs. It
// never attaches host block devices. Files: pinned SSH host key, NOPASSWD sudo
// for the lab account and the root-only installer source marker.
func omarchyOfflineProvision(ctx context.Context, dir, disk, digest, passphrase string, hostKey []byte) (err error) {
	signer, err := ssh.ParsePrivateKey(hostKey)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, "offline-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	files := []struct {
		name, path, mode string
		data             []byte
	}{
		{"host", "/etc/ssh/ssh_host_ed25519_key", "0600", hostKey},
		{"host.pub", "/etc/ssh/ssh_host_ed25519_key.pub", "0644", ssh.MarshalAuthorizedKey(signer.PublicKey())},
		{"sudoers", omarchySudoers, "0440", []byte(labUser + " ALL=(ALL) NOPASSWD: ALL\n")},
		{"marker", installerSourceMarkerPath, "0600", []byte(digest + "\n")},
	}
	root := "/dev/sda2"
	args := []string{"--", "add-drive-opts", filepath.Join(dir, disk), "format:qcow2", ":", "run"}
	if passphrase != "" {
		root = "/dev/mapper/lindmroot"
		args = append(args, ":", "cryptsetup-open", "/dev/sda2", "lindmroot")
	}
	args = append(args, ":", "mount-options", "subvol=@", root, "/")
	for _, file := range files {
		path := filepath.Join(stage, file.name)
		if err := os.WriteFile(path, file.data, 0600); err != nil {
			return err
		}
		args = append(args, ":", "upload", path, file.path, ":", "chown", "0", "0", file.path, ":", "chmod", file.mode, file.path)
	}
	args = append(args, ":", "sync", ":", "umount-all")
	if passphrase != "" {
		args = append(args, ":", "cryptsetup-close", "/dev/mapper/lindmroot")
	}
	args = append(args, ":", "shutdown")
	if err := omarchyGuestfish(ctx, dir, passphrase, args...); err != nil {
		return err
	}
	if passphrase == "" {
		return nil
	}
	return omarchyBootstrapConsole(ctx, dir, disk, stage)
}

// omarchyBootstrapConsole adds the serial console to the vendor Limine
// entries' cmdline on the unencrypted ESP for the single provisioning boot,
// so its LUKS prompt is unlocked through the lab's prompt-gated serial path.
// Limine hands that cmdline to the UKI, whose stub honours it with Secure
// Boot off. Provisioning then persists the console through the vendor's
// drop-in and limine-update, which regenerates this file and the UKI.
func omarchyBootstrapConsole(ctx context.Context, dir, disk, stage string) error {
	local := filepath.Join(stage, "limine.conf")
	image := filepath.Join(dir, disk)
	if err := omarchyGuestfish(ctx, dir, "", "--ro", "--", "add-drive-opts", image, "format:qcow2", "readonly:true", ":", "run", ":", "mount-ro", "/dev/sda1", "/", ":", "download", "/limine.conf", local); err != nil {
		return err
	}
	original, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	edited, err := omarchyConsoleCmdline(original)
	if err != nil {
		return err
	}
	if err := os.WriteFile(local, edited, 0600); err != nil {
		return err
	}
	return omarchyGuestfish(ctx, dir, "", "--", "add-drive-opts", image, "format:qcow2", ":", "run", ":", "mount", "/dev/sda1", "/", ":", "upload", local, "/limine.conf", ":", "sync", ":", "umount-all", ":", "shutdown")
}

// omarchyConsoleCmdline appends the serial console to every Limine cmdline
// that unlocks the LUKS root, and requires at least one such entry.
func omarchyConsoleCmdline(config []byte) ([]byte, error) {
	lines := strings.Split(string(config), "\n")
	changed := 0
	for i, line := range lines {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || (key != "cmdline" && key != "kernel_cmdline") || !strings.Contains(value, "cryptdevice=") {
			continue
		}
		if strings.Contains(value, "console=") {
			return nil, errors.New("omarchy Limine cmdline already selects a console")
		}
		lines[i] = strings.TrimRight(line, " \t") + " " + omarchySerialConsole
		changed++
	}
	if changed == 0 {
		return nil, errors.New("omarchy limine.conf has no LUKS root cmdline entry")
	}
	return []byte(strings.Join(lines, "\n")), nil
}

// omarchyGuestfish runs the libguestfs direct appliance with the same private
// environment as the encrypted header oracle. A non-empty key is supplied on
// stdin for cryptsetup-open only; it never appears in arguments.
func omarchyGuestfish(ctx context.Context, dir, key string, args ...string) error {
	var stdin io.Reader
	if key != "" {
		args = append([]string{"--keys-from-stdin"}, args...)
		stdin = strings.NewReader(key + "\n")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "LC_ALL=C", "LIBGUESTFS_BACKEND=direct", "LIBGUESTFS_TMPDIR=" + dir}
	kernel, modules, err := encryptedSuperminPaths()
	if err != nil {
		return err
	}
	if kernel != "" {
		env = append(env, "SUPERMIN_KERNEL="+kernel, "SUPERMIN_MODULES="+modules)
	}
	log := new(vmLog)
	if err := labexec.Run(ctx, labexec.Command{Path: "guestfish", Args: args, Env: env, Dir: dir, Stdin: stdin, Stdout: log, Stderr: log, Timeout: 5 * time.Minute}); err != nil {
		return fmt.Errorf("omarchy offline provisioning (guestfish with btrfs/cryptsetup appliance required): %w; %s", err, log.diagnostic(dir))
	}
	return nil
}

// omarchyOfflineRepository installs packages only from the authenticated ISO's
// bundled offline mirror. Package signatures are required; the vendor ships
// that repository database unsigned, so only databases are optional. A sync
// database the installer left under the same repository name is restored.
const omarchyOfflineRepository = `iso=$(blkid -o device -t TYPE=iso9660)
test -n "$iso" && test "$(printf '%s\n' "$iso" | wc -l)" -eq 1
install -d -m 0700 /run/lindm-iso /run/lindm-airootfs /run/lindm-vendor-sync
mount -o ro "$iso" /run/lindm-iso
mount -o ro,loop /run/lindm-iso/arch/x86_64/airootfs.sfs /run/lindm-airootfs
for db in offline.db offline.db.sig; do
  if [ -e "/var/lib/pacman/sync/$db" ]; then mv "/var/lib/pacman/sync/$db" /run/lindm-vendor-sync/; fi
done
cat > /run/lindm-pacman.conf <<'LINDM_PACMAN'
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Required
[offline]
SigLevel = PackageRequired
Server = file:///run/lindm-airootfs/var/cache/omarchy/mirror/offline
LINDM_PACMAN
`

const omarchyOfflineRepositoryCleanup = `rm -f /var/lib/pacman/sync/offline.db /var/lib/pacman/sync/offline.db.sig /run/lindm-pacman.conf
for db in /run/lindm-vendor-sync/*; do
  if [ -e "$db" ]; then mv "$db" /var/lib/pacman/sync/; fi
done
umount /run/lindm-airootfs /run/lindm-iso
`

// omarchyProvisionScript is the single root provisioning step of the
// provisioning boot. It is distinct per golden variant.
func omarchyProvisionScript(encrypted bool, actions []string) string {
	var script strings.Builder
	script.WriteString("umask 022\n")
	if encrypted {
		// Device-action lab prerequisites come from the authenticated ISO's
		// signed offline repository at the same package snapshot as the
		// install, never a partial upgrade against rolling mirrors.
		script.WriteString(omarchyOfflineRepository)
		script.WriteString("pacman --config /run/lindm-pacman.conf --noconfirm --needed -Sy " + strings.Join(actions, " ") + "\n")
		script.WriteString(omarchyOfflineRepositoryCleanup)
		// Serial console for the lab's prompt-gated LUKS unlock, and storage
		// modules so the autodetected initramfs also boots the lab's other
		// emulated controllers. The plymouth hook is dropped from the lab
		// initramfs: its password display redraws the prompt per keystroke and
		// hides cryptsetup's rejection, while the encrypt hook's console
		// fallback reports both. All of it goes through the vendor's own
		// drop-in directories (the mkinitcpio one sorts after Omarchy's
		// HOOKS and MODULES files) and limine-update, which rebuilds the UKI.
		script.WriteString("printf '%s\\n' 'KERNEL_CMDLINE[default]+=\" " + omarchySerialConsole + "\"' > " + omarchyConsoleDropIn + "\n")
		script.WriteString("printf '%s\\n' 'MODULES+=(virtio_blk virtio_scsi sd_mod ahci nvme)' '_lindm_hooks=()' 'for _lindm_hook in \"${HOOKS[@]}\"; do [[ $_lindm_hook == plymouth ]] || _lindm_hooks+=(\"$_lindm_hook\"); done' 'HOOKS=(\"${_lindm_hooks[@]}\")' 'unset _lindm_hooks _lindm_hook' > " + omarchyStorageDropIn + "\n")
		script.WriteString("limine-update\n")
		script.WriteString("grep -q 'console=ttyS0,115200' /boot/limine.conf\n")
	} else {
		script.WriteString(omarchyOfflineRepository)
		// The cloud golden also serves as the device-action recovery root.
		script.WriteString("pacman --config /run/lindm-pacman.conf --noconfirm --needed -Sy cloud-init " + strings.Join(actions, " ") + "\n")
		script.WriteString(omarchyOfflineRepositoryCleanup)
		script.WriteString("install -d -m 0755 /etc/cloud/cloud.cfg.d\n")
		script.WriteString("printf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > " + omarchyCloudConfig + "\n")
		script.WriteString("systemctl enable cloud-init-main.service cloud-init-local.service cloud-init-network.service cloud-config.service cloud-final.service\n")
		// Remove the provisioning-only credentials: cloud-init installs fresh
		// host keys, the lab account's keys and its sudo rule on every lane.
		script.WriteString("rm -f /home/" + labUser + "/.ssh/authorized_keys /etc/ssh/ssh_host_* " + omarchySudoers + "\n")
	}
	// Arm the poweroff while still root: the sudo rule may be gone already.
	script.WriteString("systemd-run --on-active=2 --timer-property=AccuracySec=100ms systemctl poweroff\n")
	return script.String()
}

// omarchyProvisionBoot boots the installed disk once with the ISO attached as
// a non-boot CD-ROM, authenticates the pinned host key, runs the provisioning
// script and powers off. An encrypted root is unlocked only after its prompt
// appears on the bootstrapped serial console.
func omarchyProvisionBoot(ctx context.Context, dir, disk string, iso *os.File, hardware VMHardwareOptions, loginKey, hostKey []byte, passphrase string, actions []string) (err error) {
	config, err := encryptedSSHConfig(loginKey, hostKey)
	if err != nil {
		return err
	}
	sub, err := os.MkdirTemp(dir, "provision-")
	if err != nil {
		return err
	}
	address, port, err := omarchyLoopbackPort()
	if err != nil {
		return errors.Join(err, os.RemoveAll(sub))
	}
	machine, cpu := omarchyMachine(hardware)
	args := []string{"-no-user-config", "-nodefaults", "-display", "none", "-monitor", "none",
		"-qmp", "unix:qmp.sock,server=on,wait=off",
		"-chardev", "socket,id=serial,path=serial.sock,server=on,wait=off", "-device", "isa-serial,chardev=serial",
		"-machine", machine, "-cpu", cpu, "-m", "4096", "-smp", "4",
		"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + filepath.Join(dir, "firmware-code.fd"),
		"-drive", "if=pflash,format=raw,unit=1,file=" + filepath.Join(dir, "nvram.fd"),
		"-drive", "if=none,id=disk,format=qcow2,file=" + filepath.Join(dir, disk), "-device", "virtio-rng-pci",
		"-netdev", "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:" + port + "-:22", "-device", "virtio-net-pci,netdev=net0,id=nic0",
		"-drive", "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=/proc/self/fd/3",
		"-device", "ide-cd,drive=installer"}
	if hardware.Firmware.SecureBoot {
		args = append(args, "-global", "driver=cfi.pflash01,property=secure,value=on")
	}
	args = append(args, vmStorageArguments(hardware, []string{"disk"}, 0)...)
	process, err := startEncryptedProcessFiles(ctx, sub, []*os.File{iso}, "qemu-system-x86_64", args...)
	if err != nil {
		return errors.Join(err, os.RemoveAll(sub))
	}
	vm := &guestVM{dir: sub, cmd: process.cmd, log: process.log, address: address, config: config, hardware: hardware}
	done := make(chan struct{})
	go func() {
		<-process.done
		vm.waitErr = process.err
		close(done)
	}()
	vm.done = done
	defer func() {
		if err != nil {
			err = errors.Join(err, vm.close())
		}
	}()
	if err := omarchyConnect(ctx, vm, passphrase); err != nil {
		return fmt.Errorf("omarchy provisioning boot: %w", err)
	}
	result, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(omarchyProvisionScript(passphrase != "", actions)), nil, 256<<10, 20*time.Minute)
	if err != nil {
		return fmt.Errorf("omarchy provisioning: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("omarchy provisioning exited %d: %s", result.ExitCode, omarchyTail(result.Stderr))
	}
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		return errors.New("omarchy provisioning boot did not power off")
	case <-ctx.Done():
		return ctx.Err()
	}
	return vm.closeAfterExpectedExit()
}

// omarchyConnect waits for pinned SSH. With a passphrase it concurrently
// answers the vendor initramfs's first LUKS prompt on the serial console.
// This bootstrap boot still runs the vendor plymouth hook, whose password
// display redraws its prompt for each keystroke, so a redraw is not read as
// a rejection here: the passphrase was just proven by the offline open, and
// a failed unlock surfaces as the SSH readiness deadline.
func omarchyConnect(ctx context.Context, vm *guestVM, passphrase string) error {
	if passphrase == "" {
		return vm.connect(ctx)
	}
	dial, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var console net.Conn
	for {
		var err error
		if console, err = (&net.Dialer{}).DialContext(dial, "unix", filepath.Join(vm.dir, "serial.sock")); err == nil {
			break
		}
		if err := vm.processError(); err != nil {
			return err
		}
		select {
		case <-dial.Done():
			return dial.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer func() { _ = console.Close() }()
	boot, stop := context.WithCancel(dial)
	defer stop()
	sent := make(chan error, 1)
	go func() { sent <- omarchyBootstrapUnlock(boot, console, passphrase) }()
	err := vm.connect(boot)
	stop()
	_ = console.SetReadDeadline(time.Now())
	if unlockErr := <-sent; err == nil && unlockErr != nil {
		return unlockErr
	}
	return err
}

// omarchyBootstrapUnlock submits the passphrase once, after the first
// completed prompt, then drains the console until ctx ends.
func omarchyBootstrapUnlock(ctx context.Context, conn net.Conn, secret string) error {
	var pending string
	sent := false
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		n, err := conn.Read(buf)
		if n > 0 && !sent {
			pending += string(buf[:n])
			if len(pending) > 8192 {
				pending = pending[len(pending)-8192:]
			}
			if omarchyBootstrapPrompt(pending) {
				if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return err
				}
				if _, err := io.WriteString(conn, secret+"\r"); err != nil {
					return errors.New("submit encrypted golden bootstrap passphrase failed")
				}
				sent = true
			}
		}
		var timeout net.Error
		if err != nil && !errors.As(err, &timeout) {
			break
		}
	}
	if !sent {
		return errors.New("encrypted golden booted without consuming its LUKS passphrase")
	}
	return nil
}

// omarchyBootstrapPrompt matches the vendor plymouth password display, which
// reads input on the prompt's own line, as well as a console prompt.
func omarchyBootstrapPrompt(text string) bool {
	text = strings.ToLower(text)
	i := strings.LastIndex(text, "a password is required to access the")
	return encryptedUnlockPrompt(text) || (i >= 0 && strings.HasSuffix(strings.TrimRight(text[i:], " "), ":"))
}

func omarchyTail(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 2048 {
		text = text[len(text)-2048:]
	}
	return text
}

func omarchyLoopbackPort() (address, port string, err error) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	address = listener.Addr().String()
	if _, port, err = net.SplitHostPort(address); err != nil {
		return "", "", errors.Join(err, listener.Close())
	}
	return address, port, listener.Close()
}

// omarchyEncryptedOptions normalizes the encrypted golden selection. The
// vendor install always includes its Hyprland desktop with SDDM autologin,
// so headless and desktop runs share one golden. The release's boot path has
// no TPM early-boot variant (registry Lab.TPM.Unsupported).
func omarchyEncryptedOptions(opts *EncryptedVMOptions, m *labv1.ImageManifest) error {
	if opts.Desktop != "" && opts.Desktop != "hyprland" {
		return errors.New("omarchy encrypted golden provides only its native hyprland desktop")
	}
	if reason := noTPMBootReason(m); opts.TPMBoot && reason != "" {
		return errors.New(reason)
	}
	opts.Desktop = "hyprland"
	return nil
}

// omarchyEncryptedInstall pins the verified ISO descriptor and builds the
// encrypted golden disk in staging/disk.qcow2 with the golden's credentials.
func omarchyEncryptedInstall(ctx context.Context, m *labv1.ImageManifest, staging string, verified *VerifiedImage, hardware VMHardwareOptions, state *encryptedGoldenState) (err error) {
	iso, err := openRegular(verified.Path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, iso.Close()) }()
	actual, err := digestInstalledImage(ctx, iso)
	if err != nil {
		return err
	}
	if actual.SHA256 != verified.SHA256 || actual.Size != verified.Size {
		return errors.New("verified omarchy installer changed before installation")
	}
	return omarchyInstallGolden(ctx, staging, "disk.qcow2", iso, verified.SHA256, hardware, omarchyGoldenSecrets{passphrase: state.Secret, loginKey: state.LoginKey, hostKey: state.HostKey, actions: omarchyActions(m)})
}

// omarchyEncryptedProbes repeats the installed-image identity probes on the
// first prompt-unlocked cold boot of the encrypted golden.
func omarchyEncryptedProbes(ctx context.Context, vm *EncryptedVM, m *labv1.ImageManifest) error {
	for _, probe := range omarchyProbes(m, true) {
		if _, err := vm.Run(ctx, "sudo -n sh -eu -c "+nativeQuote(probe.script), nil); err != nil {
			return fmt.Errorf("omarchy encrypted golden %s: %w", probe.label, err)
		}
	}
	return nil
}

// noTPMBootReason is the registry's reason a release has no TPM2-unlocking
// boot path at all, or "" when the lab can build one.
func noTPMBootReason(m *labv1.ImageManifest) string {
	if reason := platform.ForManifest(m.GetDistribution(), m.GetVersion()).Lab.TPM.Unsupported; reason != "" {
		return "TPM unattended boot unsupported: " + reason
	}
	return ""
}

// actionUnsupportedEvidence is a visible unsupported outcome with the native
// observation that establishes it, never a skipped or passed scenario.
type actionUnsupportedEvidence struct {
	Reason string        `json:"reason"`
	Boot   UnlockOutcome `json:"observed_boot"`
}
