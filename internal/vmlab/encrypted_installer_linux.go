package vmlab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// encryptedInstallerRecipe produces private installer input, not a cloud disk
// conversion. Only the guest installer partitions /dev/vda. The ISO, recipe and
// resulting disk contain lab secrets and must stay in the private run directory.
func encryptedInstallerRecipe(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey string) ([]byte, error) {
	return encryptedInstallerRecipeWithDesktop(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, "")
}

// encryptedInstallerRecipeWithDesktop additionally installs a real GNOME or KDE
// session. Automatic login is deliberately lab-only; SSH remains key-only.
func encryptedInstallerRecipeWithDesktop(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop string) ([]byte, error) {
	return encryptedInstallerRecipeWithOptions(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop, false)
}

// encryptedInstallerRecipeWithOptions prepares TPM-capable early userspace only
// when requested. It never enrolls a TPM token: native action enrollment remains
// the subject of the lab, and the first boot still uses the LUKS passphrase.
func encryptedInstallerRecipeWithOptions(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop string, tpmBoot bool) ([]byte, error) {
	return encryptedInstallerRecipeForMachine(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop, tpmBoot, "x86_64")
}

// encryptedInstallerRecipeForMachine keeps the signed vendor boot chain while
// selecting the guest's console and architecture-specific package repository.
func encryptedInstallerRecipeForMachine(distribution, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop string, tpmBoot bool, architecture string) ([]byte, error) {
	architecture, serialConsole, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	grubTerminal := "GRUB_TERMINAL=\"console serial\"\nGRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\"\n"
	if architecture == "aarch64" {
		grubTerminal = "GRUB_TERMINAL=\"console\"\n"
	}
	if desktop != "" && desktop != "gnome" && desktop != "kde" {
		return nil, errors.New("encrypted installer: unsupported desktop")
	}
	if distribution != "ubuntu" && distribution != "fedora" {
		return nil, errors.New("encrypted installer: unsupported distribution")
	}
	// Serial unlock is line-oriented. Exclude control characters rather than
	// allowing a passphrase which cannot be entered through the runtime console.
	if passphrase == "" || len(passphrase) > 4096 {
		return nil, errors.New("encrypted installer: invalid passphrase")
	}
	for _, c := range []byte(passphrase) {
		if c < 32 || c > 126 {
			return nil, errors.New("encrypted installer: passphrase must be printable ASCII")
		}
	}
	login, err := encryptedInstallerPublicKey(loginPublicKey)
	if err != nil {
		return nil, err
	}
	host, err := encryptedInstallerPublicKey(hostPublicKey)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(hostPrivateKey))
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 || !bytes.Equal(ssh.MarshalAuthorizedKey(signer.PublicKey()), []byte(host)) {
		return nil, errors.New("encrypted installer: host key must be a matching Ed25519 pair")
	}
	provision := encryptedInstallerProvision(login, hostPrivateKey, host)
	if desktop != "" {
		provision += encryptedInstallerDesktopProvision(distribution, desktop, architecture)
	}
	if distribution == "ubuntu" {
		packages := []string{"cryptsetup-initramfs"}
		switch desktop {
		case "gnome":
			packages = append(packages, "ubuntu-desktop-minimal")
		case "kde":
			packages = append(packages, "kubuntu-desktop")
		}
		provision += `install -d -m 0755 /etc/cloud/cloud.cfg.d /etc/default/grub.d /etc/cryptsetup-initramfs
cat > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg <<'LINDM_CLOUD'
ssh_deletekeys: false
ssh_genkeytypes: [ed25519]
ssh:
  emit_keys_to_console: false
LINDM_CLOUD
cat > /etc/default/grub.d/99-lindm-lab.cfg <<'LINDM_GRUB'
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX="console=tty0 console=` + serialConsole + `"
` + grubTerminal + `GRUB_TIMEOUT=1
LINDM_GRUB
`
		if tpmBoot {
			// Keep curtin's stock initramfs tooling until its work finishes;
			// dracut Conflicts with initramfs-tools in Noble packaging.
			provision += encryptedInstallerTPMProvision(distribution)
			provision += `DEBIAN_FRONTEND=noninteractive apt-get -y install dracut systemd tpm2-tools libtss2-tcti-device0t64 cryptsetup-initramfs-
for modules in /lib/modules/*; do
    kernel=${modules##*/}
    test -f "/boot/vmlinuz-$kernel" || continue
    dracut --force "/boot/initrd.img-$kernel" "$kernel"
done
`
		} else {
			provision += "printf '%s\\n' 'CRYPTSETUP=y' > /etc/cryptsetup-initramfs/conf-hook\nupdate-initramfs -u -k all\n"
		}
		provision += "update-grub\nsystemctl enable ssh\n"
		config := map[string]any{"autoinstall": map[string]any{
			"version":           1,
			"refresh-installer": map[string]bool{"update": false},
			"locale":            "en_US.UTF-8",
			"keyboard":          map[string]string{"layout": "us"},
			"identity":          map[string]string{"hostname": "lindm-lab", "username": "lindm-lab", "password": "!"},
			"storage": map[string]any{"layout": map[string]any{
				"name": "lvm", "password": passphrase, "sizing-policy": "all",
				"match": map[string]string{"path": "/dev/vda"},
			}},
			"ssh":           map[string]any{"install-server": true, "allow-pw": false, "authorized-keys": []string{strings.TrimSpace(login)}},
			"packages":      packages,
			"user-data":     map[string]any{"ssh_deletekeys": false, "ssh_genkeytypes": []string{"ed25519"}, "ssh": map[string]bool{"emit_keys_to_console": false}},
			"late-commands": [][]string{{"curtin", "in-target", "--target=/target", "--", "/bin/sh", "-eu", "-c", provision}},
			"shutdown":      "poweroff",
		}}
		data, err := json.Marshal(config)
		if err != nil {
			return nil, errors.New("encrypted installer: encode autoinstall")
		}
		// JSON is a YAML subset; using its encoder makes all user input data,
		// including YAML syntax and shell metacharacters, rather than syntax.
		return append([]byte("#cloud-config\n"), data...), nil
	}
	if tpmBoot {
		provision += encryptedInstallerFedoraDNF("lindm-tpm", architecture) + "install systemd-udev tpm2-tools tpm2-tss\n"
		provision += encryptedInstallerTPMProvision(distribution)
	}
	provision += `install -d -m 0755 /etc/dracut.conf.d
printf '%s\n' 'omit_dracutmodules+=" plymouth "' 'hostonly="no"' > /etc/dracut.conf.d/99-lindm-lab.conf
grubby --update-kernel=ALL --remove-args="rhgb quiet" --args="console=tty0 console=` + serialConsole + `"
cat >> /etc/default/grub <<'LINDM_GRUB'
` + grubTerminal + `GRUB_TIMEOUT=1
LINDM_GRUB
grub2-mkconfig -o /boot/grub2/grub.cfg
dracut --regenerate-all --force
restorecon -RF /home/lindm-lab/.ssh /etc/ssh /etc/sudoers.d
systemctl enable sshd
`
	return []byte("#version=F44\ntext\ncdrom\nlang en_US.UTF-8\nkeyboard us\ntimezone UTC --utc\nnetwork --bootproto=dhcp --device=link --activate --onboot=yes --hostname=lindm-lab\nrootpw --lock\nuser --name=lindm-lab --groups=wheel --lock --shell=/bin/bash\nfirewall --enabled --service=ssh\nselinux --enforcing\nservices --enabled=sshd\nignoredisk --only-use=vda\nzerombr\nclearpart --all --initlabel --drives=vda\nautopart --type=lvm --encrypted --luks-version=luks2 --passphrase=" + nativeQuote(passphrase) + "\nbootloader --boot-drive=vda --append=\"console=tty0 console=" + serialConsole + "\"\npoweroff\n%packages\n@core\nopenssh-server\nsudo\ncryptsetup\ngrub2-tools\ngrubby\ndnf5\n%end\n%post --erroronfail --interpreter=/bin/sh\nset -eu\numask 077\n" + provision + "%end\n"), nil
}

func encryptedInstallerArchitecture(architecture string) (canonical, console string, err error) {
	switch architecture {
	case "amd64", "x86_64":
		return "x86_64", "ttyS0,115200n8", nil
	case "arm64", "aarch64":
		return "aarch64", "ttyAMA0,115200", nil
	default:
		return "", "", errors.New("encrypted installer: unsupported architecture")
	}
}

func encryptedInstallerFedoraDNF(repository, architecture string) string {
	return fmt.Sprintf(`dnf5 -y --releasever=44 --disable-repo='*' \
 --repofrompath=%[1]s,https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/%[2]s/os/ \
 --enable-repo=%[1]s \
 --setopt=%[1]s.gpgcheck=1 \
 --setopt=%[1]s.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-%[2]s \
 `, repository, architecture)
}

// The native installers already name their LUKS mappings by UUID. Preserve those
// identities and unrelated options, removing only the initramfs-tools-only flag.
// This transformation does not change a LUKS keyslot or token.
const encryptedInstallerTPMCrypttabProgram = `
/^[[:space:]]*(#|$)/ { print; next }
NF < 2 || NF > 4 || $2 !~ /^UUID=/ { exit 1 }
{
    if (NF < 3) $3 = "none"
    n = split($4, options, ",")
    kept = ""
    for (i = 1; i <= n; i++) {
        if (options[i] == "" || options[i] == "initramfs" || options[i] ~ /^tpm2-device=/) continue
        kept = kept options[i] ","
    }
    $4 = kept "tpm2-device=auto"
    print
    found++
}
END { if (!found) exit 1 }
`

func encryptedInstallerTPMProvision(distribution string) string {
	modules := "systemd crypt tpm2-tss lvm"
	if distribution == "fedora" {
		// Fedora's dracut 108 splits this out of the crypt module; Noble's
		// dracut 060 still installs systemd-cryptsetup from crypt itself.
		modules += " systemd-cryptsetup"
	}
	return "install -d -m 0755 /etc/dracut.conf.d\n" +
		"printf '%s\\n' 'hostonly=\"no\"' 'omit_dracutmodules+=\" plymouth \"' 'add_dracutmodules+=\" " + modules + " \"' 'install_items+=\" /etc/crypttab \"' > /etc/dracut.conf.d/98-lindm-tpm.conf\n" +
		"awk " + nativeQuote(encryptedInstallerTPMCrypttabProgram) + " /etc/crypttab > /etc/crypttab.lindm\n" +
		"chmod 0600 /etc/crypttab.lindm\nmv /etc/crypttab.lindm /etc/crypttab\n"
}

func encryptedInstallerDesktopProvision(distribution, desktop, architecture string) string {
	var script strings.Builder
	if distribution == "fedora" {
		// The vendor DVD authenticates the base system. Desktop packages come
		// from the immutable release tree, not Anaconda's unsigned RPM path.
		// DNF verifies RPM signatures with the key supplied by that base.
		script.WriteString(encryptedInstallerFedoraDNF("lindm-desktop", architecture))
		script.WriteString("group install base-graphical desktop-accessibility fonts guest-desktop-agents hardware-support input-methods networkmanager-submodules ")
		if desktop == "gnome" {
			script.WriteString("gnome-desktop\n")
		} else {
			script.WriteString("kde-desktop\n")
		}
	}
	if desktop == "gnome" {
		config, service, session := "/etc/gdm/custom.conf", "gdm", "gnome"
		if distribution == "ubuntu" {
			config, service, session = "/etc/gdm3/custom.conf", "gdm3", "ubuntu"
		}
		fmt.Fprintf(&script, "cat > %s <<'LINDM_GDM'\n[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=lindm-lab\nInitialSetupEnable=False\nLINDM_GDM\n", config)
		script.WriteString("install -d -m 0755 /var/lib/AccountsService/users\n")
		fmt.Fprintf(&script, "cat > /var/lib/AccountsService/users/lindm-lab <<'LINDM_SESSION'\n[User]\nSystemAccount=false\nSession=%s\nXSession=%s\nLINDM_SESSION\n", session, session)
		fmt.Fprintf(&script, "systemctl enable --force %s.service\n", service)
	} else {
		script.WriteString(`install -d -m 0755 /etc/sddm.conf.d
cat > /etc/sddm.conf.d/99-lindm-lab.conf <<'LINDM_SDDM'
[Autologin]
User=lindm-lab
Session=plasma.desktop
Relogin=false
LINDM_SDDM
systemctl enable --force sddm.service
`)
	}
	if distribution == "fedora" {
		if desktop == "gnome" {
			script.WriteString("restorecon -RF /etc/gdm /var/lib/AccountsService\n")
		} else {
			script.WriteString("restorecon -RF /etc/sddm.conf.d\n")
		}
	}
	script.WriteString("systemctl set-default graphical.target\n")
	return script.String()
}

func encryptedInstallerPublicKey(value string) (string, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("encrypted installer: expected one SSH public key without options")
	}
	return string(ssh.MarshalAuthorizedKey(key)), nil
}

func encryptedInstallerProvision(login, hostPrivate, hostPublic string) string {
	var script strings.Builder
	script.WriteString("umask 077\ninstall -d -m 0700 /home/lindm-lab/.ssh\ninstall -d -m 0755 /etc/ssh/sshd_config.d /etc/sudoers.d\n")
	for _, file := range []struct{ path, data string }{
		{"/home/lindm-lab/.ssh/authorized_keys", login},
		{"/etc/ssh/ssh_host_ed25519_key", hostPrivate},
		{"/etc/ssh/ssh_host_ed25519_key.pub", hostPublic},
		{"/etc/ssh/sshd_config.d/00-lindm-lab.conf", "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nHostKey /etc/ssh/ssh_host_ed25519_key\n"},
		{"/etc/sudoers.d/lindm-lab", "lindm-lab ALL=(ALL) NOPASSWD:ALL\n"},
	} {
		fmt.Fprintf(&script, "printf '%%s' '%s' | base64 -d > %s\n", base64.StdEncoding.EncodeToString([]byte(file.data)), file.path)
	}
	script.WriteString("chmod 0600 /etc/ssh/ssh_host_ed25519_key /home/lindm-lab/.ssh/authorized_keys\nchmod 0440 /etc/sudoers.d/lindm-lab\nchown -R lindm-lab:lindm-lab /home/lindm-lab/.ssh\n")
	return script.String()
}

// prepareEncryptedInstallerForMachine remasters a Fetcher-verified vendor ISO.
// xorriso replays the original El Torito/GPT boot equipment; no kernel, shim or
// signed GRUB binary is replaced. Fedora also stores grub.cfg inside its EFI FAT
// boot image, so mcopy patches that configuration in the output ISO, not a host
// mount or block device. The caller owns removal of this private run directory.
func prepareEncryptedInstallerForMachine(ctx context.Context, dir, isoPath, distribution string, recipe []byte, architecture string) (_ string, err error) {
	input, err := openRegular(isoPath)
	if err != nil {
		return "", fmt.Errorf("encrypted installer: open verified ISO: %w", err)
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	return prepareInstallerFileForMachine(ctx, dir, input, distribution, recipe, architecture)
}

// prepareInstallerFileForMachine borrows a pinned verified media descriptor.
func prepareInstallerFileForMachine(ctx context.Context, dir string, input *os.File, distribution string, recipe []byte, architecture string) (_ string, err error) {
	if input == nil {
		return "", errors.New("installer media descriptor is required")
	}
	media, err := input.Stat()
	if err != nil || !media.Mode().IsRegular() {
		return "", errors.New("installer media must be a regular file")
	}
	architecture, _, err = encryptedInstallerArchitecture(architecture)
	if err != nil {
		return "", err
	}
	grubPath := "/boot/grub/grub.cfg"
	if distribution == "fedora" {
		grubPath = "/EFI/BOOT/grub.cfg"
	} else if distribution != "ubuntu" && distribution != "debian" {
		return "", errors.New("encrypted installer: unsupported distribution")
	}
	if len(recipe) == 0 || len(recipe) > maxMetadataBytes {
		return "", errors.New("encrypted installer: invalid recipe size")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("encrypted installer: existing private run directory required")
	}
	stage, err := os.MkdirTemp(dir, "installer-")
	if err != nil {
		return "", err
	}
	// Keep all secret staging inside the caller-owned run, including on failure.
	grubFile := filepath.Join(stage, "grub.cfg")
	if _, err := encryptedInstallerCommand(ctx, stage, []*os.File{input}, "xorriso", "-no_rc", "-abort_on", "FAILURE", "-osirrox", "on", "-indev", "stdio:/dev/fd/3", "-extract", grubPath, grubFile); err != nil {
		return "", err
	}
	original, err := readRegular(grubFile, maxMetadataBytes)
	if err != nil {
		return "", err
	}
	patched, err := encryptedInstallerGRUBForMachine(original, distribution, architecture)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(grubFile, 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(grubFile, patched, 0600); err != nil {
		return "", err
	}
	seed := filepath.Join(stage, "seed")
	if err := os.Mkdir(seed, 0700); err != nil {
		return "", err
	}
	recipeFile := "ks.cfg"
	if distribution == "ubuntu" {
		recipeFile = "user-data"
		if err := os.WriteFile(filepath.Join(seed, "meta-data"), []byte("instance-id: lindm-encrypted-installer\n"), 0600); err != nil {
			return "", err
		}
	}
	if distribution == "debian" {
		recipeFile = "preseed.cfg"
	}
	if err := os.WriteFile(filepath.Join(seed, recipeFile), recipe, 0600); err != nil {
		return "", err
	}
	output := filepath.Join(stage, "installer.iso")
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if _, err := encryptedInstallerCommand(ctx, stage, []*os.File{input}, "xorriso", "-no_rc", "-abort_on", "FAILURE", "-indev", "stdio:/dev/fd/3", "-outdev", output, "-map", grubFile, grubPath, "-map", seed, "/lindm-seed", "-boot_image", "any", "replay", "-commit", "-end"); err != nil {
		return "", err
	}
	if distribution == "fedora" {
		report, err := encryptedInstallerCommand(ctx, stage, nil, "xorriso", "-no_rc", "-abort_on", "FAILURE", "-indev", output, "-report_el_torito", "plain")
		if err != nil {
			return "", err
		}
		offset, err := encryptedInstallerEFIOffset(report)
		if err != nil {
			return "", err
		}
		// mtools accesses a regular image at a byte offset. It never opens the
		// host's EFI system partition, mounts a filesystem, or rewrites a PE.
		if _, err := encryptedInstallerCommand(ctx, stage, nil, "mcopy", "-o", "-i", output+"@@"+strconv.FormatInt(offset, 10), grubFile, "::/EFI/BOOT/grub.cfg"); err != nil {
			return "", err
		}
	}
	return output, nil
}

func encryptedInstallerGRUB(original []byte, distribution string) ([]byte, error) {
	return encryptedInstallerGRUBForMachine(original, distribution, "x86_64")
}

func encryptedInstallerGRUBForMachine(original []byte, distribution, architecture string) ([]byte, error) {
	architecture, serialConsole, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	var args string
	defaultEntry := "0"
	switch distribution {
	case "ubuntu":
		args = "autoinstall noprompt ds=nocloud\\;s=/cdrom/lindm-seed/ console=tty0 console=" + serialConsole
	case "fedora":
		args = "inst.ks=cdrom:/lindm-seed/ks.cfg inst.text console=tty0 console=" + serialConsole
	case "debian":
		args = "auto=true priority=critical preseed/file=/cdrom/lindm-seed/preseed.cfg DEBIAN_FRONTEND=text net.ifnames=0 biosdevname=0 console=tty0 console=" + serialConsole
		// Debian's first entry uses the graphical initrd. Select the vendor's
		// text installer by title rather than replacing its kernel or initrd.
		defaultEntry = "'Install'"
	default:
		return nil, errors.New("encrypted installer: unsupported distribution")
	}
	lines := strings.Split(string(original), "\n")
	kernels := 0
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if architecture == "aarch64" {
			switch fields[0] {
			case "serial", "terminal_input":
				lines[i] = "terminal_input console"
				continue
			case "terminal_output":
				lines[i] = "terminal_output console"
				continue
			}
		}
		if fields[0] == "set" && len(fields) == 2 {
			if strings.HasPrefix(fields[1], "timeout=") {
				lines[i] = "set timeout=1"
			} else if strings.HasPrefix(fields[1], "default=") {
				lines[i] = "set default=" + defaultEntry
			}
		}
		if fields[0] != "linux" && fields[0] != "linuxefi" {
			continue
		}
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "/") {
			return nil, errors.New("encrypted installer: unexpected vendor kernel command")
		}
		kept := fields[:2]
		for _, field := range fields[2:] {
			if field != "quiet" && field != "splash" && field != "rhgb" && field != "rd.live.check" && field != "---" && !strings.HasPrefix(field, "console=") {
				kept = append(kept, field)
			}
		}
		lines[i] = strings.Join(kept, " ") + " " + args
		if distribution == "ubuntu" || distribution == "debian" {
			lines[i] += " ---"
		}
		kernels++
	}
	if kernels == 0 {
		return nil, errors.New("encrypted installer: vendor GRUB configuration has no kernel entries")
	}
	terminal := "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\nterminal_input console serial\nterminal_output console serial\n"
	if architecture == "aarch64" {
		// AAVMF exposes its PL011 UART through the EFI console. GRUB's x86
		// serial --unit ports are not the ARM ttyAMA device.
		terminal = "terminal_input console\nterminal_output console\n"
	}
	return []byte(terminal + "set default=" + defaultEntry + "\nset timeout=1\n" + strings.Join(lines, "\n")), nil
}

func encryptedInstallerEFIOffset(report []byte) (int64, error) {
	var offset int64
	for _, line := range strings.Split(string(report), "\n") {
		prefix, values, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(prefix) != "El Torito boot img" {
			continue
		}
		fields := strings.Fields(values)
		if len(fields) != 8 || fields[1] != "UEFI" || fields[2] != "y" {
			continue
		}
		lba, err := strconv.ParseInt(fields[7], 10, 64)
		if err != nil || lba <= 0 || lba > (16<<30)/2048 || offset != 0 {
			return 0, errors.New("encrypted installer: invalid or ambiguous EFI boot image")
		}
		offset = lba * 2048
	}
	if offset == 0 {
		return 0, errors.New("encrypted installer: EFI boot image is missing")
	}
	return offset, nil
}

func encryptedInstallerCommand(ctx context.Context, dir string, files []*os.File, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TMPDIR="+dir, "HOME="+dir, "MTOOLSRC=/dev/null", "LC_ALL=C")
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	cmd.WaitDelay = 2 * time.Second
	out := &limitedOutput{limit: maxMetadataBytes}
	cmd.Stdout = out
	cmd.Stderr = new(vmLog)
	if err := cmd.Run(); err != nil {
		// Do not include tool diagnostics: the ISO carries keys and a passphrase.
		return nil, fmt.Errorf("encrypted installer: %s failed: %w", name, err)
	}
	if out.exceeded {
		return nil, errors.New("encrypted installer: command output exceeded limit")
	}
	return out.data, nil
}
