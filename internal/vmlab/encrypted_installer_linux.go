package vmlab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
	"lindm/internal/platform"
)

// encryptedDesktopMediaEdition is the manifest edition of a vendor Ubuntu desktop
// ISO. Its installer is ubuntu-desktop-bootstrap over the subiquity autoinstall
// backend, and the installed system, GNOME included, comes from the media's
// squashfs layers rather than from packages installed over the network.
const encryptedDesktopMediaEdition = "desktop-encrypted-lab"

// encryptedMedia is the release and installer layout of one encrypted
// installer manifest.
type encryptedMedia struct {
	release *platform.Release
	// desktop selects the encryptedDesktopMediaEdition recipe.
	desktop bool
}

// encryptedInstallerMedia maps a manifest to its installer recipe layout.
func encryptedInstallerMedia(m *labv1.ImageManifest) encryptedMedia {
	return encryptedMedia{release: platform.ForManifest(m.GetDistribution(), m.GetVersion()), desktop: m.GetEdition() == encryptedDesktopMediaEdition}
}

// encryptedInstallerDracutKernels rebuilds every installed kernel's initrd at
// the Debian name GRUB loads.
const encryptedInstallerDracutKernels = `for modules in /lib/modules/*; do
    kernel=${modules##*/}
    test -f "/boot/vmlinuz-$kernel" || continue
    dracut --force "/boot/initrd.img-$kernel" "$kernel"
done
`

// encryptedInstallerRecipe produces private installer input, not a cloud disk
// conversion. Only the guest installer partitions /dev/vda. The ISO, recipe and
// resulting disk contain lab secrets and must stay in the private run directory.
func encryptedInstallerRecipe(media encryptedMedia, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey string) ([]byte, error) {
	return encryptedInstallerRecipeWithDesktop(media, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, "")
}

// encryptedInstallerRecipeWithDesktop additionally installs a real GNOME or KDE
// session. Automatic login is deliberately lab-only; SSH remains key-only.
func encryptedInstallerRecipeWithDesktop(media encryptedMedia, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop string) ([]byte, error) {
	return encryptedInstallerRecipeWithOptions(media, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop, false)
}

// encryptedInstallerRecipeWithOptions prepares TPM-capable early userspace only
// when requested. It never enrolls a TPM token: native action enrollment remains
// the subject of the lab, and the first boot still uses the LUKS passphrase.
func encryptedInstallerRecipeWithOptions(media encryptedMedia, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop string, tpmBoot bool) ([]byte, error) {
	return encryptedInstallerRecipeForMachine(media, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop, tpmBoot, "x86_64")
}

// encryptedInstallerRecipeForMachine keeps the signed vendor boot chain while
// selecting the guest's console and architecture-specific package repository.
func encryptedInstallerRecipeForMachine(media encryptedMedia, passphrase, loginPublicKey, hostPrivateKey, hostPublicKey, desktop string, tpmBoot bool, architecture string) ([]byte, error) {
	architecture, serialConsole, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	grubTerminal := "GRUB_TERMINAL=\"console serial\"\nGRUB_SERIAL_COMMAND=\"serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\"\n"
	if architecture == "aarch64" {
		grubTerminal = "GRUB_TERMINAL=\"console\"\n"
	}
	lab := media.release.Lab
	if desktop != "" && desktop != "gnome" && desktop != "kde" {
		return nil, errors.New("encrypted installer: unsupported desktop")
	}
	if media.desktop {
		if desktop != "gnome" || lab.Installer != platform.Subiquity {
			return nil, errors.New("encrypted installer: Ubuntu desktop media install their own GNOME session; desktop must be gnome")
		}
	} else if desktop != "" && len(lab.Session.Desktops[desktop]) == 0 {
		return nil, fmt.Errorf("encrypted installer: no maintained %s desktop for %s", desktop, media.release.Name)
	}
	if lab.Installer != platform.Subiquity && lab.Installer != platform.Anaconda {
		return nil, fmt.Errorf("encrypted installer: no maintained recipe for %s", media.release.Name)
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
		provision += encryptedInstallerDesktopProvision(media.release, desktop, architecture)
	}
	if lab.Installer == platform.Subiquity {
		var packages []string
		initramfsConfig := " /etc/cryptsetup-initramfs"
		if media.desktop {
			// The desktop source already carries GNOME and dracut; curtin adds
			// cryptsetup for the LUKS layout itself.
			initramfsConfig = ""
		} else {
			packages = append([]string{"cryptsetup-initramfs"}, lab.Session.Desktops[desktop]...)
		}
		provision += `install -d -m 0755 /etc/cloud/cloud.cfg.d /etc/default/grub.d` + initramfsConfig + `
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
		switch {
		case tpmBoot:
			// Keep curtin's stock initramfs tooling until its work finishes;
			// dracut Conflicts with initramfs-tools in Noble packaging. Media
			// that install dracut themselves list no TPM packages.
			provision += encryptedInstallerTPMProvision(lab.TPM.Modules)
			if len(lab.TPM.Packages) != 0 {
				provision += "DEBIAN_FRONTEND=noninteractive apt-get -y install " + strings.Join(lab.TPM.Packages, " ") + "\n"
			}
			provision += encryptedInstallerDracutKernels
		case !media.desktop:
			provision += "printf '%s\\n' 'CRYPTSETUP=y' > /etc/cryptsetup-initramfs/conf-hook\nupdate-initramfs -u -k all\n"
		}
		// Desktop media keep the installer's own dracut initramfs on the
		// passphrase path: curtin regenerates it after adding cryptsetup.
		provision += "update-grub\nsystemctl enable ssh\n"
		autoinstall := map[string]any{
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
			"user-data":     map[string]any{"ssh_deletekeys": false, "ssh_genkeytypes": []string{"ed25519"}, "ssh": map[string]bool{"emit_keys_to_console": false}},
			"late-commands": [][]string{{"curtin", "in-target", "--target=/target", "--", "/bin/sh", "-eu", "-c", provision}},
			"shutdown":      "poweroff",
		}
		if len(packages) != 0 {
			autoinstall["packages"] = packages
		}
		if media.desktop {
			autoinstall["source"] = map[string]string{"id": "ubuntu-desktop-minimal"}
		}
		config := map[string]any{"autoinstall": autoinstall}
		data, err := json.Marshal(config)
		if err != nil {
			return nil, errors.New("encrypted installer: encode autoinstall")
		}
		// JSON is a YAML subset; using its encoder makes all user input data,
		// including YAML syntax and shell metacharacters, rather than syntax.
		return append([]byte("#cloud-config\n"), data...), nil
	}
	if tpmBoot {
		provision += encryptedInstallerReleaseDNF(media.release, "lindm-tpm", architecture) + "install " + strings.Join(lab.TPM.Packages, " ") + "\n"
		provision += encryptedInstallerTPMProvision(lab.TPM.Modules)
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
	return []byte("#version=" + lab.Kickstart + "\ntext\ncdrom\nlang en_US.UTF-8\nkeyboard us\ntimezone UTC --utc\nnetwork --bootproto=dhcp --device=link --activate --onboot=yes --hostname=lindm-lab\nrootpw --lock\nuser --name=lindm-lab --groups=wheel --lock --shell=/bin/bash\nfirewall --enabled --service=ssh\nselinux --enforcing\nservices --enabled=sshd\nignoredisk --only-use=vda\nzerombr\nclearpart --all --initlabel --drives=vda\nautopart --type=lvm --encrypted --luks-version=luks2 --passphrase=" + nativeQuote(passphrase) + "\nbootloader --boot-drive=vda --append=\"console=tty0 console=" + serialConsole + "\"\npoweroff\n%packages\n@core\nopenssh-server\nsudo\ncryptsetup\ngrub2-tools\ngrubby\ndnf5\n%end\n%post --erroronfail --interpreter=/bin/sh\nset -eu\numask 077\n" + provision + "%end\n"), nil
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

// encryptedInstallerReleaseDNF installs from the release's immutable, signed
// package tree rather than Anaconda's unsigned RPM path.
func encryptedInstallerReleaseDNF(release *platform.Release, repository, architecture string) string {
	return fmt.Sprintf(`dnf5 -y --releasever=%[3]s --disable-repo='*' \
 --repofrompath=%[1]s,%[4]s \
 --enable-repo=%[1]s \
 --setopt=%[1]s.gpgcheck=1 \
 --setopt=%[1]s.gpgkey=file://%[5]s \
 `, repository, architecture, release.Version.Value, fmt.Sprintf(release.Lab.Repository, architecture), fmt.Sprintf(release.Lab.RepositoryKey, architecture))
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

func encryptedInstallerTPMProvision(dracutModules []string) string {
	modules := strings.Join(dracutModules, " ")
	return "install -d -m 0755 /etc/dracut.conf.d\n" +
		"printf '%s\\n' 'hostonly=\"no\"' 'omit_dracutmodules+=\" plymouth \"' 'add_dracutmodules+=\" " + modules + " \"' 'install_items+=\" /etc/crypttab \"' > /etc/dracut.conf.d/98-lindm-tpm.conf\n" +
		"awk " + nativeQuote(encryptedInstallerTPMCrypttabProgram) + " /etc/crypttab > /etc/crypttab.lindm\n" +
		"chmod 0600 /etc/crypttab.lindm\nmv /etc/crypttab.lindm /etc/crypttab\n"
}

func encryptedInstallerDesktopProvision(release *platform.Release, desktop, architecture string) string {
	var script strings.Builder
	session, anaconda := release.Lab.Session, release.Lab.Installer == platform.Anaconda
	if anaconda {
		// The vendor DVD authenticates the base system. DNF verifies RPM
		// signatures with the key supplied by that base.
		script.WriteString(encryptedInstallerReleaseDNF(release, "lindm-desktop", architecture))
		script.WriteString("group install " + strings.Join(session.Desktops[desktop], " ") + "\n")
	}
	if desktop == "gnome" {
		fmt.Fprintf(&script, "cat > %s <<'LINDM_GDM'\n[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=lindm-lab\nInitialSetupEnable=False\nLINDM_GDM\n", session.GDMConfig)
		script.WriteString("install -d -m 0755 /var/lib/AccountsService/users\n")
		fmt.Fprintf(&script, "cat > /var/lib/AccountsService/users/lindm-lab <<'LINDM_SESSION'\n[User]\nSystemAccount=false\nSession=%s\nXSession=%s\nLINDM_SESSION\n", session.Name, session.Name)
		fmt.Fprintf(&script, "systemctl enable --force %s.service\n", release.Desktop.DisplayManager)
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
	if anaconda {
		if desktop == "gnome" {
			script.WriteString("restorecon -RF " + path.Dir(session.GDMConfig) + " /var/lib/AccountsService\n")
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
// signed GRUB binary is replaced. Installers whose EFI FAT boot image also
// stores grub.cfg get that copy patched by mcopy in the output ISO, not a host
// mount or block device. The caller owns removal of this private run directory.
func prepareEncryptedInstallerForMachine(ctx context.Context, dir, isoPath string, installer platform.Installer, recipe []byte, architecture string) (_ string, err error) {
	input, err := openRegular(isoPath)
	if err != nil {
		return "", fmt.Errorf("encrypted installer: open verified ISO: %w", err)
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	return prepareInstallerFileForMachine(ctx, dir, input, installer, recipe, architecture)
}

// prepareInstallerFileForMachine borrows a pinned verified media descriptor.
func prepareInstallerFileForMachine(ctx context.Context, dir string, input *os.File, installer platform.Installer, recipe []byte, architecture string) (_ string, err error) {
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
	layout, ok := installer.Media()
	if !ok {
		return "", errors.New("encrypted installer: unsupported installer")
	}
	grubPath := layout.GRUB
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
	patched, err := encryptedInstallerGRUBForMachine(original, installer, architecture)
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
	if installer == platform.Subiquity {
		if err := os.WriteFile(filepath.Join(seed, "meta-data"), []byte("instance-id: lindm-encrypted-installer\n"), 0600); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(seed, layout.Seed), recipe, 0600); err != nil {
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
	boot := []string{"-boot_image", "any", "replay"}
	if layout.RedeclareEFI {
		// Optical boot needs only the El Torito entry: re-declare the
		// unchanged vendor FAT image as the UEFI entry, without the USB MBR.
		boot = []string{"-boot_image", "any", "discard", "-boot_image", "any", "system_area=/dev/zero", "-boot_image", "any", "efi_path=/boot/" + architecture + "/efi"}
	}
	args := append([]string{"-no_rc", "-abort_on", "FAILURE", "-indev", "stdio:/dev/fd/3", "-outdev", output, "-map", grubFile, grubPath, "-map", seed, "/lindm-seed"}, boot...)
	if _, err := encryptedInstallerCommand(ctx, stage, []*os.File{input}, "xorriso", append(args, "-commit", "-end")...); err != nil {
		return "", err
	}
	if layout.EFIImage {
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
		if _, err := encryptedInstallerCommand(ctx, stage, nil, "mcopy", "-o", "-i", output+"@@"+strconv.FormatInt(offset, 10), grubFile, "::"+grubPath); err != nil {
			return "", err
		}
	}
	return output, nil
}

func encryptedInstallerGRUB(original []byte, installer platform.Installer) ([]byte, error) {
	return encryptedInstallerGRUBForMachine(original, installer, "x86_64")
}

func encryptedInstallerGRUBForMachine(original []byte, installer platform.Installer, architecture string) ([]byte, error) {
	architecture, serialConsole, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	layout, ok := installer.Media()
	if !ok {
		return nil, errors.New("encrypted installer: unsupported installer")
	}
	args, defaultEntry := layout.Args+" console=tty0 console="+serialConsole, layout.Entry
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
		// openSUSE assigns menu variables without "set" and enables a
		// graphical theme that would replace the serial-capable console.
		if len(fields) == 1 {
			switch {
			case strings.HasPrefix(fields[0], "timeout="):
				lines[i] = "timeout=1"
			case strings.HasPrefix(fields[0], "default="):
				lines[i] = "default=" + defaultEntry
			case strings.HasPrefix(fields[0], "with_gfx="):
				lines[i] = "with_gfx=0"
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
		if layout.Separator {
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
	out := nativeexec.NewBuffer(maxMetadataBytes)
	env := append(os.Environ(), "TMPDIR="+dir, "HOME="+dir, "MTOOLSRC=/dev/null", "LC_ALL=C")
	// Tool diagnostics are discarded: the ISO carries keys and a passphrase.
	if err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: env, Dir: dir, Files: files, Stdout: out, Timeout: 15 * time.Minute}); err != nil {
		return nil, fmt.Errorf("encrypted installer: %s failed: %w", name, err)
	}
	if out.Truncated() {
		return nil, errors.New("encrypted installer: command output exceeded limit")
	}
	return out.Bytes(), nil
}
