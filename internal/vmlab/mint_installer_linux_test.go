//go:build linux

package vmlab

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/platform"
)

// mintTestMedia is the encrypted-installer layout of the Mint 22.3 row.
func mintTestMedia() encryptedMedia {
	return encryptedMedia{release: platform.ForManifest("linuxmint", "22.3")}
}

// mintPreseedValues maps each debconf question to its value and decodes the
// two base64 layers of ubiquity/success_command.
func mintPreseedValues(t *testing.T, recipe []byte) (values map[string]string, outer, inner string) {
	t.Helper()
	values = make(map[string]string)
	for _, line := range strings.Split(string(recipe), "\n") {
		fields := strings.SplitN(line, " ", 4)
		if len(fields) == 4 {
			if _, duplicate := values[fields[1]]; duplicate {
				t.Fatalf("duplicate preseed question %s", fields[1])
			}
			values[fields[1]] = fields[3]
		}
	}
	decode := func(command string) string {
		quoted := strings.Split(command, "'")
		if len(quoted) < 4 {
			t.Fatalf("missing quoted payload in %q", command)
		}
		payload, err := base64.StdEncoding.DecodeString(quoted[3])
		if err != nil {
			t.Fatal(err)
		}
		return string(payload)
	}
	outer = decode(values["ubiquity/success_command"])
	inner = decode(outer)
	for _, script := range []string{values["ubiquity/success_command"], outer, inner} {
		cmd := exec.Command("/bin/sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid provisioning shell: %v: %s", err, output)
		}
	}
	return values, outer, inner
}

func TestMintPreseedBindsUnencryptedTargetAndCredentials(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	digest := strings.Repeat("a", 64)
	recipe, err := mintInstallerRecipe("/dev/vda", "x86_64", digest, login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	values, outer, inner := mintPreseedValues(t, recipe)
	for name, want := range map[string]string{
		"partman-auto/method": "regular", "partman-auto/disk": "/dev/vda", "grub-installer/bootdev": "/dev/vda",
		"passwd/username": "lindm-lab", "time/zone": "Etc/UTC",
		"ubiquity/reboot": "true", "ubiquity/download_updates": "false",
	} {
		if values[name] != want {
			t.Fatalf("preseed %s=%q, want %q", name, values[name], want)
		}
	}
	if _, ok := values["partman-crypto/passphrase"]; ok {
		t.Fatal("unencrypted install carries a LUKS passphrase")
	}
	password := values["passwd/user-password"]
	if len(password) < 26 || password != values["passwd/user-password-again"] {
		t.Fatal("Ubiquity user page lacks a random matching password")
	}
	for _, want := range []string{"mount --bind", "chroot /target /bin/sh -eu /root/lindm-provision", "umount -l"} {
		if !strings.Contains(outer, want) {
			t.Fatalf("live-system wrapper lost %q", want)
		}
	}
	for _, want := range []string{
		"apt-get -y install openssh-server cloud-init", base64.StdEncoding.EncodeToString([]byte(login)),
		base64.StdEncoding.EncodeToString([]byte(private)), base64.StdEncoding.EncodeToString([]byte(public)),
		"datasource_list: [ NoCloud ]", "console=ttyS0", digest + "' > " + installerSourceMarkerPath, "cloud-init clean",
		"update-grub", "systemctl enable ssh", "passwd -l lindm-lab",
	} {
		if !strings.Contains(inner, want) {
			t.Fatalf("installed provisioning lost %q", want)
		}
	}
	// The SSH credential writer leaves umask 077. An emptied machine-id
	// created under it stays mode 0600 and breaks D-Bus activation for every
	// non-root reader on first boot; the marker alone must remain root-only.
	reset, machineID := strings.Index(inner, "umask 022\n"), strings.Index(inner, "touch /etc/machine-id")
	if reset < strings.Index(inner, "umask 077") || machineID < reset || !strings.Contains(inner, "(umask 077 && printf") {
		t.Fatal("installed system files inherit the credential umask")
	}
	if strings.Contains(inner, password) || strings.Contains(outer, password) {
		t.Fatal("installer password leaked into installed provisioning")
	}
	again, err := mintInstallerRecipe("/dev/vda", "x86_64", digest, login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if again2, _, _ := mintPreseedValues(t, again); again2["passwd/user-password"] == password {
		t.Fatal("installer password is not fresh per build")
	}
}

func TestMintPreseedRejectsWrongAuthorityAndTarget(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	digest := strings.Repeat("a", 64)
	for _, test := range []struct{ disk, arch, digest, login, private, public string }{
		{"/dev/host", "x86_64", digest, login, private, public},
		{"/dev/vda", "aarch64", digest, login, private, public},
		{"/dev/vda", "x86_64", "';false", login, private, public},
		{"/dev/vda", "x86_64", digest, "invalid", private, public},
		{"/dev/vda", "x86_64", digest, login, private, login},
	} {
		if _, err := mintInstallerRecipe(test.disk, test.arch, test.digest, test.login, test.private, test.public); err == nil {
			t.Fatalf("invalid installer authority/target accepted: %+v", test)
		}
	}
}

func TestMintEncryptedRecipe(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, tpmBoot := range []bool{false, true} {
		recipe, err := encryptedInstallerRecipeForMachine(mintTestMedia(), "lab-passphrase", login, private, public, "cinnamon", tpmBoot, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		values, _, inner := mintPreseedValues(t, recipe)
		for name, want := range map[string]string{
			"partman-auto/method": "crypto", "partman-auto/disk": "/dev/vda", "partman-crypto/passphrase": "lab-passphrase",
			"partman-crypto/passphrase-again": "lab-passphrase", "partman-auto-lvm/guided_size": "max", "ubiquity/reboot": "true",
		} {
			if values[name] != want {
				t.Fatalf("tpm=%t preseed %s=%q, want %q", tpmBoot, name, values[name], want)
			}
		}
		for _, want := range []string{
			"autologin-user=lindm-lab", "autologin-session=cinnamon", "console=ttyS0,115200n8", "GRUB_CMDLINE_LINUX_DEFAULT=\"\"",
			"GRUB_TERMINAL=\"console serial\"", "ssh_host_ed25519_key", "systemctl enable ssh", "passwd -l lindm-lab",
		} {
			if !strings.Contains(inner, want) {
				t.Fatalf("tpm=%t provisioning lost %q", tpmBoot, want)
			}
		}
		if strings.Contains(inner, "cloud-init") {
			t.Fatal("encrypted golden must keep its baked SSH identity, not cloud-init")
		}
		if tpmBoot != strings.Contains(inner, "dracut --force") || tpmBoot != strings.Contains(inner, "tpm2-device=auto") || tpmBoot == strings.Contains(inner, "CRYPTSETUP=y") {
			t.Fatalf("tpm=%t selected the wrong early-boot stack", tpmBoot)
		}
	}
	for _, test := range []struct{ desktop, passphrase, arch string }{
		{"", "lab-passphrase", "x86_64"},
		{"gnome", "lab-passphrase", "x86_64"},
		{"cinnamon", "lab passphrase", "x86_64"},
		{"cinnamon", "lab-passphrase", "aarch64"},
	} {
		if _, err := encryptedInstallerRecipeForMachine(mintTestMedia(), test.passphrase, login, private, public, test.desktop, false, test.arch); err == nil {
			t.Fatalf("invalid Mint encrypted recipe accepted: %+v", test)
		}
	}
	if _, err := encryptedInstallerRecipeForMachine(labMedia("ubuntu"), "lab-passphrase", login, private, public, "cinnamon", false, "x86_64"); err == nil {
		t.Fatal("Cinnamon accepted for a non-Mint installer")
	}
}

// The vendor Mint 22.3 Cinnamon /boot/grub/grub.cfg, abridged.
const mintVendorGRUB = `loadfont unicode

menuentry "Start Linux Mint 22.3 Cinnamon 64-bit" --class linuxmint {
	set gfxpayload=keep
	linux	/casper/vmlinuz  boot=casper uuid=6e72f523-dc09-4880-8910-93ffa64401c5 username=mint hostname=mint iso-scan/filename=${iso_path} quiet splash --
	initrd	/casper/initrd.lz
}
if [ "$grub_platform" = "efi" ]; then
menuentry 'UEFI Firmware Settings' {
	fwsetup
}
fi
`

func TestMintGRUBPreservesVendorKernelAndInitrd(t *testing.T) {
	patched, err := encryptedInstallerGRUBForMachine([]byte(mintVendorGRUB), platform.Ubiquity, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	text := string(patched)
	for _, want := range []string{
		"linux /casper/vmlinuz boot=casper uuid=6e72f523-dc09-4880-8910-93ffa64401c5 username=mint hostname=mint iso-scan/filename=${iso_path} noninteractive noprompt file=/cdrom/lindm-seed/preseed.cfg console=tty0 console=ttyS0,115200n8\n",
		"initrd\t/casper/initrd.lz", "set default=0", "set timeout=1", "terminal_output console serial",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("installer lost vendor payload or seed argument %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{" quiet", " splash", " -- ", " --\n"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("patched boot configuration retained %q", unwanted)
		}
	}
}

func TestMintManifestsSelectOnlyTheirLane(t *testing.T) {
	plain, err := LoadManifest("../../lab/images/linuxmint-22.3-cinnamon-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := LoadManifest("../../lab/images/linuxmint-22.3-cinnamon-encrypted-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{plain.GetSha256(), encrypted.GetSha256()} {
		if m != "a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4" {
			t.Fatal("Mint manifests pin different media")
		}
	}
	spec, err := installerImageFor(plain)
	if err != nil || spec == nil || spec.installer != platform.Ubiquity || !spec.exitOnReboot || spec.version != mintInstallerRecipeVersion {
		t.Fatalf("unencrypted Mint manifest did not select the Ubiquity installer: %+v %v", spec, err)
	}
	labels := make(map[string]bool)
	for _, probe := range spec.probes {
		labels[probe.label] = true
	}
	for _, want := range []string{"distribution", "version", "source_marker", "root_filesystem", "package_tool", "privilege_tool"} {
		if !labels[want] {
			t.Fatalf("first-boot validation lacks %s", want)
		}
	}
	if spec, err := installerImageFor(encrypted); err == nil || spec != nil {
		t.Fatal("encrypted-lab Mint manifest was admitted as an unencrypted cloud or installer disk")
	}
	if _, err := mintManifest(encrypted, mintEncryptedInstallerEdition); err != nil {
		t.Fatal(err)
	}
	if _, err := mintManifest(plain, mintEncryptedInstallerEdition); err == nil {
		t.Fatal("encrypted lane admits the wrong Mint edition")
	}
}

// Derivative rows run their base release's branch of a lab guest script's
// os-release switch; releases without a base keep their own identity, and an
// unknown release is refused rather than guessed from ID_LIKE.
func TestNativeScriptIdentitySelectsRegistryBase(t *testing.T) {
	for _, test := range []struct{ id, version, want string }{
		{"linuxmint", "22.3", "LINDM_NATIVE_ID='ubuntu'\nLINDM_NATIVE_VERSION='24.04'\n"},
		{"pop", "24.04", "LINDM_NATIVE_ID='ubuntu'\nLINDM_NATIVE_VERSION='24.04'\n"},
		{"ubuntu", "24.04", ""},
		{"fedora", "44", ""},
	} {
		identity, err := nativeScriptIdentity(platform.ForManifest(test.id, test.version))
		if err != nil || identity != test.want {
			t.Fatalf("%s %s identity %q, %v", test.id, test.version, identity, err)
		}
		osRelease := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(osRelease, []byte("ID="+test.id+"\nVERSION_ID="+test.version+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		script := identity + strings.Replace(nativeOSRelease, "/etc/os-release", osRelease, 1) + "\nprintf '%s:%s' \"$ID\" \"$VERSION_ID\""
		output, err := exec.Command("/bin/sh", "-eu", "-c", script).Output()
		want := test.id + ":" + test.version
		if test.want != "" {
			want = "ubuntu:24.04"
		}
		if err != nil || string(output) != want {
			t.Fatalf("%s %s script identity %q, %v", test.id, test.version, output, err)
		}
	}
	for _, release := range []*platform.Release{nil, platform.ForManifest("linuxmint", "21.3")} {
		if _, err := nativeScriptIdentity(release); err == nil {
			t.Fatal("unknown release received a native script identity")
		}
	}
	if !strings.HasPrefix(nativeOSRelease, ". /etc/os-release\n") {
		t.Fatal("native identity must apply after the guest's own os-release")
	}
}

// A derivative recovers from its base release's cloud image; release
// mismatches and unknown releases are refused before any guest starts.
func TestRecoveryReleaseMatchesNativeBase(t *testing.T) {
	ubuntu := platform.ForManifest("ubuntu", "24.04")
	for _, target := range []*platform.Release{platform.ForManifest("linuxmint", "22.3"), ubuntu} {
		if err := recoveryReleaseMatches(target, ubuntu); err != nil {
			t.Fatalf("%s: %v", target.Name, err)
		}
	}
	for _, pair := range [][2]*platform.Release{
		{platform.ForManifest("linuxmint", "22.3"), platform.ForManifest("ubuntu", "26.04")},
		{platform.ForManifest("fedora", "44"), ubuntu},
		{platform.ForManifest("linuxmint", "21.3"), ubuntu},
	} {
		if err := recoveryReleaseMatches(pair[0], pair[1]); err == nil {
			t.Fatalf("%s recovered from %s", pair[0].Name, pair[1].Name)
		}
	}
}
