//go:build linux

package vmlab

import (
	"encoding/base64"
	"encoding/xml"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// Prevent encrypted media from falling back to YaST's unencrypted guided disk
// proposal or a traditional GRUB topology that cannot consume the LUKS2 root.
func TestTumbleweedEncryptedProfileKeepsLUKS2AndVendorBLS(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, arch := range []string{"x86_64", "aarch64"} {
		version := tumbleweedInstallerTestVersion(arch)
		recipe, err := tumbleweedInstallerRecipeWithEncryption(platform.ForManifest("opensuse-tumbleweed", version), version, "/dev/vda", arch, strings.Repeat("a", 64), login, private, public, "a<&\"secret", "gnome", true, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository, CAPEM: []byte("test-only CA")})
		if err != nil {
			t.Fatal(err)
		}
		var profile struct {
			Loader     string `xml:"bootloader>loader_type"`
			Partitions []struct {
				Mount  string `xml:"mount"`
				Method string `xml:"crypt_method"`
				Key    string `xml:"crypt_key"`
			} `xml:"partitioning>drive>partitions>partition"`
		}
		if err := xml.Unmarshal(recipe, &profile); err != nil {
			t.Fatal(err)
		}
		if profile.Loader != "grub2-bls" || len(profile.Partitions) != 3 {
			t.Fatalf("wrong vendor topology: %+v", profile)
		}
		root := profile.Partitions[2]
		if root.Mount != "/" || root.Method != "luks2" || root.Key != "a<&\"secret" {
			t.Fatalf("encrypted root lost owner key or type: %+v", root)
		}
		for _, partition := range profile.Partitions[:2] {
			if partition.Method != "" || partition.Key != "" {
				t.Fatal("GRUB boot assets unexpectedly encrypted")
			}
		}
		// Regression: with fresh firmware variables YaST's grub2-bls timeout
		// was lost and the first boot waited at the GRUB menu indefinitely.
		var scripts autoyastProfile
		if err := xml.Unmarshal(recipe, &scripts); err != nil {
			t.Fatal(err)
		}
		if len(scripts.Scripts) != 1 {
			t.Fatal("missing installed-system provisioning")
		}
		fields := strings.Split(scripts.Scripts[0].Source, "'")
		if len(fields) < 4 {
			t.Fatal("missing provisioning payload")
		}
		payload, err := base64.StdEncoding.DecodeString(fields[3])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(payload), grubEnvSetScript("/boot/efi/EFI/opensuse/grubenv", "timeout", "1")) {
			t.Fatal("grub2-bls menu timeout is not persisted on the ESP")
		}
	}
}

func TestTumbleweedOrdinaryGoldenContainsNativeMeasuredRecoveryTools(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, arch := range []string{"x86_64", "aarch64"} {
		version := tumbleweedInstallerTestVersion(arch)
		release := platform.ForManifest("opensuse-tumbleweed", version)
		recipe, err := tumbleweedInstallerRecipeWithEncryption(release, version, "/dev/vda", arch, strings.Repeat("a", 64), login, private, public, "", "", false, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository, CAPEM: []byte("test-only CA")})
		if err != nil {
			t.Fatal(err)
		}
		var profile struct {
			Loader   string   `xml:"bootloader>loader_type"`
			Packages []string `xml:"software>packages>package"`
		}
		if err := xml.Unmarshal(recipe, &profile); err != nil {
			t.Fatal(err)
		}
		if profile.Loader != "grub2-bls" {
			t.Fatal("ordinary recovery golden selected a different boot chain")
		}
		for _, inputs := range [][]string{release.Lab.Guest.Actions, release.Lab.Guest.MeasuredBoot} {
			for _, pkg := range inputs {
				if !slices.Contains(profile.Packages, pkg) {
					t.Fatalf("ordinary golden omitted signed recovery prerequisite %s", pkg)
				}
			}
		}
	}
}

func TestTumbleweedCaptureBootstrapUsesDVDWithoutSnapshot(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	release := platform.ForManifest("opensuse-tumbleweed", "20261007")
	for _, arch := range []string{"x86_64", "aarch64"} {
		recipe, err := tumbleweedInstallerProfile(release, "20261007", "/dev/vda", arch, strings.Repeat("a", 64), login, private, public, "", "", false, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		var profile autoyastProfile
		if err := xml.Unmarshal(recipe, &profile); err != nil {
			t.Fatal(err)
		}
		if len(profile.AddOns) != 0 || profile.InstallRecommended != "false" || !slices.Equal(profile.Patterns, []string{"base"}) {
			t.Fatalf("capture installer escaped minimal DVD closure: %+v", profile)
		}
		for _, pkg := range []string{"openssh-server", "sudo", "rpm", "zypper", "iproute2"} {
			if !slices.Contains(profile.Packages, pkg) {
				t.Fatalf("bootstrap omitted native solver prerequisite %s", pkg)
			}
		}
		if slices.Contains(profile.Packages, "cloud-init") || slices.Contains(profile.Packages, "cloud-init-config-suse") {
			t.Fatal("capture bootstrap depends on cloud-init absent from the DVD")
		}
		if slices.Contains(profile.Packages, "kernel-default") {
			t.Fatal("capture-only DVD bootstrap was made dependent on the final snapshot kernel")
		}
		if len(profile.Scripts) != 1 || profile.Scripts[0].Chrooted != "true" {
			t.Fatal("capture bootstrap did not provision fixed SSH identity")
		}
		fields := strings.Split(profile.Scripts[0].Source, "'")
		if len(fields) < 4 {
			t.Fatal("missing provisioning payload")
		}
		payload, err := base64.StdEncoding.DecodeString(fields[3])
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"repository-bootstrap-v1", base64.StdEncoding.EncodeToString([]byte(login)), base64.StdEncoding.EncodeToString([]byte(private)), "systemctl enable sshd.service", tumbleweedSSHDOrdering} {
			if !strings.Contains(string(payload), want) {
				t.Fatalf("offline SSH provisioning omitted %q", want)
			}
		}
		for _, forbidden := range []string{"cloud-init", "https://", "zypper ", "update-ca-certificates"} {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("DVD bootstrap unexpectedly depends on %s", forbidden)
			}
		}
	}
	if _, err := tumbleweedInstallerProfile(release, "20261007", "/dev/vda", "x86_64", strings.Repeat("a", 64), login, private, public, "", "", false, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository}, true); err == nil {
		t.Fatal("capture-only profile accepted an external repository")
	}
	if _, err := tumbleweedInstallerRecipeWithEncryption(release, "20261009", "/dev/vda", "x86_64", strings.Repeat("a", 64), login, private, public, "", "", false, nil); err == nil {
		t.Fatal("final ordinary golden admitted the offline capture-only fallback")
	}
}

func TestArchGoldenIdentitySeparatesOwnerBootloaderAndArchive(t *testing.T) {
	m := &labv1.ImageManifest{Distribution: "arch", Version: "rolling", Sha256: strings.Repeat("a", 64), Edition: "systemd-boot-encrypted-lab", RepositorySnapshotDate: proto.String("2026-10-02")}
	first := encryptedGoldenID(m, EncryptedVMOptions{}, "code", "vars", "", true)
	m.Edition = "grub-encrypted-lab"
	second := encryptedGoldenID(m, EncryptedVMOptions{}, "code", "vars", "", true)
	m.RepositorySnapshotDate = proto.String("2026-10-03")
	third := encryptedGoldenID(m, EncryptedVMOptions{}, "code", "vars", "", true)
	if first == second || second == third || first == third {
		t.Fatal("different bootloader or archive reused encrypted golden")
	}
}

func TestArchOrdinaryMachineIdentityIsPublicButCredentialsStayPrivate(t *testing.T) {
	manifest, err := LoadManifest("../../lab/images/arch-20261001-systemd-boot-x86_64.json")
	if err != nil {
		t.Fatal(err)
	}
	image, err := archRecoveryInstallerImage(manifest)
	if err != nil {
		t.Fatal(err)
	}
	login, private, public := encryptedInstallerTestKeys(t)
	recipe, err := image.recipe("/dev/nvme0n1", "x86_64", manifest.GetSha256(), login, private, public)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(recipe), "\n") {
		const suffix = "' | base64 -d > /mnt/root/lindm-provision"
		if !strings.HasSuffix(line, suffix) {
			continue
		}
		encoded := strings.TrimSuffix(strings.TrimPrefix(line, "printf '%s' '"), suffix)
		payload, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"install -m 0644 /dev/null /etc/machine-id", "chmod 0600 /etc/ssh/ssh_host_ed25519_key", "chmod 0600 /home/lindm-lab/.ssh/authorized_keys"} {
			if !strings.Contains(string(payload), required) {
				t.Fatalf("ordinary installer lost explicit mode: %s", required)
			}
		}
		return
	}
	t.Fatal("ordinary installer omitted its owned provisioning payload")
}

func TestArchEncryptedMachineIdentityIsPublicButCredentialsStayPrivate(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, edition := range []string{"systemd-boot-encrypted-lab", "grub-encrypted-lab"} {
		manifest := &labv1.ImageManifest{Distribution: "arch", Version: "rolling", Edition: edition, RepositorySnapshotDate: proto.String("2026-10-02")}
		recipe, err := archEncryptedInstallerRecipe(encryptedInstallerMedia(manifest), "x86_64", "private-test-secret", login, private, public, "gnome")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for line := range strings.SplitSeq(string(recipe), "\n") {
			const suffix = "' | base64 -d > /mnt/root/lindm-provision"
			if !strings.HasSuffix(line, suffix) {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(line, "printf '%s' '"), suffix))
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"install -m 0644 /dev/null /etc/machine-id", "chmod 0600 /etc/ssh/ssh_host_ed25519_key", "chmod 0600 /home/lindm-lab/.ssh/authorized_keys"} {
				if !strings.Contains(string(payload), required) {
					t.Fatalf("%s lost explicit mode: %s", edition, required)
				}
			}
			found = true
		}
		if !found {
			t.Fatalf("%s omitted owned provisioning payload", edition)
		}
	}
}

// Regression: a top-level umask 077 made pacstrap's `mkdir -p -m` create /etc
// and /var root-only (pacman keeps existing directory modes), so dbus-broker
// could not read /etc/machine-id after dropping privileges and the first boot
// never configured networking. Only the key and credential writers are private.
func TestArchInstallersScopeCredentialUmask(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	recipes := map[string][]byte{}
	for _, edition := range []string{"systemd-boot-encrypted-lab", "grub-encrypted-lab"} {
		manifest := &labv1.ImageManifest{Distribution: "arch", Version: "rolling", Edition: edition, RepositorySnapshotDate: proto.String("2026-10-02")}
		recipe, err := archEncryptedInstallerRecipe(encryptedInstallerMedia(manifest), "x86_64", "private-test-secret", login, private, public, "gnome")
		if err != nil {
			t.Fatal(err)
		}
		recipes[edition] = recipe
	}
	manifest, err := LoadManifest("../../lab/images/arch-20261001-systemd-boot-x86_64.json")
	if err != nil {
		t.Fatal(err)
	}
	image, err := archRecoveryInstallerImage(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if recipes["systemd-boot-lab"], err = image.recipe("/dev/vda", "x86_64", manifest.GetSha256(), login, private, public); err != nil {
		t.Fatal(err)
	}
	for edition, recipe := range recipes {
		lines := strings.Split(string(recipe), "\n")
		umask, depth := "", 0
		for i, line := range lines {
			switch {
			case line == "(":
				depth++
			case line == ")":
				depth--
			case depth == 0 && strings.HasPrefix(line, "umask "):
				umask = line
			}
			if strings.HasPrefix(line, "pacstrap ") && umask != "umask 022" {
				t.Fatalf("%s: pacstrap runs under %q", edition, umask)
			}
			if strings.Contains(line, "> /run/lindm-install-key") && !strings.HasPrefix(line, "(umask 077 && ") {
				t.Fatalf("%s: install key is not written under umask 077", edition)
			}
			if strings.HasSuffix(line, "| base64 -d > /mnt/root/lindm-provision") {
				if depth != 1 || lines[i-1] != "umask 077" {
					t.Fatalf("%s: credential provisioning file is not written under a scoped umask 077", edition)
				}
				payload, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(line, "printf '%s' '"), "' | base64 -d > /mnt/root/lindm-provision"))
				if err != nil {
					t.Fatal(err)
				}
				// System files after the credential writer must not inherit 077.
				credentials := strings.LastIndex(string(payload), "umask 077\n")
				if credentials < 0 || strings.Contains(string(payload[:credentials]), "umask") {
					t.Fatalf("%s: chroot provisioning changes umask before the credential writer", edition)
				}
				if rest := string(payload[credentials:]); edition != "systemd-boot-lab" && !strings.Contains(rest, "\numask 022\n") {
					t.Fatalf("%s: boot and desktop provisioning inherit the credential umask", edition)
				}
			}
		}
		if depth != 0 || umask != "umask 022" {
			t.Fatalf("%s: unbalanced or private top-level umask %q", edition, umask)
		}
	}
}

func TestArchInstallerRejectsUnpinnedOrImplicitBootSelection(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, test := range []struct{ arch, edition, snapshot string }{
		{"aarch64", "systemd-boot-encrypted-lab", "2026-10-02"},
		{"x86_64", "encrypted-lab", "2026-10-02"},
		{"x86_64", "systemd-boot-encrypted-lab", "latest"},
	} {
		m := &labv1.ImageManifest{Distribution: "arch", Version: "rolling", Edition: test.edition, RepositorySnapshotDate: proto.String(test.snapshot)}
		if _, err := archEncryptedInstallerRecipe(encryptedInstallerMedia(m), test.arch, "secret", login, private, public, "gnome"); err == nil {
			t.Fatalf("accepted unmaintained installer input %+v", test)
		}
	}
}

func TestTumbleweedSnapshotRequiresExplicitTLSTrust(t *testing.T) {
	for _, snapshot := range []*tumbleweedSnapshotRepository{
		{URL: "http://10.0.2.2/snapshots/pin/", CAPEM: []byte("ca")},
		{URL: "https://user:password@10.0.2.2/snapshots/pin/", CAPEM: []byte("ca")},
		{URL: "https://10.0.2.2/snapshots/pin/"},
	} {
		if _, _, _, err := tumbleweedInstallerRepository(snapshot); err == nil {
			t.Fatal("accepted repository without isolated TLS trust")
		}
	}
}

func TestArchISOBLSPreservesVendorBootIdentity(t *testing.T) {
	original := "title Arch Linux\nlinux /arch/boot/x86_64/vmlinuz-linux\ninitrd /arch/boot/x86_64/initramfs-linux.img\noptions archisobasedir=arch archisosearchuuid=2026-10-01 console=tty0\n"
	patched, err := encryptedInstallerGRUBForMachine([]byte(original), platform.ArchISO, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patched), "archisosearchuuid=2026-10-01") || !strings.Contains(string(patched), "script=/run/archiso/bootmnt/lindm-seed/install.sh") {
		t.Fatal("BLS remaster lost vendor image identity or local installer")
	}
	for _, invalid := range []string{
		strings.ReplaceAll(original, "linux /arch", "linux relative"),
		original + "options second\n",
		strings.ReplaceAll(original, "initrd /arch/boot/x86_64/initramfs-linux.img\n", ""),
	} {
		if _, err := encryptedInstallerBLS([]byte(invalid), "script=/local"); err == nil {
			t.Fatal("accepted ambiguous or incomplete vendor boot entry")
		}
	}
}

func TestLiveActionsExcludeOnlyRecoverySanitize(t *testing.T) {
	want := []platform.Capability{platform.Wipe, platform.ReportLoss, platform.Lock}
	if got := deviceActionCapabilities("wipe", "live-actions"); !slices.Equal(got, want) {
		t.Fatalf("live action capabilities %v, want %v", got, want)
	}
	for _, phase := range []string{"recovery-nvme", "recovery-sata", "recovery-attestation-refusal"} {
		if got := deviceActionCapabilities("wipe", phase); !slices.Contains(got, platform.RecoverySanitize) {
			t.Fatalf("recovery phase %s omitted its capability: %v", phase, got)
		}
	}
}

func TestRepositoryBootstrapClassifiesTumbleweedArtifact(t *testing.T) {
	for _, test := range []struct {
		name string
		dvd  bool
	}{
		{"opensuse-tumbleweed-20261007-x86_64.json", false},
		{"opensuse-tumbleweed-20261007-aarch64.json", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			image, err := LoadManifest("../../lab/images/" + test.name)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := repositorySnapshotInstaller(image)
			if err != nil {
				t.Fatal(err)
			}
			if test.dvd {
				if spec == nil || spec.installer != platform.AutoYaST {
					t.Fatal("signed DVD did not select the offline AutoYaST bootstrap")
				}
			} else if spec != nil {
				t.Fatal("genuine Tumbleweed QCOW2 selected a DVD installer")
			}
			image.Edition = "dvd-encrypted-lab"
			if _, err := repositorySnapshotInstaller(image); err == nil {
				t.Fatal("encrypted golden was admitted as a solver bootstrap")
			}
		})
	}
}

func TestTumbleweedFinalProfilesRequireExactFullSnapshotKernel(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, arch := range []string{"x86_64", "aarch64"} {
		version := tumbleweedInstallerTestVersion(arch)
		release := platform.ForManifest("opensuse-tumbleweed", version)
		for _, secret := range []string{"", "encrypted-test-root"} {
			recipe, err := tumbleweedInstallerRecipeWithEncryption(release, version, "/dev/vda", arch, strings.Repeat("a", 64), login, private, public, secret, "", false, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository, CAPEM: []byte("test-only CA")})
			if err != nil {
				t.Fatal(err)
			}
			var profile autoyastProfile
			if err := xml.Unmarshal(recipe, &profile); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(profile.Packages, "kernel-default") || slices.Contains(profile.Packages, "kernel-default-base") {
				t.Fatal("final installer did not request the full snapshot kernel package")
			}
			if len(profile.Scripts) != 1 {
				t.Fatal("missing installed-chroot pin check")
			}
			fields := strings.Split(profile.Scripts[0].Source, "'")
			if len(fields) < 4 {
				t.Fatal("missing provisioning payload")
			}
			provision, err := base64.StdEncoding.DecodeString(fields[3])
			if err != nil {
				t.Fatal(err)
			}
			for _, pin := range platform.RepositorySnapshotRecipes[release.ID].SnapshotPackages[version][arch] {
				name, evr, _ := strings.Cut(pin, "=")
				if !strings.Contains(evr, ":") {
					evr = "0:" + evr
				}
				for _, want := range []string{"rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n' -- " + nativeQuote(name), "= " + nativeQuote(evr)} {
					if !strings.Contains(string(provision), want) {
						t.Fatalf("final provisioning omitted exact native package check %q", want)
					}
				}
			}
		}
		if _, _, err := tumbleweedSnapshotPackageSelection(release, "20261008", arch); err == nil {
			t.Fatal("unrecorded snapshot admitted without exact kernel facts")
		}
	}
}

// Regression: YaST selected openconnect-lang for aarch64 GNOME although the
// signed closure lacks it, and the encrypted desktop install stalled.
func TestTumbleweedDesktopProfileTaboosPackagesOutsideClosure(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, test := range []struct {
		arch, desktop string
		want          []string
	}{
		{"aarch64", "gnome", []string{"openconnect-lang"}},
		{"aarch64", "", nil},
		{"x86_64", "gnome", nil},
	} {
		version := tumbleweedInstallerTestVersion(test.arch)
		passphrase := ""
		if test.desktop != "" {
			passphrase = "secret"
		}
		recipe, err := tumbleweedInstallerRecipeWithEncryption(platform.ForManifest("opensuse-tumbleweed", version), version, "/dev/vda", test.arch, strings.Repeat("a", 64), login, private, public, passphrase, test.desktop, false, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository, CAPEM: []byte("test-only CA")})
		if err != nil {
			t.Fatal(err)
		}
		var profile struct {
			Taboo []string `xml:"software>remove-packages>package"`
		}
		if err := xml.Unmarshal(recipe, &profile); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(profile.Taboo, test.want) {
			t.Fatalf("%s %q: removed packages %v, want %v", test.arch, test.desktop, profile.Taboo, test.want)
		}
	}
}
