//go:build linux

package vmlab

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

type autoyastProfile struct {
	Mode struct {
		Confirm     string `xml:"confirm"`
		SecondStage string `xml:"second_stage"`
		// final_halt applies only after a second stage; without halt the
		// installer reboots into the vendor DVD and reinstalls.
		Halt string `xml:"halt"`
	} `xml:"general>mode"`
	Drives []struct {
		Device     string `xml:"device"`
		Initialize string `xml:"initialize"`
		Use        string `xml:"use"`
	} `xml:"partitioning>drive"`
	Bootloader struct {
		Append      string `xml:"append"`
		UpdateNVRAM struct {
			Type  string `xml:"http://www.suse.com/1.0/configns type,attr"`
			Value string `xml:",chardata"`
		} `xml:"update_nvram"`
	} `xml:"bootloader>global"`
	InstallRecommended string   `xml:"software>install_recommended"`
	Patterns           []string `xml:"software>patterns>pattern"`
	Packages           []string `xml:"software>packages>package"`
	AddOns             []struct {
		URL      string `xml:"media_url"`
		Alias    string `xml:"alias"`
		Priority string `xml:"priority"`
	} `xml:"add-on>add_on_others>listentry"`
	Users []struct {
		Name     string `xml:"username"`
		Password string `xml:"user_password"`
	} `xml:"users>user"`
	Scripts []struct {
		Chrooted string `xml:"chrooted"`
		Source   string `xml:"source"`
	} `xml:"scripts>chroot-scripts>script"`
}

const tumbleweedTestRepository = "https://10.0.2.2:12345/snapshots/" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"

func tumbleweedInstallerRecipe(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
	version := tumbleweedInstallerTestVersion(architecture)
	return tumbleweedInstallerRecipeWithEncryption(platform.ForManifest("opensuse-tumbleweed", version), version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic, "", "", false, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository, CAPEM: []byte("test-only CA")})
}

func tumbleweedInstallerTestVersion(architecture string) string {
	switch architecture {
	case "x86_64":
		return "20261009"
	case "aarch64":
		return "20261007"
	default:
		return ""
	}
}

func TestTumbleweedAutoYaSTBindsOwnedDiskPinnedMediaAndCredentials(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, architecture := range []string{"x86_64", "aarch64"} {
		t.Run(architecture, func(t *testing.T) {
			digest := strings.Repeat("a", 64)
			recipe, err := tumbleweedInstallerRecipe("/dev/vda", architecture, digest, login, private, public)
			if err != nil {
				t.Fatal(err)
			}
			var profile autoyastProfile
			if err := xml.Unmarshal(recipe, &profile); err != nil {
				t.Fatal(err)
			}
			if profile.Mode.Confirm != "false" || profile.Mode.SecondStage != "false" || profile.Mode.Halt != "true" {
				t.Fatalf("profile is not unattended single-stage poweroff: %+v", profile.Mode)
			}
			if len(profile.Drives) != 1 || profile.Drives[0].Device != "/dev/vda" || profile.Drives[0].Initialize != "true" || profile.Drives[0].Use != "all" {
				t.Fatalf("profile does not bind the owned guest disk: %+v", profile.Drives)
			}
			// Fresh firmware variables per guest: only the removable path boots.
			console := "console=ttyS0"
			if architecture == "aarch64" {
				console = "console=ttyAMA0"
			}
			// YaST's schema (yast2-schema 5.0.3 on the Snapshot20261007 DVD)
			// types update_nvram as an untyped "true"|"false" string; with
			// config:type="boolean" the installer stops on an invalid profile.
			if profile.Bootloader.UpdateNVRAM.Value != "false" || profile.Bootloader.UpdateNVRAM.Type != "" || !strings.Contains(profile.Bootloader.Append, console) || !strings.Contains(profile.Bootloader.Append, "net.ifnames=0") {
				t.Fatalf("bootloader binds NVRAM, breaks the schema or loses console: %+v", profile.Bootloader)
			}
			// The schema names this element install_recommended; any other
			// software child also invalidates the whole profile.
			if profile.InstallRecommended != "true" || strings.Contains(string(recipe), "install_recommends") {
				t.Fatal("software section does not use the schema's install_recommended element")
			}
			// The DVD (default priority 99) outranks the one online repository,
			// whose signed snapshot binding uses this exact URL and alias.
			if len(profile.AddOns) != 1 || profile.AddOns[0].URL != tumbleweedTestRepository || profile.AddOns[0].Alias != tumbleweedRepositoryAlias || profile.AddOns[0].Priority != "120" {
				t.Fatalf("profile lacks the bound lower-priority repository: %+v", profile.AddOns)
			}
			unbound := strings.NewReplacer("http://www.suse.com/1.0/yast2ns", "", "http://www.suse.com/1.0/configns", "", tumbleweedTestRepository, "").Replace(string(recipe))
			if strings.Contains(unbound, "://") || strings.Contains(unbound, "add_on_products") {
				t.Fatal("profile adds an unbound network repository")
			}
			// The solver otherwise satisfies cloud-init-config with MicroOS's
			// configuration (observed on Snapshot20261007), not the TW default.
			for _, want := range []string{"openssh-server", "sudo", "cloud-init", "cloud-init-config-suse"} {
				if !containsString(profile.Packages, want) {
					t.Fatalf("profile lacks package %q", want)
				}
			}
			if !containsString(profile.Patterns, "base") {
				t.Fatal("profile lacks the base pattern")
			}
			users := make(map[string]string)
			for _, user := range profile.Users {
				users[user.Name] = user.Password
			}
			if users["root"] != "!" || users["lindm-lab"] != "!" {
				t.Fatalf("profile permits password login: %+v", profile.Users)
			}
			if len(profile.Scripts) != 1 || profile.Scripts[0].Chrooted != "true" {
				t.Fatal("provisioning must run once inside the installed system")
			}
			script := profile.Scripts[0].Source
			fields := strings.Split(script, "'")
			if len(fields) < 4 {
				t.Fatal("missing quoted provisioning payload")
			}
			payload, err := base64.StdEncoding.DecodeString(fields[3])
			if err != nil {
				t.Fatal(err)
			}
			// Observed lifecycle flake: sshd answered before systemd-user-sessions
			// removed /run/nologin, and pam_nologin rejected the pinned key.
			for _, want := range []string{base64.StdEncoding.EncodeToString([]byte(login)), base64.StdEncoding.EncodeToString([]byte(private)), base64.StdEncoding.EncodeToString([]byte(public)), "datasource_list: [ NoCloud ]", digest + "' > " + installerSourceMarkerPath, "cloud-init clean", "systemctl enable sshd.service", "'[Unit]' 'After=systemd-user-sessions.service' > " + tumbleweedSSHDOrdering} {
				if !bytes.Contains(payload, []byte(want)) {
					t.Fatalf("installed provisioning lost %q", want)
				}
			}
			const machineIDReset = "install -m 0644 /dev/null /etc/machine-id"
			if !bytes.Contains(payload, []byte(machineIDReset)) {
				t.Fatal("machine identity inherits private credential mode")
			}
			machineID := filepath.Join(t.TempDir(), "machine-id")
			reset := exec.Command("/bin/sh", "-eu", "-c", "umask 077\n"+strings.ReplaceAll(machineIDReset, "/etc/machine-id", nativeQuote(machineID)))
			if output, err := reset.CombinedOutput(); err != nil {
				t.Fatalf("reset public machine identity: %v: %s", err, output)
			}
			info, err := os.Stat(machineID)
			if err != nil || info.Mode().Perm() != 0644 || info.Size() != 0 {
				t.Fatalf("machine identity must be empty and mode 0644 under umask 077: %v %v", info, err)
			}
			// A failing payload must fail the AutoYaST script, not the cleanup.
			if !strings.Contains(script, "/bin/sh -eu /tmp/lindm-provision && rm -f") {
				t.Fatal("provisioning failure is masked by cleanup")
			}
			for _, text := range []string{script, string(payload)} {
				cmd := exec.Command("/bin/sh", "-n")
				cmd.Stdin = strings.NewReader(text)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("invalid provisioning shell: %v: %s", err, output)
				}
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestTumbleweedRecipeRejectsWrongAuthorityAndTarget(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	for _, test := range []struct{ disk, arch, digest, login, private, public string }{
		{"/dev/host", "aarch64", strings.Repeat("a", 64), login, private, public},
		{"/dev/vda", "riscv64", strings.Repeat("a", 64), login, private, public},
		{"/dev/vda", "aarch64", "]]><script/>", login, private, public},
		{"/dev/vda", "aarch64", strings.Repeat("a", 64), "invalid", private, public},
		{"/dev/vda", "aarch64", strings.Repeat("a", 64), login, private, login},
	} {
		if _, err := tumbleweedInstallerRecipe(test.disk, test.arch, test.digest, test.login, test.private, test.public); err == nil {
			t.Fatalf("invalid installer authority/target accepted: %+v", test)
		}
	}
}

func TestTumbleweedInstallerManifestPinsSnapshotDVD(t *testing.T) {
	manifest, err := LoadManifest("../../lab/images/opensuse-tumbleweed-20261007-aarch64.json")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := installerImageFor(manifest)
	if err != nil || spec == nil || spec.installer != platform.AutoYaST || spec.cache != "tumbleweed-installed" {
		t.Fatalf("snapshot DVD is not installer-built: %+v, %v", spec, err)
	}
	if manifest.GetImageSizeBytes() < 1<<30 || manifest.GetSignerProvenanceUrl() == "" || manifest.GetReleaseProvenanceUrl() == "" {
		t.Fatal("installer acquisition lacks a pinned vendor ISO and provenance")
	}
	probes := make(map[string]string)
	for _, probe := range spec.probes {
		probes[probe.label] = probe.script
	}
	if !strings.Contains(probes["version"], "'20261007'") || !strings.Contains(probes["source_marker"], manifest.GetSha256()) || !strings.Contains(probes["removable_boot"], "bootaa64.efi") {
		t.Fatalf("validation does not bind the installed snapshot, media and boot path: %v", probes)
	}
	if !strings.Contains(probes["exact_snapshot_packages"], "'kernel-default'") || !strings.Contains(probes["exact_snapshot_packages"], "'0:7.2.9-1.1'") {
		t.Fatal("ordinary first boot does not enforce the registry's exact full-kernel pin")
	}
	for name, mutate := range map[string]func(*labv1.ImageManifest){
		"moving release": func(m *labv1.ImageManifest) { m.Release = "Current" },
		"network media": func(m *labv1.ImageManifest) {
			m.ImageFilename = "openSUSE-Tumbleweed-NET-aarch64-Snapshot20261007-Media.iso"
		},
		"other snapshot":     func(m *labv1.ImageManifest) { m.Version = "20261008" },
		"undated version":    func(m *labv1.ImageManifest) { m.Version, m.Release = "rolling", "Snapshotrolling" },
		"foreign media arch": func(m *labv1.ImageManifest) { m.Architecture = "x86_64" },
		"unsigned checksum":  func(m *labv1.ImageManifest) { m.ChecksumMode = labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED },
	} {
		t.Run(name, func(t *testing.T) {
			changed, ok := proto.Clone(manifest).(*labv1.ImageManifest)
			if !ok {
				t.Fatal("clone changed manifest type")
			}
			mutate(changed)
			if _, err := installerImageFor(changed); err == nil {
				t.Fatal("invalid Tumbleweed installer manifest accepted")
			}
		})
	}
	cloud, err := LoadManifest("../../lab/images/opensuse-tumbleweed-20261007-x86_64.json")
	if err != nil {
		t.Fatal(err)
	}
	if spec, err := installerImageFor(cloud); spec != nil || err != nil {
		t.Fatalf("cloud disk routed through installer: %v", err)
	}
}

// Excerpt of the vendor EFI/BOOT/grub.cfg from openSUSE-Tumbleweed-NET-aarch64-
// Snapshot20261007-Media.iso: bare default/timeout assignments and a theme.
const tumbleweedVendorGRUB = `with_gfx=1
search --no-floppy --file /boot/aarch64/efi --set
prefix=($root)/boot/aarch64/grub2-efi
if [ "$with_gfx" = 1 ] ; then
  terminal_output gfxterm
fi
if sleep --interruptible 0 ; then
  timeout=60
fi
default=1
menuentry "Boot from Hard Disk" --class opensuse {
  exit
}
menuentry 'Installation' --class opensuse {
  set gfxpayload=keep
  linux /boot/aarch64/linux splash=silent
  initrd /boot/aarch64/initrd
}
menuentry 'Upgrade' --class opensuse {
  linux /boot/aarch64/linux splash=silent upgrade=1
  initrd /boot/aarch64/initrd
}
`

func TestTumbleweedGRUBSelectsUnattendedInstallation(t *testing.T) {
	for _, arch := range []string{"x86_64", "aarch64"} {
		patched, err := encryptedInstallerGRUBForMachine([]byte(tumbleweedVendorGRUB), platform.AutoYaST, arch)
		if err != nil {
			t.Fatal(err)
		}
		text := string(patched)
		// The vendor's later bare assignments would override a prefixed "set".
		for _, stale := range []string{"\ndefault=1", "timeout=60", "with_gfx=1"} {
			if strings.Contains(text, stale) {
				t.Fatalf("vendor menu override %q survived: %s", stale, text)
			}
		}
		for _, want := range []string{"default='Installation'", "timeout=1", "with_gfx=0", "linux /boot/aarch64/linux splash=silent autoyast=cd:/lindm-seed/autoinst.xml textmode=1 self_update=0", "initrd /boot/aarch64/initrd"} {
			if !strings.Contains(text, want) {
				t.Fatalf("installer lost %q: %s", want, text)
			}
		}
		console := "console=ttyS0"
		if arch == "aarch64" {
			console = "console=ttyAMA0"
		}
		if !strings.Contains(text, console) || strings.Contains(text, " ---") {
			t.Fatalf("wrong console or Debian argument separator: %s", text)
		}
	}
}

// The El Torito FAT image holds the grub.cfg the vendor's GRUB actually reads.
// Build media with real xorriso/mtools in the vendor ARM DVD layout: platform-0
// catalog entry plus a hybrid MBR partition naming that file, which
// openSUSE-Tumbleweed-DVD-aarch64-Snapshot20261007 carries and xorriso's
// replay rejects ("Cannot make proposal to mark data file as MBR partition").
func TestTumbleweedRemasterPatchesEFIImageGRUB(t *testing.T) {
	for _, tool := range []string{"xorriso", "mformat", "mmd", "mcopy", "mtype"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("native remaster oracle requires xorriso and mtools")
		}
	}
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	run := func(name string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "MTOOLSRC=/dev/null", "MTOOLS_SKIP_CHECK=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", name, err, output)
		}
		return output
	}
	if err := os.MkdirAll(filepath.Join(tree, "EFI", "BOOT"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "boot", "aarch64"), 0700); err != nil {
		t.Fatal(err)
	}
	grub := filepath.Join(tree, "EFI", "BOOT", "grub.cfg")
	if err := os.WriteFile(grub, []byte(tumbleweedVendorGRUB), 0600); err != nil {
		t.Fatal(err)
	}
	efi := filepath.Join(tree, "boot", "aarch64", "efi")
	run("mformat", "-C", "-i", efi, "-f", "1440", "::")
	run("mmd", "-i", efi, "::/EFI", "::/EFI/BOOT")
	run("mcopy", "-i", efi, grub, "::/EFI/BOOT/grub.cfg")
	media := filepath.Join(dir, "vendor.iso")
	run("xorriso", "-as", "mkisofs", "-quiet", "-R", "-o", media, "-b", "boot/aarch64/efi", "-no-emul-boot", tree)
	vendorReport := string(run("xorriso", "-no_rc", "-indev", media, "-report_el_torito", "plain"))
	if !strings.Contains(vendorReport, " BIOS ") {
		t.Fatalf("fixture lacks the vendor platform-0 catalog entry: %s", vendorReport)
	}
	lba, err := strconv.ParseInt(strings.Fields(vendorReport[strings.LastIndex(vendorReport, "El Torito boot img"):])[12], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	mbr := make([]byte, 66)
	mbr[0], mbr[4] = 0x80, 0x0c
	binary.LittleEndian.PutUint32(mbr[8:], uint32(lba*4))
	binary.LittleEndian.PutUint32(mbr[12:], 1440*1024/512)
	mbr[64], mbr[65] = 0x55, 0xaa
	vendor, err := os.OpenFile(media, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vendor.WriteAt(mbr, 446); err != nil {
		t.Fatal(err)
	}
	if err := vendor.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(run("xorriso", "-no_rc", "-indev", media, "-report_system_area", "plain")), "MBR partition path :   1  /boot/aarch64/efi") {
		t.Fatal("fixture lacks the vendor hybrid MBR partition")
	}
	input, err := os.Open(media)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	stage := filepath.Join(dir, "run")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	output, err := prepareInstallerFileForMachine(t.Context(), stage, input, platform.AutoYaST, []byte("<profile/>"), "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	report := string(run("xorriso", "-no_rc", "-indev", output, "-report_el_torito", "plain", "-report_system_area", "plain"))
	if strings.Count(report, "El Torito boot img") != 1 || !strings.Contains(report, "El Torito img path :   1  /boot/aarch64/efi") || strings.Contains(report, "MBR partition") {
		t.Fatalf("remastered media is not one UEFI entry without the hybrid MBR: %s", report)
	}
	offset, err := encryptedInstallerEFIOffset([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	inner := run("mtype", "-i", output+"@@"+strconv.FormatInt(offset, 10), "::/EFI/BOOT/grub.cfg")
	extracted := filepath.Join(dir, "extracted")
	run("xorriso", "-no_rc", "-osirrox", "on", "-indev", output, "-extract", "/EFI/BOOT/grub.cfg", extracted+".cfg", "-extract", "/lindm-seed/autoinst.xml", extracted+".xml")
	outer, err := os.ReadFile(extracted + ".cfg")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile(extracted + ".xml")
	if err != nil || string(profile) != "<profile/>" {
		t.Fatalf("profile not placed at the autoyast path: %q, %v", profile, err)
	}
	for name, cfg := range map[string][]byte{"EFI image": inner, "ISO tree": outer} {
		if !bytes.Contains(cfg, []byte("autoyast=cd:/lindm-seed/autoinst.xml")) || !bytes.Contains(cfg, []byte("default='Installation'")) {
			t.Fatalf("%s grub.cfg not patched: %s", name, cfg)
		}
	}
}
