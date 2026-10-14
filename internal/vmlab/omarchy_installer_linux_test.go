// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

type omarchyTestConfiguration struct {
	DiskConfig struct {
		ConfigType          string `json:"config_type"`
		DeviceModifications []struct {
			Device     string `json:"device"`
			Wipe       bool   `json:"wipe"`
			Partitions []struct {
				ObjID      string `json:"obj_id"`
				FSType     string `json:"fs_type"`
				Mountpoint *string
				Status     string `json:"status"`
				Start      struct {
					Value int64 `json:"value"`
				} `json:"start"`
				Size struct {
					Value int64 `json:"value"`
				} `json:"size"`
				Btrfs []struct {
					Name       string `json:"name"`
					Mountpoint string `json:"mountpoint"`
				} `json:"btrfs"`
			} `json:"partitions"`
		} `json:"device_modifications"`
		DiskEncryption *struct {
			EncryptionType     string   `json:"encryption_type"`
			Partitions         []string `json:"partitions"`
			EncryptionPassword string   `json:"encryption_password"`
		} `json:"disk_encryption"`
	} `json:"disk_config"`
	Bootloader struct {
		Bootloader string `json:"bootloader"`
	} `json:"bootloader_config"`
	OmarchyInstall struct {
		Mode              string `json:"mode"`
		DeferProvisioning bool   `json:"defer_provisioning"`
		Boot              struct {
			EnableFallback bool `json:"enable_fallback"`
		} `json:"boot"`
	} `json:"omarchy_install"`
	Kernels []string `json:"kernels"`
}

type omarchyTestCredentials struct {
	EncryptionPassword *string `json:"encryption_password"`
	RootEncPassword    string  `json:"root_enc_password"`
	Users              []struct {
		Username    string `json:"username"`
		EncPassword string `json:"enc_password"`
		Sudo        bool   `json:"sudo"`
	} `json:"users"`
}

const omarchyTestHash = "$6$salt$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx"

func omarchyTestSeed(t *testing.T) omarchySeed {
	t.Helper()
	_, public, err := encryptedKey()
	if err != nil {
		t.Fatal(err)
	}
	return omarchySeed{disk: "/dev/vda", diskBytes: omarchyDiskBytes, passwordHash: omarchyTestHash, authorizedKey: public}
}

func decodeOmarchySeed(t *testing.T, files map[string][]byte) (omarchyTestConfiguration, omarchyTestCredentials) {
	t.Helper()
	if len(files) != 4 {
		t.Fatalf("cidata must carry exactly the configurator files used: %v", len(files))
	}
	var config omarchyTestConfiguration
	var credentials omarchyTestCredentials
	if err := json.Unmarshal(files["user_configuration.json"], &config); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files["user_credentials.json"], &credentials); err != nil {
		t.Fatal(err)
	}
	return config, credentials
}

func TestOmarchyCidataUnencryptedLayout(t *testing.T) {
	seed := omarchyTestSeed(t)
	files, err := omarchyCidataFiles(seed)
	if err != nil {
		t.Fatal(err)
	}
	config, credentials := decodeOmarchySeed(t, files)
	if config.DiskConfig.DiskEncryption != nil || credentials.EncryptionPassword != nil || string(files["user_encrypt_installation.txt"]) != "false\n" {
		t.Fatal("unencrypted seed requested encryption")
	}
	if config.Bootloader.Bootloader != "Limine" || config.OmarchyInstall.Mode != "full_disk" || config.OmarchyInstall.DeferProvisioning || !config.OmarchyInstall.Boot.EnableFallback || len(config.Kernels) != 1 || config.Kernels[0] != "linux-omarchy" {
		t.Fatalf("seed differs from the vendor full-disk Limine install: %+v", config.OmarchyInstall)
	}
	devices := config.DiskConfig.DeviceModifications
	if config.DiskConfig.ConfigType != "default_layout" || len(devices) != 1 || devices[0].Device != "/dev/vda" || !devices[0].Wipe || len(devices[0].Partitions) != 2 {
		t.Fatalf("unexpected target disk: %+v", devices)
	}
	boot, root := devices[0].Partitions[0], devices[0].Partitions[1]
	const mib = 1 << 20
	if boot.ObjID != omarchyBootPartitionID || boot.FSType != "fat32" || boot.Start.Value != mib || boot.Size.Value != 2<<30 {
		t.Fatalf("unexpected ESP: %+v", boot)
	}
	if root.ObjID != omarchyRootPartitionID || root.FSType != "btrfs" || root.Start.Value != boot.Start.Value+boot.Size.Value || root.Start.Value+root.Size.Value != omarchyDiskBytes-mib {
		t.Fatalf("root must fill the disk up to the GPT backup reserve: %+v", root)
	}
	subvolumes := map[string]string{}
	for _, subvolume := range root.Btrfs {
		subvolumes[subvolume.Name] = subvolume.Mountpoint
	}
	if subvolumes["@"] != "/" || subvolumes["@home"] != "/home" || len(subvolumes) != 4 {
		t.Fatalf("unexpected Btrfs subvolumes: %v", subvolumes)
	}
	if credentials.RootEncPassword != omarchyTestHash || len(credentials.Users) != 1 || credentials.Users[0].Username != labUser || !credentials.Users[0].Sudo || credentials.Users[0].EncPassword != omarchyTestHash {
		t.Fatalf("unexpected credentials: %+v", credentials)
	}
	if keys := string(files["authorized_keys"]); strings.Count(keys, "\n") != 1 || !strings.HasPrefix(keys, "ssh-ed25519 ") {
		t.Fatalf("authorized_keys must hold exactly the lab key: %q", keys)
	}
}

func TestOmarchyCidataEncryptedRoot(t *testing.T) {
	seed := omarchyTestSeed(t)
	seed.passphrase = "lab-only-passphrase"
	seed.disk = "/dev/sda"
	files, err := omarchyCidataFiles(seed)
	if err != nil {
		t.Fatal(err)
	}
	config, credentials := decodeOmarchySeed(t, files)
	encryption := config.DiskConfig.DiskEncryption
	if encryption == nil || encryption.EncryptionType != "luks" || len(encryption.Partitions) != 1 || encryption.Partitions[0] != omarchyRootPartitionID || encryption.EncryptionPassword != seed.passphrase {
		t.Fatalf("encrypted seed must LUKS-encrypt only the root partition: %+v", encryption)
	}
	if credentials.EncryptionPassword == nil || *credentials.EncryptionPassword != seed.passphrase || string(files["user_encrypt_installation.txt"]) != "true\n" {
		t.Fatal("encrypted flag and credentials must match the disk_encryption block")
	}
	if config.DiskConfig.DeviceModifications[0].Device != "/dev/sda" {
		t.Fatal("seed ignored the selected target disk")
	}
}

func TestOmarchyCidataRejectsUnsafeInput(t *testing.T) {
	for name, change := range map[string]func(*omarchySeed){
		"relative disk":        func(s *omarchySeed) { s.disk = "vda" },
		"small disk":           func(s *omarchySeed) { s.diskBytes = 4 << 30 },
		"plaintext password":   func(s *omarchySeed) { s.passwordHash = "secret" },
		"multiline hash":       func(s *omarchySeed) { s.passwordHash = omarchyTestHash + "\nroot::0:0" },
		"multiline passphrase": func(s *omarchySeed) { s.passphrase = "a\nb" },
		"key options":          func(s *omarchySeed) { s.authorizedKey = "command=\"/bin/sh\" " + s.authorizedKey },
		"two keys":             func(s *omarchySeed) { s.authorizedKey += "\n" + s.authorizedKey },
	} {
		t.Run(name, func(t *testing.T) {
			seed := omarchyTestSeed(t)
			change(&seed)
			if _, err := omarchyCidataFiles(seed); err == nil {
				t.Fatal("unsafe seed accepted")
			}
		})
	}
}

func TestOmarchyManifests(t *testing.T) {
	plain, err := LoadManifest("../../lab/images/omarchy-4.0.4-x86_64.json")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := LoadManifest("../../lab/images/omarchy-4.0.4-encrypted-x86_64.json")
	if err != nil {
		t.Fatal(err)
	}
	if spec, err := installerImageFor(plain); err != nil || spec == nil || spec.install == nil {
		t.Fatalf("plain manifest must select the cidata installer: %v", err)
	}
	if _, err := installerImageFor(encrypted); err == nil {
		t.Fatal("encrypted-lab edition must not build the cloud-init golden")
	}
	if err := omarchyManifest(encrypted, omarchyEncryptedInstallerEdition); err != nil {
		t.Fatal(err)
	}
	if plain.GetSha256() != encrypted.GetSha256() || plain.GetSignatureUrl() != encrypted.GetSignatureUrl() {
		t.Fatal("both editions must pin the same signed ISO")
	}
	for name, change := range map[string]func(*labv1.ImageManifest){
		"checksum signature mode": func(m *labv1.ImageManifest) { m.ChecksumMode = labv1.ChecksumMode_CHECKSUM_MODE_DETACHED },
		"other version":           func(m *labv1.ImageManifest) { m.Version = "4.0.3" },
		"arm":                     func(m *labv1.ImageManifest) { m.Architecture = "aarch64" },
		"other media":             func(m *labv1.ImageManifest) { m.ImageFilename = "omarchy-4.0.4-dev.iso" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(plain)
			change(changed)
			if err := omarchyManifest(changed, omarchyInstallerEdition); err == nil {
				t.Fatal("unpinned Omarchy media accepted")
			}
		})
	}
}

func TestOmarchyConsoleCmdline(t *testing.T) {
	config := "timeout: 3\n/+Omarchy\n  //linux-omarchy\n    protocol: efi\n    path: boot():/EFI/Linux/omarchy_linux-omarchy.efi#abc\n    cmdline: quiet splash cryptdevice=PARTUUID=x:root root=/dev/mapper/root rw\n  //Snapshots\n    cmdline: quiet splash root=UUID=y rw\n"
	edited, err := omarchyConsoleCmdline([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(config, "root=/dev/mapper/root rw\n", "root=/dev/mapper/root rw "+omarchySerialConsole+"\n", 1)
	if string(edited) != want {
		t.Fatalf("only the LUKS root cmdline may gain the serial console:\n%s", edited)
	}
	for name, input := range map[string]string{
		"no LUKS entry":    "cmdline: quiet root=UUID=y rw\n",
		"existing console": "cmdline: cryptdevice=PARTUUID=x:root console=tty1\n",
	} {
		if _, err := omarchyConsoleCmdline([]byte(input)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Observed on the Omarchy 4.0.4 lab initramfs without plymouth: the encrypt
// hook's sentence can arrive in a serial read before its newline, and
// answering it typed the passphrase into the echoing console before
// cryptsetup's own prompt, which then read as a rejection.
func TestEncryptedUnlockPromptMkinitcpioEncrypt(t *testing.T) {
	for text, want := range map[string]bool{
		"\nA password is required to access the root volume:":                                   false,
		"\nA password is required to access the root volume:\n":                                 false,
		"\nA password is required to access the root volume:\nEnter passphrase for /dev/vda2: ": true,
	} {
		if got := encryptedUnlockPrompt(text); got != want {
			t.Errorf("encryptedUnlockPrompt(%q) = %t, want %t", text, got, want)
		}
	}
	for text, want := range map[string]bool{
		// plymouth ask-for-password (bootstrap boot only)
		"A password is required to access the root volume:": true,
		// a partial read must not trigger an early submission
		"A password is required to access the ro": false,
	} {
		if got := omarchyBootstrapPrompt(text); got != want {
			t.Errorf("omarchyBootstrapPrompt(%q) = %t, want %t", text, got, want)
		}
	}
}

// The vendor plymouth password display redraws its prompt for every
// keystroke; the bootstrap unlock must submit exactly once and not mistake
// the redraw for a rejection.
func TestOmarchyBootstrapUnlockSubmitsOnceAcrossPlymouthRedraws(t *testing.T) {
	guest, host := net.Pipe()
	t.Cleanup(func() { _ = guest.Close(); _ = host.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- omarchyBootstrapUnlock(ctx, host, "lab-secret") }()
	prompt := "A password is required to access the root volume: "
	if _, err := io.WriteString(guest, "Starting systemd-udevd\n"+prompt); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(guest)
	line, err := reader.ReadString('\r')
	if err != nil || line != "lab-secret\r" {
		t.Fatalf("passphrase not submitted once: %q %v", line, err)
	}
	for _, redraw := range []string{prompt + "*", prompt + "**********", prompt} {
		if _, err := io.WriteString(guest, "\r"+redraw); err != nil {
			t.Fatal(err)
		}
	}
	extra := make(chan string, 1)
	go func() { data, _ := reader.ReadString('\r'); extra <- data }()
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("redrawn prompt treated as failure: %v", err)
	}
	_ = guest.Close()
	if data := <-extra; data != "" {
		t.Fatalf("passphrase submitted again after redraw: %q", data)
	}
}

func TestOmarchyBootstrapUnlockRequiresPrompt(t *testing.T) {
	guest, host := net.Pipe()
	t.Cleanup(func() { _ = guest.Close(); _ = host.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- omarchyBootstrapUnlock(ctx, host, "lab-secret") }()
	if _, err := io.WriteString(guest, "Booting without any encrypted root\n"); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-result; err == nil {
		t.Fatal("boot without a LUKS prompt accepted")
	}
}

// cryptsetup writes "Enter passphrase for ...: " and then flushes queued input
// with TCSAFLUSH while disabling echo; a secret typed on the first prompt
// bytes was discarded and the Omarchy cold boot waited until the SSH deadline.
// The unlock must type only after the prompt has settled.
func TestUnlockEncryptedSerialWaitsOutPromptFlush(t *testing.T) {
	guest, host := net.Pipe()
	t.Cleanup(func() { _ = guest.Close(); _ = host.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := unlockEncryptedSerial(ctx, host, "lab-secret", nil)
		result <- err
	}()
	prompted := time.Now()
	if _, err := io.WriteString(guest, "\nA password is required to access the root volume:\nEnter passphrase for /dev/vda2: "); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(guest).ReadString('\r')
	if err != nil || line != "lab-secret\r" {
		t.Fatalf("secret not typed: %q %v", line, err)
	}
	if waited := time.Since(prompted); waited < encryptedPromptSettle {
		t.Fatalf("secret typed %v after the prompt, inside the TCSAFLUSH window", waited)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// Observed on the Omarchy update lane: an Arch channel without its adjacent
// detached signature target fails catalog validation before any publication.
func TestUpdateChannelPublishesArchSignatureTarget(t *testing.T) {
	artifact := packaging.Artifact{Format: packaging.FormatArch, Path: "/work/lindm-agent-0.2.0-1-x86_64.pkg.tar.zst", SignaturePath: "/work/lindm-agent-0.2.0-1-x86_64.pkg.tar.zst.sig", Version: "0.2.0", Architecture: packaging.Architecture{GOARCH: "amd64"}}
	channel, targets, name := updateChannel(artifact, 1, true, 100)
	if err := protovalidate.Validate(channel); err != nil {
		t.Fatal(err)
	}
	got := channel.GetArtifacts()[0]
	if got.GetSignatureTargetPath() != name+".sig" || targets[name] != artifact.Path || targets[name+".sig"] != artifact.SignaturePath || len(targets) != 2 || got.GetNativeVersion() != "0.2.0-1" {
		t.Fatalf("Arch update targets do not bind the detached signature: %+v %v", got, targets)
	}
	artifact.Format, artifact.SignaturePath = packaging.FormatDEB, ""
	if _, targets, _ := updateChannel(artifact, 1, true, 100); len(targets) != 1 {
		t.Fatalf("DEB update published extra targets: %v", targets)
	}
}

// Omarchy has no immutable online repository snapshot: its cloud golden
// installs the resource tools from the authenticated ISO, so the resource lane
// only verifies them. Every other rolling release still requires its approved
// snapshot and refreshes against it.
func TestRollingResourcePrerequisitesFromInstaller(t *testing.T) {
	plain, err := LoadManifest("../../lab/images/omarchy-4.0.4-x86_64.json")
	if err != nil {
		t.Fatal(err)
	}
	row := platform.ForManifest(plain.GetDistribution(), plain.GetVersion())
	install, query, err := rollingResourcePrerequisites(row, platform.BackendPacman, false)
	want := "pacman -Q"
	for _, name := range row.Lab.ResourcePackages {
		want += " " + nativeQuote(name)
	}
	if err != nil || install != "" || query != want || strings.Contains(query, "firewalld") {
		t.Fatalf("installer-provided prerequisites = %q %q %v", install, query, err)
	}
	cloud := omarchyCloudPackages(plain)
	for _, name := range append(slices.Clone(row.Lab.Guest.Actions), row.Lab.ResourcePackages...) {
		if !slices.Contains(cloud, name) {
			t.Fatalf("cloud golden omits %s: %v", name, cloud)
		}
	}
	if len(cloud) != len(slices.Compact(slices.Sorted(slices.Values(cloud)))) {
		t.Fatalf("cloud golden packages repeat: %v", cloud)
	}
	if omarchyCloudRecipeVersion == omarchyInstallerRecipeVersion {
		t.Fatal("cloud golden recipe does not change with its resource prerequisites")
	}
	for _, release := range platform.Releases() {
		if release.Lab.Guest.FromInstaller || len(release.Native().Lab.ResourcePackages) == 0 || release.Native().Packages.Backend != platform.BackendPacman {
			continue
		}
		if _, _, err := rollingResourcePrerequisites(release, platform.BackendPacman, false); err == nil {
			t.Fatalf("%s provisioned rolling prerequisites without its approved snapshot", release.Key)
		}
		install, _, err := rollingResourcePrerequisites(release, platform.BackendPacman, true)
		if err != nil || !strings.HasPrefix(install, "pacman -Syu --needed --noconfirm ") {
			t.Fatalf("%s snapshot provisioning = %q %v", release.Key, install, err)
		}
	}
}
