package recoveryboot

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/measuredboot"
	"lindm/internal/platform"
)

func TestMeasuredKernelOptionsStripsGRUBBootImage(t *testing.T) {
	const action = "12345678-1234-1234-1234-123456789abc"
	options, err := measuredboot.KernelOptions(action, "ttyS0,115200n8")
	if err != nil {
		t.Fatal(err)
	}
	got, err := measuredOptions([]byte("BOOT_IMAGE=(hd0,gpt3)/boot/vmlinuz-6.19.10-300.fc44.x86_64 " + options + "\n"))
	if err != nil || got != options {
		t.Fatalf("options=%q err=%v", got, err)
	}
	if parsed, err := measuredboot.ActionFromKernelOptions(got); err != nil || parsed != action {
		t.Fatalf("action=%q err=%v", parsed, err)
	}
	if _, err := measuredOptions([]byte("BOOT_IMAGE=(hd0,gpt3)/boot/vmlinuz\n")); err == nil {
		t.Fatal("bare BOOT_IMAGE accepted as kernel options")
	}
	if _, err := measuredOptions(bytes.Repeat([]byte{'a'}, 4097)); err == nil {
		t.Fatal("oversized command line accepted")
	}
}

func TestMeasuredEntryKeepsVendorKernelAndSortsLast(t *testing.T) {
	const action = "12345678-1234-1234-1234-123456789abc"
	layout := &measuredLayout{chain: platform.GRUBChain{Entries: platform.GRUBBLS}, entryID: blsEntryPrefix + action, binding: &agentv1.RecoveryMeasuredBoot{KernelPath: "/boot/vmlinuz-6.19.10-300.fc44.x86_64", InitrdPath: "/boot/lindm-recovery-" + action + ".initrd", KernelOptions: "rdinit=/init panic=10 quiet lindm.recovery.action=" + action}}
	entry := string(layout.entry())
	for _, line := range []string{"linux /boot/vmlinuz-6.19.10-300.fc44.x86_64\n", "initrd /boot/lindm-recovery-" + action + ".initrd\n", "options rdinit=/init panic=10 quiet lindm.recovery.action=" + action + "\n", "grub_arg --unrestricted\n"} {
		if !strings.Contains(entry, line) {
			t.Fatalf("entry lacks %q:\n%s", line, entry)
		}
	}
	if strings.Count(entry, "initrd ") != 1 || !strings.HasPrefix(layout.entryID, "~") {
		t.Fatalf("entry must load one initramfs and sort after vendor entries: %q", layout.entryID)
	}
}

func TestMeasuredCustomConfigEntryLoadsOnlyApprovedPair(t *testing.T) {
	const action = "12345678-1234-1234-1234-123456789abc"
	options := "rdinit=/init panic=10 quiet lindm.recovery.action=" + action
	layout := &measuredLayout{chain: platform.GRUBChain{Entries: platform.GRUBCustomConfig, ConfigDirectory: "grub"}, entryID: customEntryPrefix + action, bootFSUUID: "fb8b4264-587e-4a60-a103-a1d39552f189", binding: &agentv1.RecoveryMeasuredBoot{KernelPath: "/vmlinuz-6.8.0-142-generic", InitrdPath: "/lindm-recovery-" + action + ".initrd", KernelOptions: options}}
	entry := string(layout.entry())
	for _, line := range []string{
		"--unrestricted --id 'lindm-recovery-" + action + "' {\n",
		"\tsearch --no-floppy --fs-uuid --set=root fb8b4264-587e-4a60-a103-a1d39552f189\n",
		"\tlinux ($root)/vmlinuz-6.8.0-142-generic " + options + "\n",
		"\tinitrd ($root)/lindm-recovery-" + action + ".initrd\n}\n",
	} {
		if !strings.Contains(entry, line) {
			t.Fatalf("custom entry lacks %q:\n%s", line, entry)
		}
	}
	if strings.Count(entry, "linux ") != 1 || strings.Count(entry, "initrd ") != 1 || strings.Count(entry, "menuentry ") != 1 {
		t.Fatalf("custom entry must define one kernel and one initramfs:\n%s", entry)
	}
}

func TestMeasuredChainRejectsUnlistedTools(t *testing.T) {
	for _, chain := range []platform.GRUBChain{
		{},
		{Entries: platform.GRUBBLS, Editenv: "/tmp/grub2-editenv"},
		{Entries: platform.GRUBCustomConfig, Editenv: "/usr/bin/grub-editenv", ConfigDirectory: "../grub"},
		{Entries: "systemd-boot", Editenv: "/usr/bin/grub2-editenv"},
	} {
		if validChain(chain) {
			t.Fatalf("unqualified chain accepted: %+v", chain)
		}
	}
	for _, chain := range []platform.GRUBChain{
		{Entries: platform.GRUBBLS, Editenv: "/usr/bin/grub2-editenv", ConfigDirectory: "grub2"},
		{Entries: platform.GRUBCustomConfig, Editenv: "/usr/bin/grub-editenv", ConfigDirectory: "grub"},
	} {
		if !validChain(chain) {
			t.Fatalf("registry chain refused: %+v", chain)
		}
	}
}

func TestBootDeviceUsesLongestContainingMount(t *testing.T) {
	const mountinfo = "22 1 252:3 /root / rw - btrfs /dev/vda3 rw\n" +
		"30 22 252:3 /boot /boot rw - btrfs /dev/vda3 rw\n" +
		"31 30 252:2 / /boot/efi rw - vfat /dev/vda2 rw\n" +
		"40 22 0:5 / /bootx rw - tmpfs tmpfs rw\n"
	for directory, want := range map[string]string{"/boot": "/dev/vda3", "/boot/efi": "/dev/vda2", "/boot/grub2": "/dev/vda3", "/var": "/dev/vda3"} {
		got, err := mountSourceFor(strings.NewReader(mountinfo), directory)
		if err != nil || got != want {
			t.Fatalf("%s: device %q err %v, want %q", directory, got, err, want)
		}
	}
	if _, err := mountSourceFor(strings.NewReader(mountinfo), "/bootx"); err == nil {
		t.Fatal("non-device mount source accepted")
	}
}

func TestMeasuredInitramfsOmitsSignerAndMountsSecurityfs(t *testing.T) {
	dir := t.TempDir()
	input := fixtureIngredient(t, dir, "ingredient", []byte("deterministic-approved-bytes"))
	request := BuildRequest{Kernel: input, Agent: input, Config: input, StateUUID: "12345678-1234-1234-1234-123456789abc", SourceDateEpoch: 1700000000, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB}
	archive := filepath.Join(dir, "measured.cpio")
	closure, err := writeInitramfs(archive, request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(closure, "boot_mode RECOVERY_BOOT_MODE_MEASURED_GRUB\n") || strings.Contains(closure, "image-signing.pem") {
		t.Fatalf("measured closure:\n%s", closure)
	}
	// The Go PID 1 boots measured mode from the vendor kernel without the ESP:
	// its parameters name only the off-target state volume.
	if params := initParamsFor(request).render(); params != initParamsHeader+"\nboot_mode measured_grub\nstate_uuid 12345678-1234-1234-1234-123456789abc\n" {
		t.Fatalf("measured init parameters:\n%s", params)
	}
	file, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("image-signing.pem")) {
		t.Fatal("measured archive embeds a UKI signer")
	}
}

// A grub.d entry finds the separate /boot by its filesystem UUID, taken from
// root-owned udev data for the mounted device number (Ubuntu's ext4 /boot).
func TestBootFilesystemUUIDAcceptsOnlyCanonicalSupportedFilesystems(t *testing.T) {
	const uuid = "5b886046-3262-4eca-a390-4cd88779a3c7"
	got, err := parseBootFilesystemUUID("S:disk/by-uuid/" + uuid + "\nE:ID_FS_TYPE=ext4\nE:ID_FS_UUID=" + uuid + "\nE:ID_FS_LABEL=BOOT\n")
	if err != nil || got != uuid {
		t.Fatalf("boot UUID = %q, %v", got, err)
	}
	for _, invalid := range []string{
		"E:ID_FS_TYPE=vfat\nE:ID_FS_UUID=ABCD-1234\n",
		"E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=5B886046-3262-4ECA-A390-4CD88779A3C7\n",
		"E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=" + uuid + "; reboot\n",
		"E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=" + uuid + "\nE:ID_FS_UUID=" + uuid + "\n",
		"E:ID_FS_TYPE=ext4\n",
	} {
		if _, err := parseBootFilesystemUUID(invalid); err == nil {
			t.Fatalf("unsafe boot filesystem identity accepted: %q", invalid)
		}
	}
}
