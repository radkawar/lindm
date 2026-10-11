//go:build linux

package vmlab

import "testing"

// rocky102-arm64-dgx20-recovery-nvme-01/-02 failed after the owned reboot with
// "guest operation emitted unexpected stderr"; -03 captured it: systemd 257's
// bootctl status, exit 0, warning on the grub-only keys of the vendor's own
// BLS entries. Those notices are admitted; every other diagnostic still fails.
func TestOwnedBootStatusAdmitsOnlyBLSUnknownKeyNotices(t *testing.T) {
	captured := "/boot/loader/entries/1d349827085342da994400280f0d7183-0-rescue.conf:6: Unknown line 'grub_users', ignoring.\n" +
		"/boot/loader/entries/1d349827085342da994400280f0d7183-0-rescue.conf:7: Unknown line 'grub_arg', ignoring.\n" +
		"/boot/loader/entries/1d349827085342da994400280f0d7183-0-rescue.conf:8: Unknown line 'grub_class', ignoring.\n" +
		"/boot/loader/entries/1d349827085342da994400280f0d7183-6.12.0-211.16.1.el10_2.0.1.aarch64.conf:6: Unknown line 'grub_users', ignoring.\n" +
		"/boot/loader/entries/1d349827085342da994400280f0d7183-6.12.0-211.16.1.el10_2.0.1.aarch64.conf:7: Unknown line 'grub_arg', ignoring.\n" +
		"/boot/loader/entries/1d349827085342da994400280f0d7183-6.12.0-211.16.1.el10_2.0.1.aarch64.conf:8: Unknown line 'grub_class', ignoring.\n"
	for _, stderr := range []string{"", captured} {
		if err := ownedBootStatusNotices([]byte(stderr)); err != nil {
			t.Fatalf("admitted notices refused: %v", err)
		}
	}
	for name, stderr := range map[string]string{
		"sudo":             "sudo: unable to resolve host lindm-lab: Name or service not known\n",
		"esp":              "Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.\n",
		"random seed":      "Mount point '/boot/efi' which backs the random seed file is world accessible, which is a security hole!\n",
		"other directory":  "/boot/efi/loader/entries/x.conf:6: Unknown line 'grub_users', ignoring.\n",
		"different notice": "/boot/loader/entries/x.conf:6: Failed to parse line, ignoring.\n",
		"trailing text":    "/boot/loader/entries/x.conf:6: Unknown line 'grub_users', ignoring. extra\n",
		"mixed":            captured + "bootctl: Failed to read EFI variable LoaderInfo: Permission denied\n",
	} {
		if err := ownedBootStatusNotices([]byte(stderr)); err == nil {
			t.Errorf("%s: unexpected bootctl stderr admitted", name)
		}
	}
}
