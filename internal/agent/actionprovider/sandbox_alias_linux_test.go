//go:build linux

package actionprovider

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// The sandbox drop-in outlives the boot. Natively on RHEL 10.2, the encrypted
// root moved from sda to sdb after a cold boot with a second virtio-SCSI disk,
// and a drop-in naming /dev/sda3 kept the executor from starting. LUKS targets
// are therefore provisioned by their approved UUID alias, which must resolve to
// exactly the identity-verified node at provisioning time.
func TestSandboxTargetPathUsesVerifiedStableAlias(t *testing.T) {
	const uuid = "b9aa47ed-27fa-4355-8185-2f62cf3d0e71"
	luks := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: "0x5000000000000001", Serial: "lindm-lab-0", SizeBytes: 1 << 30, LuksUuid: uuid}
	handle := &targetHandle{node: blockNode{Path: "/dev/sda3", Device: "8:3", UUID: uuid}}
	block := func(major, minor uint32) func(string, *unix.Stat_t) error {
		return func(path string, st *unix.Stat_t) error {
			if path != "/dev/disk/by-uuid/"+uuid {
				t.Fatalf("stat of unexpected alias %q", path)
			}
			st.Mode, st.Rdev = unix.S_IFBLK|0o600, unix.Mkdev(major, minor)
			return nil
		}
	}
	path, err := sandboxTargetPath(luks, handle, block(8, 3))
	if err != nil || path != "/dev/disk/by-uuid/"+uuid {
		t.Fatalf("verified LUKS alias not selected: %q, %v", path, err)
	}
	for name, stat := range map[string]func(string, *unix.Stat_t) error{
		"missing alias": func(string, *unix.Stat_t) error { return unix.ENOENT },
		"renumbered":    block(8, 19),
		"not a block": func(_ string, st *unix.Stat_t) error {
			st.Mode, st.Rdev = unix.S_IFCHR|0o600, unix.Mkdev(8, 3)
			return nil
		},
		"regular file":   func(_ string, st *unix.Stat_t) error { st.Mode = unix.S_IFREG | 0o600; return nil },
		"other disk 8:0": block(8, 0),
	} {
		if _, err := sandboxTargetPath(luks, handle, stat); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: alias accepted or wrong error: %v", name, err)
		}
	}
	plain := &agentv1.StorageTarget{IdentityBasis: luks.GetIdentityBasis(), Wwn: luks.GetWwn(), Serial: luks.GetSerial(), SizeBytes: luks.GetSizeBytes()}
	path, err = sandboxTargetPath(plain, handle, func(string, *unix.Stat_t) error {
		t.Fatal("non-LUKS target has no identity-derived alias to stat")
		return nil
	})
	if err != nil || path != "/dev/sda3" {
		t.Fatalf("non-LUKS target path changed: %q, %v", path, err)
	}
}
