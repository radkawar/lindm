//go:build linux

package vmlab

import (
	"testing"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/platform"
)

func TestStorageIdentityOracleSeparatesLUKSAndFilesystemUUID(t *testing.T) {
	// Synthetic pairs presentation exercises the independent parser, not a
	// claim that this test booted a guest or captured native media evidence.
	data := []byte(`NAME="sda3" TYPE="part" SIZE="22493003776" FSTYPE="crypto_LUKS" MOUNTPOINT="" MOUNTPOINTS="" PKNAME="sda" KNAME="sda3" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="a6cf314f-4414-41c5-bdc4-e784718bd7d7" FSVER="2" PARTUUID="ab028852-c1e8-4e77-af2e-f52235b83cc4" PARTTYPE="0fc63daf-8483-4772-8e79-3d69d8477de4" PTTYPE="gpt" PTUUID="616f7698-4a4a-4c6c-8543-fc47d344c677"` + "\n")
	storage, err := parseTruthStorage(data, truthSuccess)
	if err != nil {
		t.Fatal(err)
	}
	id := storage.Devices[0].Identity
	if id.GetLuksUuid().GetValue() != "a6cf314f-4414-41c5-bdc4-e784718bd7d7" || id.GetLuksVersion().GetValue() != "2" || id.GetFilesystemUuid().GetStatus() != truthUnavailable || id.GetSerial().GetStatus() != truthUnavailable {
		t.Fatalf("native identity oracle conflated absent or encrypted fields: %v", id)
	}
	// Parsing lsblk alone is not complete LUKS health evidence. Supply the
	// separate native header/topology observations used by a real inspection.
	id.LuksKeyslotCount, id.LuksTokenCount = truthUint(1), truthUint(0)
	id.BackingDisk, id.RootBacking = truthString("sda"), truthBool(true)
	before := nativeDetailsFixture()
	before.Storage = storage
	after := proto.CloneOf(before)
	actual := proto.CloneOf(before)
	if err := compareVMDetails(platform.ForManifest("ubuntu", "24.04"), "x86_64", before, after, actual); err != nil {
		t.Fatal(err)
	}
	actual.Storage.Devices[0].Identity.LuksUuid.Value = "11111111-1111-1111-1111-111111111111"
	if err := compareVMDetails(platform.ForManifest("ubuntu", "24.04"), "x86_64", before, after, actual); err == nil {
		t.Fatal("oracle ignored changed LUKS identity")
	}
	actual = proto.CloneOf(before)
	actual.Storage.Devices[0].Identity = nil
	if err := compareVMDetails(platform.ForManifest("ubuntu", "24.04"), "x86_64", before, after, actual); err == nil {
		t.Fatal("oracle ignored missing storage identity")
	}
}

func TestStorageIdentityOracleResolvesMapperKernelParents(t *testing.T) {
	input := `NAME="crypt-root" TYPE="crypt" SIZE="8192" FSTYPE="" MOUNTPOINT="" MOUNTPOINTS="" PKNAME="" KNAME="dm-0" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="" FSVER="" PARTUUID="" PARTTYPE="" PTTYPE="" PTUUID=""
NAME="root-lv" TYPE="lvm" SIZE="4096" FSTYPE="ext4" MOUNTPOINT="/" MOUNTPOINTS="/" PKNAME="dm-0" KNAME="dm-1" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="root-fs" FSVER="1.0" PARTUUID="" PARTTYPE="" PTTYPE="" PTUUID=""
`
	storage, err := parseTruthStorage([]byte(input), truthSuccess)
	if err != nil {
		t.Fatal(err)
	}
	if storage.Devices[1].Parent.Value != "crypt-root" || storage.Devices[1].Encryption.Value != "inherited-dm-crypt" {
		t.Fatalf("kernel alias lost encrypted ancestry: %v", storage.Devices[1])
	}
}

func TestStorageIdentityOracleGPTUsesOnlyDiskGUID(t *testing.T) {
	const guid = "616f7698-4a4a-4c6c-8543-fc47d344c677"
	for _, kind := range []string{"disk", "part", "crypt"} {
		id := storageTruthIdentity(map[string]string{"TYPE": kind, "PTTYPE": "gpt", "PTUUID": guid, "PARTUUID": "not-a-disk-guid"})
		if id.GptDiskGuid == nil {
			t.Fatal("missing GPT availability")
		}
		if kind == "disk" {
			if id.GptDiskGuid.Status != truthSuccess || id.GptDiskGuid.Value != guid {
				t.Fatalf("lost disk GUID: %v", id.GptDiskGuid)
			}
		} else if id.GptDiskGuid.Status != truthUnavailable {
			t.Fatal("partition table field inherited without backing-disk proof")
		}
	}
	invalid := storageTruthIdentity(map[string]string{"TYPE": "disk", "PTTYPE": "gpt", "PTUUID": "invalid"})
	if invalid.GptDiskGuid.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT {
		t.Fatal("invalid native GPT GUID accepted")
	}
}

func TestStorageTruthRetainsRootAmongMultipleMounts(t *testing.T) {
	// Synthetic native pairs reproducing Fedora44 ARM's Btrfs layout:
	// MOUNTPOINT selected /var while the same device also supplies /.
	input := `NAME="vda2" TYPE="part" SIZE="5262786048" FSTYPE="btrfs" MOUNTPOINT="/var" MOUNTPOINTS="/var\x0a/" PKNAME="vda" KNAME="vda2" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="" FSVER="" PARTUUID="" PARTTYPE="" PTTYPE="" PTUUID=""
`
	storage, err := parseTruthStorage([]byte(input), truthSuccess)
	if err != nil {
		t.Fatal(err)
	}
	if mount := storage.Devices[0].Mountpoint; mount.Status != truthSuccess || mount.Value != "/" {
		t.Fatalf("root mount hidden by another subvolume: %v", mount)
	}
}
