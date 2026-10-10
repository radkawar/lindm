//go:build linux

package vmlab

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestStorageIdentityOracleSeparatesLUKSAndFilesystemUUID(t *testing.T) {
	// Synthetic pairs presentation exercises the independent parser, not a
	// claim that this test booted a guest or captured native media evidence.
	data := []byte(`NAME="sda3" TYPE="part" SIZE="22493003776" FSTYPE="crypto_LUKS" MOUNTPOINT="" PKNAME="sda" KNAME="sda3" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="a6cf314f-4414-41c5-bdc4-e784718bd7d7" FSVER="2" PARTUUID="ab028852-c1e8-4e77-af2e-f52235b83cc4" PARTTYPE="0fc63daf-8483-4772-8e79-3d69d8477de4"` + "\n")
	storage, err := parseTruthStorage(data, truthSuccess)
	if err != nil {
		t.Fatal(err)
	}
	id := storage.Devices[0].Identity
	if id.GetLuksUuid().GetValue() != "a6cf314f-4414-41c5-bdc4-e784718bd7d7" || id.GetLuksVersion().GetValue() != "2" || id.GetFilesystemUuid().GetStatus() != truthUnavailable || id.GetSerial().GetStatus() != truthUnavailable {
		t.Fatalf("native identity oracle conflated absent or encrypted fields: %v", id)
	}
	before := nativeDetailsFixture()
	before.Storage = storage
	after := proto.CloneOf(before)
	actual := proto.CloneOf(before)
	if err := compareVMDetails(before, after, actual); err != nil {
		t.Fatal(err)
	}
	actual.Storage.Devices[0].Identity.LuksUuid.Value = "11111111-1111-1111-1111-111111111111"
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("oracle ignored changed LUKS identity")
	}
	actual = proto.CloneOf(before)
	actual.Storage.Devices[0].Identity = nil
	if err := compareVMDetails(before, after, actual); err == nil {
		t.Fatal("oracle ignored missing storage identity")
	}
}

func TestStorageIdentityOracleResolvesMapperKernelParents(t *testing.T) {
	input := `NAME="crypt-root" TYPE="crypt" SIZE="8192" FSTYPE="" MOUNTPOINT="" PKNAME="" KNAME="dm-0" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="" FSVER="" PARTUUID="" PARTTYPE=""
NAME="root-lv" TYPE="lvm" SIZE="4096" FSTYPE="ext4" MOUNTPOINT="/" PKNAME="dm-0" KNAME="dm-1" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="root-fs" FSVER="1.0" PARTUUID="" PARTTYPE=""
`
	storage, err := parseTruthStorage([]byte(input), truthSuccess)
	if err != nil {
		t.Fatal(err)
	}
	if storage.Devices[1].Parent.Value != "crypt-root" || storage.Devices[1].Encryption.Value != "inherited-dm-crypt" {
		t.Fatalf("kernel alias lost encrypted ancestry: %v", storage.Devices[1])
	}
}
