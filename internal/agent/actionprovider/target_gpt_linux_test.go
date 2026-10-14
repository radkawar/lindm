// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func fallbackIdentityFixture() (*agentv1.StorageTarget, []blockNode) {
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS, Serial: "lindm-demo-encrypted", GptDiskGuid: "616f7698-4a4a-4c6c-8543-fc47d344c677", DiskSizeBytes: 25769803776, SizeBytes: 22493003776, LuksUuid: "f393f8b5-f6bf-41a0-81fd-736cf10b6d9d"}
	return target, []blockNode{{Path: "/dev/vda", Type: "disk", Device: "252:0", Serial: target.Serial, Size: target.DiskSizeBytes, PartitionTable: "gpt", DiskGUID: target.GptDiskGuid, Children: []blockNode{{Path: "/dev/vda3", Type: "part", Device: "252:3", Size: target.SizeBytes, UUID: target.LuksUuid, Filesystem: "crypto_LUKS"}}}}
}

func TestVirtioStorageIdentityFallback(t *testing.T) {
	for _, variant := range []string{"virtio-no-wwn", "duplicate-serial-different-guid", "duplicate-luks", "wwn-appeared", "approved-wwn-disappeared", "basis-downgrade", "guid-changed", "disk-size-changed", "luks-changed", "wwn-unreadable", "partition-not-disk-child"} {
		t.Run(variant, func(t *testing.T) {
			target, nodes := fallbackIdentityFixture()
			evidence := sysfsBlockIdentity{BlockSerial: sysfsIdentityValue{Value: target.Serial}}
			switch variant {
			case "duplicate-serial-different-guid":
				nodes = append(nodes, blockNode{Type: "disk", Device: "252:16", Serial: target.Serial, Size: 4096, PartitionTable: "gpt", DiskGUID: "different"})
			case "duplicate-luks":
				nodes[0].Children = append(nodes[0].Children, nodes[0].Children[0])
			case "wwn-appeared":
				nodes[0].WWN = "now-present"
			case "approved-wwn-disappeared":
				target.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL
				target.Wwn = "approved-wwn"
				target.GptDiskGuid, target.DiskSizeBytes = "", 0
			case "basis-downgrade":
				target.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL
			case "guid-changed":
				nodes[0].DiskGUID = "changed"
			case "disk-size-changed":
				nodes[0].Size++
			case "luks-changed":
				nodes[0].Children[0].UUID = fixtureLUKS
			case "wwn-unreadable":
				evidence.WWID.Error = "unavailable"
			case "partition-not-disk-child":
				nodes = append(nodes, nodes[0].Children[0])
				nodes[0].Children = nil
			}
			selected, disk, diagnostic := resolveTargetIdentity(nodes, target, false, func(string) sysfsBlockIdentity { return evidence })
			want := variant == "virtio-no-wwn"
			if (selected != nil) != want || (disk != nil) != want {
				t.Fatalf("incorrect fallback selection: %s", diagnostic.encode())
			}
		})
	}
}

func TestStorageIdentityBasisValidationAndAllowlist(t *testing.T) {
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	approved, _ := fallbackIdentityFixture()
	if err := validator.Validate(approved); err != nil {
		t.Fatalf("complete fallback rejected: %v", err)
	}
	provider := &Provider{config: &agentv1.DeviceActionProviderConfig{Targets: []*agentv1.QualifiedActionTarget{{Target: approved}}}}
	for _, field := range []string{"basis", "wwn", "serial", "guid", "disk-size", "luks"} {
		t.Run(field, func(t *testing.T) {
			changed := proto.CloneOf(approved)
			switch field {
			case "basis":
				changed.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_UNSPECIFIED
			case "wwn":
				changed.Wwn = "new-wwn"
			case "serial":
				changed.Serial = ""
			case "guid":
				changed.GptDiskGuid = ""
			case "disk-size":
				changed.DiskSizeBytes = 0
			case "luks":
				changed.LuksUuid = ""
			}
			if validator.Validate(changed) == nil {
				t.Fatal("incomplete or downgraded identity accepted")
			}
			if _, err := provider.qualified(changed); err == nil {
				t.Fatal("changed signed identity matched allowlist")
			}
		})
	}
}

func TestPinnedGPTDiskGUID(t *testing.T) {
	for _, sector := range []int{512, 4096} {
		data := make([]byte, 2*sector)
		header := data[sector:]
		copy(header, "EFI PART")
		binary.LittleEndian.PutUint32(header[8:12], 0x10000)
		binary.LittleEndian.PutUint32(header[12:16], 92)
		binary.LittleEndian.PutUint64(header[24:32], 1)
		copy(header[56:72], []byte{0x98, 0x76, 0x6f, 0x61, 0x4a, 0x4a, 0x6c, 0x4c, 0x85, 0x43, 0xfc, 0x47, 0xd3, 0x44, 0xc6, 0x77})
		binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:92]))
		guid, err := readGPTDiskGUID(bytes.NewReader(data), sector)
		if err != nil || guid != "616f7698-4a4a-4c6c-8543-fc47d344c677" {
			t.Fatalf("native GUID: %q %v", guid, err)
		}
		header[56]++
		if _, err := readGPTDiskGUID(bytes.NewReader(data), sector); err == nil {
			t.Fatal("corrupt GPT header accepted")
		}
	}
}
