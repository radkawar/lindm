// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

func testVPDSerial(serial string) []byte {
	data := make([]byte, 4+len(serial))
	data[1] = 0x80
	binary.BigEndian.PutUint16(data[2:4], uint16(len(serial)))
	copy(data[4:], serial)
	return data
}

func TestReadSysfsBlockIdentityUsesOnlyCanonicalDeviceNumbers(t *testing.T) {
	for _, device := range []string{"", "../8:0", "8:0/../../x", "8", "8:0:1", "+8:0", "08:0", "8:00", "4294967296:0"} {
		t.Run(device, func(t *testing.T) {
			identity := readSysfsBlockIdentity(device, func(string) ([]byte, error) {
				t.Fatal("invalid device number reached filesystem")
				return nil, nil
			})
			if identity.WWID.Error != "invalid_device_number" || identity.DeviceWWID.Error != "invalid_device_number" || identity.Serial.Error != "invalid_device_number" || identity.VPDSerial.Error != "invalid_device_number" {
				t.Fatalf("invalid number accepted: %+v", identity)
			}
		})
	}
}

func TestReadSysfsBlockIdentityPreservesNativeEvidence(t *testing.T) {
	for _, bus := range []string{"sata", "nvme"} {
		t.Run(bus, func(t *testing.T) {
			files := map[string][]byte{}
			if bus == "sata" {
				files["device/wwid"] = []byte("naa.5000000000000001\n")
				files["device/vpd_pg80"] = testVPDSerial("lindm-lab-0          ")
			} else {
				files["wwid"] = []byte("nvme.1b36-6c696e646d2d6c61622d30-51454d55204e564d65204374726c-00000001\n")
				files["device/serial"] = []byte("lindm-lab-0          \n")
			}
			identity := readSysfsBlockIdentity("8:16", func(path string) ([]byte, error) {
				attribute, ok := strings.CutPrefix(path, "/sys/dev/block/8:16/")
				if !ok {
					t.Fatalf("unexpected native source path %q", path)
				}
				if value, ok := files[attribute]; ok {
					return value, nil
				}
				return nil, os.ErrNotExist
			})
			if bus == "sata" {
				if identity.DeviceWWID.Value != "naa.5000000000000001" || identity.VPDSerial.Value != "lindm-lab-0" || identity.WWID.Error != "absent" || identity.Serial.Error != "absent" {
					t.Fatalf("lost SATA native evidence: %+v", identity)
				}
			} else if identity.WWID.Value != strings.TrimSpace(string(files["wwid"])) || identity.Serial.Value != "lindm-lab-0" || identity.DeviceWWID.Error != "absent" || identity.VPDSerial.Error != "absent" {
				t.Fatalf("lost NVMe native evidence: %+v", identity)
			}
		})
	}
}

func TestReadSysfsBlockIdentityRejectsMalformedVPDSerial(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		{0, 0x80, 0},
		{0, 0x81, 0, 1, 'a'},
		{5, 0x80, 0, 1, 'a'},
		{0, 0x80, 0, 2, 'a'},
		{0, 0x80, 0, 0, 'a'},
		testVPDSerial("ab\x00cd"),
		testVPDSerial("ab\ncd"),
		testVPDSerial("\nleading"),
		testVPDSerial("trailing\n"),
		testVPDSerial("ab\xffcd"),
		testVPDSerial("    "),
		testVPDSerial(strings.Repeat("x", 4096)),
	} {
		identity := readSysfsBlockIdentity("8:0", func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/device/vpd_pg80") {
				return data, nil
			}
			return nil, errors.New("private native error")
		})
		if identity.VPDSerial.Value != "" || identity.VPDSerial.Error == "" || identity.WWID.Error != "unavailable" {
			t.Fatalf("invalid native identity accepted: %+v", identity)
		}
	}
}

func TestSCSIWWNUsesOnlyExactNativeNAAOrEUIBytes(t *testing.T) {
	for _, test := range []struct {
		native string
		want   string
	}{
		{"naa.5000000000000001", "0x5000000000000001"},
		{"naa.60000000000000010000000000000002", "0x60000000000000010000000000000002"},
		{"eui.0011223344556677", "0x0011223344556677"},
		{"0x5000000000000001", ""},
		{"t10.ATA_QEMU_HARDDISK_lindm-lab-0", ""},
		{"naa.500000000000001", ""},
		{"naa.500000000000000z", ""},
		{"NAA.5000000000000001", ""},
		{"naa.500000000000000A", ""},
		{"nvme.1b36-serial-model-00000001", ""},
	} {
		if got := scsiWWN(test.native); got != test.want {
			t.Fatalf("native WWID %q: got %q want %q", test.native, got, test.want)
		}
	}
}

func TestResolveBlockIdentityCanonicalizesOnlyNativeSerialPadding(t *testing.T) {
	for _, test := range []struct {
		name   string
		serial string
		native sysfsBlockIdentity
		want   string
		fail   bool
	}{
		{"NVMe padding", "serial      ", sysfsBlockIdentity{WWID: sysfsIdentityValue{Value: "eui.0011223344556677"}, Serial: sysfsIdentityValue{Value: "serial"}}, "serial", false},
		{"virtio block serial", "", sysfsBlockIdentity{BlockSerial: sysfsIdentityValue{Value: "virtio-serial"}}, "virtio-serial", false},
		{"conflicting virtio serial", "", sysfsBlockIdentity{BlockSerial: sysfsIdentityValue{Value: "virtio-serial"}, Serial: sysfsIdentityValue{Value: "other"}}, "", true},
		{"without native evidence", "serial      ", sysfsBlockIdentity{}, "serial      ", false},
		{"leading space", " serial", sysfsBlockIdentity{WWID: sysfsIdentityValue{Value: "eui.0011223344556677"}, Serial: sysfsIdentityValue{Value: "serial"}}, "", true},
		{"tab", "serial\t", sysfsBlockIdentity{WWID: sysfsIdentityValue{Value: "eui.0011223344556677"}, Serial: sysfsIdentityValue{Value: "serial"}}, "", true},
		{"different native serial", "serial      ", sysfsBlockIdentity{WWID: sysfsIdentityValue{Value: "eui.0011223344556677"}, Serial: sysfsIdentityValue{Value: "other"}}, "", true},
		{"conflicting native serials", "", sysfsBlockIdentity{Serial: sysfsIdentityValue{Value: "serial"}, VPDSerial: sysfsIdentityValue{Value: "other"}}, "", true},
		{"conflicting native WWNs", "", sysfsBlockIdentity{WWID: sysfsIdentityValue{Value: "eui.0011223344556677"}, DeviceWWID: sysfsIdentityValue{Value: "naa.5000000000000001"}}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := blockNode{Serial: test.serial}
			reason := resolveBlockIdentity(&node, test.native)
			if (reason != "") != test.fail || !test.fail && node.Serial != test.want {
				t.Fatalf("unexpected serial canonicalization: %q %+v", reason, node)
			}
		})
	}
}

func TestNativeBlockIdentityMustRemainPresentAfterDescriptorPin(t *testing.T) {
	for _, bus := range []string{"sata", "nvme"} {
		t.Run(bus, func(t *testing.T) {
			target, nodes, native := recoveryIdentityFixture(bus)
			identity := native[nodes[0].Device]
			node := nodes[0]
			if reason := resolveBlockIdentity(&node, identity); reason != "" || node.WWN != target.Wwn || node.Serial != target.Serial {
				t.Fatalf("fixture identity failed: %s", reason)
			}
			if !sameNativeBlockIdentity(node, identity) {
				t.Fatal("unchanged pinned native identity refused")
			}
			if sameNativeBlockIdentity(node, sysfsBlockIdentity{}) {
				t.Fatal("disappeared native identity accepted from prior observation")
			}
			for _, serialOnly := range []bool{false, true} {
				changed := identity
				if serialOnly {
					changed.Serial, changed.VPDSerial = sysfsIdentityValue{}, sysfsIdentityValue{}
				} else {
					changed.WWID, changed.DeviceWWID = sysfsIdentityValue{}, sysfsIdentityValue{}
				}
				if sameNativeBlockIdentity(node, changed) {
					t.Fatal("incomplete pinned native identity accepted")
				}
			}
			if sameNativeBlockIdentity(node, native[nodes[1].Device]) {
				t.Fatal("state disk substituted for pinned approved target")
			}
		})
	}
}

func TestReadVirtioSerialFromBlockDevice(t *testing.T) {
	identity := readSysfsBlockIdentity("252:0", func(path string) ([]byte, error) {
		if path == "/sys/dev/block/252:0/serial" {
			return []byte("lindm-demo-encrypted\n"), nil
		}
		return nil, os.ErrNotExist
	})
	node := blockNode{}
	if reason := resolveBlockIdentity(&node, identity); reason != "" || node.Serial != "lindm-demo-encrypted" || !absentNativeWWN(identity) {
		t.Fatalf("virtio identity unavailable: %q %+v", reason, identity)
	}
	if !sameNativeBlockIdentity(node, identity) || sameNativeBlockIdentity(node, sysfsBlockIdentity{}) {
		t.Fatal("pinned virtio serial was not rechecked")
	}
}
