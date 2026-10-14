// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"errors"
	"testing"
	"testing/fstest"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	sysfsNamespace  = "dev/block/259:0"
	sysfsController = sysfsNamespace + "/device"
	sysfsFallback   = "nvme.1b36-6c696e646d2d6c61622d30-51454d55204e564d65204374726c-00000001"
)

var sysfsRdev = unix.Mkdev(259, 0)

func sysfsNVMeFixture(controller string) fstest.MapFS {
	attribute := func(text string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(text + "\n")} }
	return fstest.MapFS{
		sysfsNamespace + "/nsid":                     attribute("1"),
		sysfsNamespace + "/size":                     attribute("8388608"),
		sysfsNamespace + "/queue/logical_block_size": attribute("512"),
		sysfsNamespace + "/wwid":                     attribute(sysfsFallback),
		controller + "/cntlid":                       attribute("0"),
		controller + "/transport":                    attribute("pcie"),
		// Older kernels print the space-padded Identify fields.
		controller + "/serial":                  attribute("lindm-lab-0         "),
		controller + "/model":                   attribute("QEMU NVMe Ctrl                          "),
		controller + "/firmware_rev":            attribute("8.2.2   "),
		controller + "/device/vendor":           attribute("0x1b36"),
		controller + "/device/subsystem_vendor": attribute("0x1af4"),
	}
}

func sysfsTarget(wwn string) *agentv1.StorageTarget {
	return &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: wwn, Serial: "lindm-lab-0", SizeBytes: 4 << 30}
}

func sysfsExpectedScope(basis agentv1.NvmeIdentityBasis) *agentv1.NVMeSanitizeScope {
	return &agentv1.NVMeSanitizeScope{NamespaceId: 1, Identity: &agentv1.NVMeSanitizeIdentity{
		Basis: basis, VendorId: 0x1b36, SubsystemVendorId: 0x1af4,
		ControllerSerial: "lindm-lab-0", ControllerModel: "QEMU NVMe Ctrl", ControllerFirmware: "8.2.2",
		NamespaceSizeBytes: 4 << 30, LbaDataSizeShift: 9,
	}}
}

func TestNVMeSysfsScopeMatchesKernelIdentityProjection(t *testing.T) {
	serial := agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID
	nid := agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID
	head := sysfsNVMeFixture(sysfsNamespace + "/device/nvme0")
	head[sysfsNamespace+"/device/subsysnqn"] = &fstest.MapFile{Data: []byte("nqn.2019-08.org.qemu:lindm-lab-0\n")}
	eui := sysfsNVMeFixture(sysfsController)
	eui[sysfsNamespace+"/wwid"] = &fstest.MapFile{Data: []byte("eui.00112233445566778899aabbccddeeff\n")}
	for _, test := range []struct {
		name  string
		sys   fstest.MapFS
		wwn   string
		basis agentv1.NvmeIdentityBasis
	}{
		{"controller fallback", sysfsNVMeFixture(sysfsController), sysfsFallback, serial},
		{"controller fallback without udev WWN", sysfsNVMeFixture(sysfsController), "", serial},
		{"namespace NID", eui, "eui.00112233445566778899aabbccddeeff", nid},
		{"single-controller multipath head", head, sysfsFallback, serial},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, err := readNVMeSysfsScope(test.sys, sysfsRdev, 4<<30, sysfsTarget(test.wwn), 1)
			if err != nil {
				t.Fatal(err)
			}
			if want := sysfsExpectedScope(test.basis); !proto.Equal(scope, want) {
				t.Fatalf("scope = %v, want %v", scope, want)
			}
			if err := protovalidate.Validate(scope); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNVMeSysfsScopeRefusesAbsentOrInconsistentIdentity(t *testing.T) {
	for _, test := range []struct {
		reason string
		change func(fstest.MapFS)
		target *agentv1.StorageTarget
		nsid   uint32
	}{
		{reason: "nvme_sysfs_partition", change: func(s fstest.MapFS) { s[sysfsNamespace+"/partition"] = &fstest.MapFile{Data: []byte("1\n")} }},
		{reason: "nvme_sysfs_nsid_absent", change: func(s fstest.MapFS) { delete(s, sysfsNamespace+"/nsid") }},
		{reason: "nvme_sysfs_nsid_mismatch", nsid: 2},
		{reason: "nvme_sysfs_controller_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/cntlid") }},
		{reason: "nvme_multiple_controllers", change: func(s fstest.MapFS) {
			delete(s, sysfsController+"/cntlid")
			s[sysfsController+"/nvme0/cntlid"] = &fstest.MapFile{Data: []byte("0\n")}
			s[sysfsController+"/nvme1/cntlid"] = &fstest.MapFile{Data: []byte("1\n")}
		}},
		{reason: "nvme_sysfs_transport_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/transport") }},
		{reason: "nvme_transport_not_pcie", change: func(s fstest.MapFS) { s[sysfsController+"/transport"] = &fstest.MapFile{Data: []byte("tcp\n")} }},
		{reason: "nvme_pci_vendor_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/device/vendor") }},
		{reason: "nvme_vendor_identity_absent", change: func(s fstest.MapFS) {
			s[sysfsController+"/device/vendor"] = &fstest.MapFile{Data: []byte("0x0000\n")}
		}},
		{reason: "nvme_pci_subsystem_vendor_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/device/subsystem_vendor") }},
		{reason: "nvme_sysfs_serial_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/serial") }},
		{reason: "nvme_sysfs_serial_invalid", change: func(s fstest.MapFS) { s[sysfsController+"/serial"] = &fstest.MapFile{Data: []byte("    \n")} }},
		{reason: "nvme_sysfs_model_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/model") }},
		{reason: "nvme_sysfs_firmware_absent", change: func(s fstest.MapFS) { delete(s, sysfsController+"/firmware_rev") }},
		{reason: "nvme_sysfs_firmware_invalid", change: func(s fstest.MapFS) {
			s[sysfsController+"/firmware_rev"] = &fstest.MapFile{Data: []byte("8.2.2\x01\n")}
		}},
		{reason: "nvme_sysfs_block_size_absent", change: func(s fstest.MapFS) { delete(s, sysfsNamespace+"/queue/logical_block_size") }},
		{reason: "nvme_lba_layout", change: func(s fstest.MapFS) {
			s[sysfsNamespace+"/queue/logical_block_size"] = &fstest.MapFile{Data: []byte("8192\n")}
		}},
		{reason: "nvme_sysfs_size_absent", change: func(s fstest.MapFS) { delete(s, sysfsNamespace+"/size") }},
		{reason: "nvme_sysfs_size_mismatch", change: func(s fstest.MapFS) { s[sysfsNamespace+"/size"] = &fstest.MapFile{Data: []byte("0\n")} }},
		{reason: "nvme_exact_identity_changed", target: &agentv1.StorageTarget{Serial: "other", SizeBytes: 4 << 30}},
		{reason: "nvme_sysfs_wwid_absent", change: func(s fstest.MapFS) { delete(s, sysfsNamespace+"/wwid") }},
		{reason: "nvme_uuid_namespace_identity", change: func(s fstest.MapFS) {
			s[sysfsNamespace+"/wwid"] = &fstest.MapFile{Data: []byte("uuid.6f3b1d1e-0c4a-4d6e-9a43-111111111111\n")}
		}},
		// The kernel spells the fallback from Identify VID; a PCI vendor that
		// differs from it is never silently accepted.
		{reason: "nvme_sysfs_identity_inconsistent", change: func(s fstest.MapFS) {
			s[sysfsController+"/device/vendor"] = &fstest.MapFile{Data: []byte("0x8086\n")}
		}},
		{reason: "nvme_namespace_identity_changed", target: sysfsTarget("nvme.other")},
		{reason: "nvme_namespace_identity_changed", change: func(s fstest.MapFS) {
			s[sysfsNamespace+"/wwid"] = &fstest.MapFile{Data: []byte("eui.0011223344556677\n")}
		}},
		{reason: "nvme_sysfs_wwid_invalid", change: func(s fstest.MapFS) { s[sysfsNamespace+"/wwid"] = &fstest.MapFile{Data: []byte("eui.XYZ\n")} }},
	} {
		t.Run(test.reason, func(t *testing.T) {
			sys := sysfsNVMeFixture(sysfsController)
			if test.change != nil {
				test.change(sys)
			}
			target, nsid := test.target, test.nsid
			if target == nil {
				target = sysfsTarget(sysfsFallback)
			}
			if nsid == 0 {
				nsid = 1
			}
			scope, err := readNVMeSysfsScope(sys, sysfsRdev, 4<<30, target, nsid)
			var refusal *NVMeScopeRefusal
			if scope != nil || !errors.As(err, &refusal) || refusal.Reason != test.reason || !errors.Is(err, ErrUnsupported) {
				t.Fatalf("scope=%v err=%v, want refusal %s", scope, err, test.reason)
			}
		})
	}
}
