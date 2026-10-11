//go:build linux

package vmlab

import (
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestNVMeUnprivilegedIdentifyKernel(t *testing.T) {
	for release, want := range map[string]bool{
		"5.14.0-611.5.1.el9_7.x86_64":  false,
		"5.15.0-153-generic":           false,
		"6.1.0-40-amd64":               false,
		"6.2.0-39-generic":             true,
		"6.8.0-85-generic":             true,
		"6.12.0-124.8.1.el10_1.x86_64": true,
		"6.19.3-300.fc44.x86_64":       true,
		"7.0.0-34-generic":             true,
	} {
		got, err := nvmeUnprivilegedIdentifyKernel(release)
		if err != nil || got != want {
			t.Fatalf("%s: got %v %v, want %v", release, got, err, want)
		}
	}
	for _, release := range []string{"", "6", "linux-6.8", "6.x"} {
		if _, err := nvmeUnprivilegedIdentifyKernel(release); err == nil {
			t.Fatalf("unparseable release %q accepted", release)
		}
	}
}

func TestNVMeScopeFieldsCoverEveryApprovalField(t *testing.T) {
	scope := &agentv1.NVMeSanitizeScope{NamespaceId: 1, Identity: &agentv1.NVMeSanitizeIdentity{
		Basis: agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID, VendorId: 0x1b36, SubsystemVendorId: 0x1af4,
		ControllerSerial: "lindm-lab-0", ControllerModel: "QEMU NVMe Ctrl", ControllerFirmware: "8.2.2",
		NamespaceSizeBytes: 4 << 30, LbaDataSizeShift: 9,
	}}
	fields := nvmeScopeFields(scope)
	want := map[string]string{
		"namespace_id": "1", "controller_wide": "false",
		"identity.basis": "NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID", "identity.vendor_id": "6966", "identity.subsystem_vendor_id": "6900",
		"identity.controller_serial": "lindm-lab-0", "identity.controller_model": "QEMU NVMe Ctrl", "identity.controller_firmware": "8.2.2",
		"identity.namespace_size_bytes": "4294967296", "identity.lba_data_size_shift": "9",
	}
	if len(fields) != len(want) {
		t.Fatalf("fields = %v", fields)
	}
	for name, value := range want {
		if fields[name] != value {
			t.Fatalf("%s = %q, want %q", name, fields[name], value)
		}
	}
}
