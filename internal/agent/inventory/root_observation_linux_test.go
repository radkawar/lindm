// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestUploadHostDoesNotReadPrivilegedSerial(t *testing.T) {
	read := func(path string) ([]byte, error) {
		switch path {
		case "/sys/class/dmi/id/product_serial":
			t.Fatal("network process attempted root-only DMI serial")
		case "/sys/class/dmi/id/sys_vendor":
			return []byte("public vendor\n"), nil
		case "/sys/class/dmi/id/product_name":
			return []byte("public model\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	host, _ := collectHost(t.Context(), read, true)
	if host.HardwareSerial.Status != unavailable || host.HardwareSerial.Value != "" || host.HardwareVendor.Value != "public vendor" || host.HardwareModel.Value != "public model" {
		t.Fatal("upload host lost public DMI fields or invented a serial")
	}
}

func TestUploadDetailsDoNotProbePrivilegedFirmwareOrCPUModel(t *testing.T) {
	sources := fixtureDetails(t.TempDir())
	sources.rootObservation = true
	read, stat := sources.readFile, sources.stat
	sources.readFile = func(path string) ([]byte, error) {
		if strings.HasPrefix(path, "/sys/firmware/") {
			t.Fatalf("network process read privileged firmware: %s", path)
		}
		if path == "/proc/cpuinfo" {
			return armCPUFixture("0xd0c"), nil
		}
		if strings.HasPrefix(path, "/sys/devices/system/cpu/") {
			return []byte("0\n"), nil
		}
		return read(path)
	}
	sources.stat = func(path string) (fs.FileInfo, error) {
		if strings.HasPrefix(path, "/sys/firmware/") {
			t.Fatalf("network process probed privileged firmware: %s", path)
		}
		return stat(path)
	}
	details := collectDetails(t.Context(), sources)
	if details.Firmware.Mode.Status != unavailable || details.Firmware.SecureBoot.Status != unavailable {
		t.Fatal("network process fabricated firmware evidence")
	}
	if details.Cpu.Model.Status != success || details.Cpu.ModelSource.Value != "arm_midr_procfs" || details.Cpu.LogicalCores.Value != 1 {
		t.Fatal("network process discarded independent public ARM CPU evidence")
	}
}

func TestRootProjectionPreservesNativeSerialAndFirmwareStates(t *testing.T) {
	const boot = "25eec0a2-bb9f-42bc-b6cc-0508320c960e"
	for _, tc := range []struct {
		name             string
		serial           string
		serialErr        error
		efi              bool
		secureBoot       []byte
		secureBootErr    error
		wantSerial       inventoryv1.CollectionStatus
		wantMode         string
		wantSecureBoot   string
		wantSecureStatus inventoryv1.CollectionStatus
	}{
		{name: "blank_serial_bios", serial: "\n", wantSerial: unavailable, wantMode: "bios", wantSecureStatus: unavailable},
		{name: "uefi_enabled", serial: "real serial\n", efi: true, secureBoot: []byte{6, 0, 0, 0, 1}, wantSerial: success, wantMode: "uefi", wantSecureBoot: "enabled", wantSecureStatus: success},
		{name: "uefi_disabled", serial: "real serial\n", efi: true, secureBoot: []byte{6, 0, 0, 0, 0}, wantSerial: success, wantMode: "uefi", wantSecureBoot: "disabled", wantSecureStatus: success},
		{name: "caller_denied", serialErr: fs.ErrPermission, efi: true, secureBootErr: fs.ErrPermission, wantSerial: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, wantMode: "uefi", wantSecureStatus: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED},
		{name: "missing", serialErr: fs.ErrNotExist, efi: true, secureBootErr: fs.ErrNotExist, wantSerial: unavailable, wantMode: "uefi", wantSecureStatus: unavailable},
		{name: "malformed", serial: "bad\x00serial", efi: true, secureBoot: []byte{1}, wantSerial: invalid, wantMode: "uefi", wantSecureStatus: invalid},
		{name: "oversized_serial", serial: strings.Repeat("x", 4097), wantSerial: invalid, wantMode: "bios", wantSecureStatus: unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.efi {
				if err := os.MkdirAll(filepath.Join(root, "sys/firmware/efi"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			sources := fixtureDetails(root)
			sources.readFile = func(path string) ([]byte, error) {
				switch path {
				case "/sys/class/dmi/id/product_serial":
					return []byte(tc.serial), tc.serialErr
				case "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c":
					return tc.secureBoot, tc.secureBootErr
				default:
					return nil, fs.ErrNotExist
				}
			}
			before := time.Now()
			got := collectRootObservation(t.Context(), boot, sources)
			if got.BootId != boot || got.StartedAt.AsTime().Before(before) || got.FinishedAt.AsTime().After(time.Now()) {
				t.Fatal("root projection lost boot or collection timestamps")
			}
			if got.HardwareSerial.Status != tc.wantSerial || got.Firmware.Mode.Value != tc.wantMode || got.Firmware.SecureBoot.Value != tc.wantSecureBoot || got.Firmware.SecureBoot.Status != tc.wantSecureStatus {
				t.Fatalf("incorrect native root evidence: %v", got)
			}
			if err := protovalidate.Validate(got); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRootProjectionHonorsExpiredDeadline(t *testing.T) {
	sources := fixtureDetails(t.TempDir())
	sources.readFile = func(string) ([]byte, error) {
		t.Fatal("expired collection attempted native read")
		return nil, nil
	}
	sources.stat = func(string) (fs.FileInfo, error) {
		t.Fatal("expired collection attempted native stat")
		return nil, nil
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	got := collectRootObservation(ctx, "25eec0a2-bb9f-42bc-b6cc-0508320c960e", sources)
	const timeout = inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT
	if got.HardwareSerial.Status != timeout || got.Firmware.Mode.Status != timeout || got.Firmware.SecureBoot.Status != timeout || got.Storage.Status != timeout ||
		got.Cpu.Model.Status != timeout || got.Cpu.ModelSource.Status != timeout || got.Cpu.LogicalCores.Status != timeout || got.Cpu.PhysicalCores.Status != timeout || got.Cpu.X86_64Level.Status != timeout {
		t.Fatalf("expired deadline became native evidence: %v", got)
	}
}

func TestRootProjectionPreservesNativeCPUStates(t *testing.T) {
	const denied = inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	for _, tc := range []struct {
		name        string
		cpuInfo     []byte
		cpuErr      error
		dmi         []byte
		dmiErr      error
		wantModel   string
		wantSource  string
		wantStatus  inventoryv1.CollectionStatus
		wantCounts  inventoryv1.CollectionStatus
		wantDMIRead bool
	}{
		{name: "arm_smbios", cpuInfo: armCPUFixture("0xd0c"), dmi: cpuType4Fixture("Native ARM processor"), wantModel: "Native ARM processor", wantSource: "smbios_type4", wantStatus: success, wantCounts: success, wantDMIRead: true},
		{name: "arm_midr", cpuInfo: armCPUFixture("0xd0c"), dmiErr: fs.ErrNotExist, wantSource: "arm_midr_procfs", wantStatus: success, wantCounts: success, wantDMIRead: true},
		{name: "arm_smbios_denied", cpuInfo: armCPUFixture("0xd0c"), dmiErr: fs.ErrPermission, wantStatus: denied, wantCounts: success, wantDMIRead: true},
		{name: "arm_smbios_malformed", cpuInfo: armCPUFixture("0xd0c"), dmi: []byte{4, 2, 0, 0}, wantStatus: invalid, wantCounts: success, wantDMIRead: true},
		{name: "arm_smbios_oversized", cpuInfo: armCPUFixture("0xd0c"), dmi: make([]byte, maxDetailFile+1), wantStatus: capacity, wantCounts: success, wantDMIRead: true},
		{name: "x86_proc", cpuInfo: detailFixture(t, "cpuinfo.txt"), wantModel: "13th Gen Intel(R) Core(TM) i7-13700K", wantSource: "proc_cpuinfo", wantStatus: success, wantCounts: success},
		{name: "missing_cpuinfo", cpuErr: fs.ErrNotExist, wantStatus: unavailable, wantCounts: unavailable},
		{name: "denied_cpuinfo", cpuErr: fs.ErrPermission, wantStatus: denied, wantCounts: denied},
		{name: "invalid_cpuinfo", cpuInfo: []byte("processor: invalid\n"), wantStatus: invalid, wantCounts: invalid},
		{name: "oversized_cpuinfo", cpuInfo: make([]byte, maxDetailFile+1), wantStatus: capacity, wantCounts: capacity},
		{name: "oversized_model", cpuInfo: []byte("processor: 0\nmodel name: " + strings.Repeat("x", 4097) + "\nphysical id: 0\ncore id: 0\n"), wantStatus: invalid, wantCounts: success},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := fixtureDetails(t.TempDir())
			// Root collection must not inherit network-process deferral.
			sources.rootObservation = true
			dmiReads := 0
			sources.readFile = func(path string) ([]byte, error) {
				switch path {
				case "/proc/cpuinfo":
					return tc.cpuInfo, tc.cpuErr
				case "/sys/firmware/dmi/tables/DMI":
					dmiReads++
					return tc.dmi, tc.dmiErr
				}
				if strings.HasPrefix(path, "/sys/devices/system/cpu/") {
					return []byte("0\n"), nil
				}
				return nil, fs.ErrNotExist
			}
			root := collectRootObservation(t.Context(), "25eec0a2-bb9f-42bc-b6cc-0508320c960e", sources)
			cpu := root.GetCpu()
			if cpu.GetModel().GetStatus() != tc.wantStatus || cpu.GetModelSource().GetStatus() != tc.wantStatus ||
				cpu.GetModelSource().GetValue() != tc.wantSource || cpu.GetLogicalCores().GetStatus() != tc.wantCounts ||
				cpu.GetPhysicalCores().GetStatus() != tc.wantCounts {
				t.Fatalf("root CPU lost native states or provenance: %v", cpu)
			}
			if tc.wantModel != "" && cpu.Model.Value != tc.wantModel {
				t.Fatalf("root CPU model=%q, want %q", cpu.Model.Value, tc.wantModel)
			}
			if (dmiReads != 0) != tc.wantDMIRead || dmiReads > 1 {
				t.Fatalf("root CPU read privileged DMI %d times", dmiReads)
			}
			if err := protovalidate.Validate(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStandaloneDetailsRetainCallerCPUPrivilege(t *testing.T) {
	sources := fixtureDetails(t.TempDir())
	dmiReads := 0
	sources.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/cpuinfo":
			return armCPUFixture("0xd0c"), nil
		case "/sys/firmware/dmi/tables/DMI":
			dmiReads++
			return nil, fs.ErrPermission
		}
		if strings.HasPrefix(path, "/sys/devices/system/cpu/") {
			return []byte("0\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	details := collectDetails(t.Context(), sources)
	const denied = inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	if dmiReads != 1 || details.Cpu.Model.Status != denied || details.Cpu.ModelSource.Status != denied ||
		details.Cpu.LogicalCores.Status != success || details.Cpu.PhysicalCores.Status != success {
		t.Fatal("standalone collection escalated or hid the caller's denied CPU model probe")
	}
}
