// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Constructed native-format parser fixtures; captured host evidence is tested
// separately so malformed tables never masquerade as a real machine capture.
func cpuType4Fixture(version string) []byte {
	data := make([]byte, 0x1a)
	data[0], data[1], data[0x10], data[0x18] = 4, 0x1a, 1, 0x41
	data = append(data, version...)
	return append(data, 0, 0)
}

func armCPUFixture(parts ...string) []byte {
	var data strings.Builder
	for i, part := range parts {
		fmt.Fprintf(&data, "processor : %d\nFeatures : fp asimd\nCPU implementer : 0x41\nCPU architecture : 8\nCPU part : %s\n\n", i, part)
	}
	return []byte(data.String())
}

func TestSMBIOSCPUModel(t *testing.T) {
	end := []byte{127, 4, 0xff, 0xff, 0, 0}
	for _, tt := range []struct {
		name string
		data []byte
		want string
		err  error
	}{
		{"native version", append(cpuType4Fixture("NVIDIA Grace"), end...), "NVIDIA Grace", nil},
		{"trim version", cpuType4Fixture("  Neoverse-V2  "), "Neoverse-V2", nil},
		{"mixed sorted", append(cpuType4Fixture("Zeta CPU"), cpuType4Fixture("Alpha CPU")...), "Alpha CPU; Zeta CPU", nil},
		{"same sockets", append(cpuType4Fixture("Grace"), cpuType4Fixture("Grace")...), "Grace", nil},
		{"placeholder", cpuType4Fixture("Not Specified"), "", fs.ErrNotExist},
		{"partial versions", append(cpuType4Fixture("Grace"), cpuType4Fixture("Unknown")...), "", fs.ErrNotExist},
		{"no processors", end, "", fs.ErrNotExist},
		{"empty table", nil, "", errInvalid},
		{"short header", []byte{4, 0x1a, 0}, "", errInvalid},
		{"short formatted", []byte{4, 3, 0, 0, 0, 0}, "", errInvalid},
		{"overrun formatted", []byte{4, 0xff, 0, 0, 0, 0}, "", errInvalid},
		{"short type4", []byte{4, 4, 0, 0, 0, 0}, "", errInvalid},
		{"unterminated strings", cpuType4Fixture("Grace")[:30], "", errInvalid},
		{"corrupt suffix", append(cpuType4Fixture("Grace"), 9), "", errInvalid},
		{"after end", append(append(cpuType4Fixture("Grace"), end...), 9), "", errInvalid},
		{"invalid UTF8", cpuType4Fixture("bad\xff"), "", errInvalid},
		{"control character", cpuType4Fixture("bad\nmodel"), "", errInvalid},
		{"oversize version", cpuType4Fixture(strings.Repeat("a", 4097)), "", errCapacity},
		{"oversize table", make([]byte, maxDetailFile+1), "", errCapacity},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSMBIOSCPUModel(tt.data)
			if got != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("model=%q err=%v, want %q %v", got, err, tt.want, tt.err)
			}
		})
	}
	for _, index := range []byte{2, 255} {
		data := cpuType4Fixture("Grace")
		data[0x10] = index
		if _, err := parseSMBIOSCPUModel(data); !errors.Is(err, errInvalid) {
			t.Fatalf("invalid string index %d: %v", index, err)
		}
	}
	data := cpuType4Fixture("Grace")
	data[0x10] = 0
	if _, err := parseSMBIOSCPUModel(data); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absent version: %v", err)
	}
	data = cpuType4Fixture("Grace")
	data[0x18] = 0
	if _, err := parseSMBIOSCPUModel(data); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unpopulated socket: %v", err)
	}
	// The processor version is an indexed string, not necessarily string one.
	data = cpuType4Fixture("socket\x00vendor\x00Grace")
	data[0x10] = 3
	if got, err := parseSMBIOSCPUModel(data); got != "Grace" || err != nil {
		t.Fatalf("indexed version: %q %v", got, err)
	}
}

func TestARMCPUModelSources(t *testing.T) {
	for _, tt := range []struct {
		name     string
		cpu      []byte
		dmi      []byte
		dmiErr   error
		deferDMI bool
		midrs    map[string]string
		want     string
		source   string
		status   inventoryv1.CollectionStatus
	}{
		{name: "preferred SMBIOS", cpu: armCPUFixture("0xd4f"), dmi: cpuType4Fixture("NVIDIA Grace"), want: "NVIDIA Grace", source: "smbios_type4", status: success},
		{name: "absent SMBIOS", cpu: armCPUFixture("0xd4f"), dmiErr: fs.ErrNotExist, want: "Neoverse-V2", source: "arm_midr_procfs", status: success},
		{name: "placeholder SMBIOS", cpu: armCPUFixture("0xd4f"), dmi: cpuType4Fixture("To Be Filled By O.E.M."), want: "Neoverse-V2", source: "arm_midr_procfs", status: success},
		{name: "unknown part", cpu: armCPUFixture("0xfff"), deferDMI: true, want: "ARM implementer 0x41 part 0xfff", source: "arm_midr_procfs", status: success},
		{name: "unknown implementer", cpu: []byte(strings.ReplaceAll(string(armCPUFixture("0xd4f")), "0x41", "0xfe")), deferDMI: true, want: "ARM implementer 0xfe part 0xd4f", source: "arm_midr_procfs", status: success},
		{name: "mixed cores", cpu: armCPUFixture("0xd0b", "0xd03", "0xd0b"), deferDMI: true, want: "Cortex-A53; Cortex-A76", source: "arm_midr_procfs", status: success},
		{name: "mixed known unknown", cpu: armCPUFixture("0xd4f", "0xfff"), deferDMI: true, want: "ARM implementer 0x41 part 0xfff; Neoverse-V2", source: "arm_midr_procfs", status: success},
		{name: "same cores", cpu: armCPUFixture("0xd4f", "0xd4f"), deferDMI: true, want: "Neoverse-V2", source: "arm_midr_procfs", status: success},
		{name: "sysfs MIDR", cpu: []byte("processor : 0\nFeatures : fp asimd\n"), deferDMI: true, midrs: map[string]string{"0": "0x00000000410fd4f0\n"}, want: "Neoverse-V2", source: "arm_midr_sysfs", status: success},
		{name: "mixed sysfs MIDR", cpu: []byte("processor : 0\nFeatures : fp asimd\n\nprocessor : 1\nFeatures : fp asimd\n"), deferDMI: true, midrs: map[string]string{"0": "0x410fd030", "1": "0x410fd0b0"}, want: "Cortex-A53; Cortex-A76", source: "arm_midr_sysfs", status: success},
		{name: "denied DMI", cpu: armCPUFixture("0xd4f"), dmiErr: fs.ErrPermission, status: inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED},
		{name: "malformed DMI", cpu: armCPUFixture("0xd4f"), dmi: []byte{4}, status: invalid},
		{name: "malformed proc MIDR", cpu: armCPUFixture("0x1000"), deferDMI: true, status: invalid},
		{name: "empty proc MIDR", cpu: armCPUFixture(""), deferDMI: true, status: invalid},
		{name: "duplicate proc MIDR", cpu: append(armCPUFixture("0xd4f")[:len(armCPUFixture("0xd4f"))-1], []byte("CPU part : 0xd4f\n")...), deferDMI: true, status: invalid},
		{name: "partial proc MIDR", cpu: []byte("processor : 0\nCPU implementer : 0x41\n"), deferDMI: true, status: invalid},
		{name: "missing MIDR", cpu: []byte("processor : 0\nFeatures : fp asimd\n"), deferDMI: true, status: unavailable},
		{name: "malformed sysfs MIDR", cpu: []byte("processor : 0\nFeatures : fp asimd\n"), deferDMI: true, midrs: map[string]string{"0": "0x100000000"}, status: invalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sources := detailSources{rootObservation: tt.deferDMI, readFile: func(path string) ([]byte, error) {
				if path == cpuDMITable {
					if tt.deferDMI {
						t.Fatal("network collector accessed privileged DMI")
					}
					return tt.dmi, tt.dmiErr
				}
				for id, midr := range tt.midrs {
					if path == "/sys/devices/system/cpu/cpu"+id+"/regs/identification/midr_el1" {
						return []byte(midr), nil
					}
				}
				return nil, fs.ErrNotExist
			}}
			got := collectCPU(context.Background(), sources, tt.cpu, nil)
			if got.Model.Status != tt.status || got.Model.Value != tt.want || got.ModelSource.Status != tt.status || got.ModelSource.Value != tt.source {
				t.Fatalf("CPU model/source: %v", got)
			}
			if got.LogicalCores.Status != success || got.X86_64Level.Status != unavailable {
				t.Fatalf("ARM topology/ISA changed: %v", got)
			}
		})
	}
}

func TestCPUModelNativeX86Regression(t *testing.T) {
	sources := detailSources{readFile: func(path string) ([]byte, error) {
		t.Fatalf("x86 model must not probe ARM/DMI evidence: %s", path)
		return nil, fs.ErrNotExist
	}}
	got := collectCPU(context.Background(), sources, detailFixture(t, "cpuinfo.txt"), nil)
	if got.Model.Status != success || got.Model.Value != "13th Gen Intel(R) Core(TM) i7-13700K" || got.ModelSource.Status != success || got.ModelSource.Value != "proc_cpuinfo" || got.LogicalCores.Value != 1 || got.PhysicalCores.Value != 1 || got.X86_64Level.Value != "x86-64-v3" {
		t.Fatalf("native x86 changed: %v", got)
	}
}

func TestCPUModelFailureSources(t *testing.T) {
	for _, err := range []error{fs.ErrNotExist, fs.ErrPermission, context.Canceled, context.DeadlineExceeded, errCapacity, errInvalid} {
		got := collectCPU(context.Background(), detailSources{}, nil, err)
		if got.Model.Status != statusFor(err) || got.ModelSource.Status != got.Model.Status || got.ModelSource.Value != "" {
			t.Fatalf("source failure %v: %v", err, got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sources := detailSources{rootObservation: true, readFile: func(string) ([]byte, error) {
		t.Fatal("canceled collector read native source")
		return nil, nil
	}}
	got := collectCPU(ctx, sources, armCPUFixture("0xd4f"), nil)
	if got.Model.Status != statusFor(context.Canceled) || got.ModelSource.Status != got.Model.Status {
		t.Fatalf("canceled ARM source: %v", got)
	}
}

func TestARMMIDRParsing(t *testing.T) {
	for _, value := range []string{"0x410fd4f0", "0x00000000410fd4f0\n", "0x411FD4F1"} {
		implementer, part, err := parseARMMIDR([]byte(value))
		if err != nil || implementer != 0x41 || part != 0xd4f {
			t.Fatalf("MIDR %q: %x %x %v", value, implementer, part, err)
		}
	}
	for _, value := range []string{"", "410fd4f0", "0x", "0x-1", "0x100000000", "0x410fd4f0\x00", "0x410fd4f0 extra"} {
		if _, _, err := parseARMMIDR([]byte(value)); !errors.Is(err, errInvalid) {
			t.Fatalf("accepted MIDR %q: %v", value, err)
		}
	}
}
