// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"io/fs"
	"testing"
)

func TestCapturedFedora44ARMCPU(t *testing.T) {
	// Raw interfaces captured on the leased DGX Fedora 44 guest; provenance
	// records image and firmware identities. The guest's SMBIOS version names
	// its virtual CPU, not the Cortex-X925 host MIDR or its Fedora distribution.
	const fixture = "cpu-fedora44-aarch64/"
	cpu := detailFixture(t, fixture+"cpuinfo.txt")
	dmi := detailFixture(t, fixture+"DMI.bin")
	midr := detailFixture(t, fixture+"midr_el1.txt")
	if model, err := parseSMBIOSCPUModel(dmi); model != "virt-8.2" || err != nil {
		t.Fatalf("captured SMBIOS model=%q err=%v", model, err)
	}
	implementer, part, err := parseARMMIDR(midr)
	if err != nil || implementer != 0x41 || part != 0xd85 || armCPUName(implementer, part) != "Cortex-X925" {
		t.Fatalf("captured MIDR=%x/%x err=%v", implementer, part, err)
	}
	for _, tt := range []struct {
		name      string
		deferDMI  bool
		absentDMI bool
		want      string
		source    string
	}{
		{name: "root native DMI", want: "virt-8.2", source: "smbios_type4"},
		{name: "unprivileged interim", deferDMI: true, want: "Cortex-X925", source: "arm_midr_procfs"},
		{name: "native proc fallback", absentDMI: true, want: "Cortex-X925", source: "arm_midr_procfs"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sources := detailSources{rootObservation: tt.deferDMI, readFile: func(path string) ([]byte, error) {
				if path == cpuDMITable {
					if tt.deferDMI {
						t.Fatal("unprivileged collector read DMI")
					}
					if tt.absentDMI {
						return nil, fs.ErrNotExist
					}
					return dmi, nil
				}
				// No topology was captured in this fixture; do not invent it.
				return nil, fs.ErrNotExist
			}}
			got := collectCPU(context.Background(), sources, cpu, nil)
			if got.Model.Status != success || got.Model.Value != tt.want || got.ModelSource.Status != success || got.ModelSource.Value != tt.source {
				t.Fatalf("captured model/source: %v", got)
			}
			if got.LogicalCores.Status != success || got.LogicalCores.Value != 2 || got.PhysicalCores.Status != unavailable || got.X86_64Level.Status != unavailable {
				t.Fatalf("captured ARM topology/ISA: %v", got)
			}
		})
	}
}
