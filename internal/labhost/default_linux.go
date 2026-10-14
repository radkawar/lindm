// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
)

func localDefault() (*labv1.LabConfig, error) {
	var memory unix.Sysinfo_t
	if err := unix.Sysinfo(&memory); err != nil {
		return nil, fmt.Errorf("lab hosts: inspect local memory: %w", err)
	}
	// KVM is the native execution requirement, not an availability probe.
	// Missing access must fail at execution rather than silently selecting TCG.
	cfg := defaultConfig(runtime.GOARCH, runtime.NumCPU(), uint64(memory.Totalram)*uint64(memory.Unit)/(1<<20), true)
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultConfig(architecture string, cpus int, memoryMib uint64, kvm bool) *labv1.LabConfig {
	// Reserve one quarter of CPU and RAM for the host, budgeting every slot at
	// the 4 vCPU / 4096 MiB admission ceilings. Actual ordinary cloud guests
	// retain their existing 2 vCPU / 2048 MiB allocation.
	cpuSlots := max(cpus*3/4/4, 1)
	memorySlots := max(memoryMib/4*3/4096, 1)
	slots := min(uint64(cpuSlots), memorySlots, 1024)
	return &labv1.LabConfig{Hosts: []*labv1.LabHost{{
		Name:          "local",
		Transport:     "local",
		Architectures: []string{architecture},
		Kvm:           kvm,
		MaxGuests:     uint32(slots),
		MaxVcpus:      4,
		MaxMemoryMib:  4096,
		WorkDirectory: filepath.Join(os.TempDir(), "lindm-lab-"+strconv.Itoa(os.Getuid())),
		Runtime:       "native",
	}}}
}
