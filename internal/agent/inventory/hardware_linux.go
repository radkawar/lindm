//go:build linux

package inventory

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// collectCPU uses procfs identity and online-processor evidence first. ARM
// cpuinfo commonly omits x86 topology fields; sysfs supplies package/core IDs
// without guessing one physical core per logical processor.
func collectCPU(ctx context.Context, s detailSources, data []byte, err error) *inventoryv1.CpuDetails {
	result := parseCPU(data, err)
	if result.LogicalCores.Status == success {
		collectCPUModel(ctx, s, data, result)
	}
	if result.LogicalCores.Status != success || result.PhysicalCores.Status != unavailable {
		return result
	}
	cores := make(map[string]bool)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, id, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "processor" {
			continue
		}
		id = strings.TrimSpace(id) // Already validated by parseCPU.
		base := "/sys/devices/system/cpu/cpu" + id + "/topology/"
		packageID := s.text(ctx, base+"physical_package_id")
		coreID := s.text(ctx, base+"core_id")
		for _, field := range []*inventoryv1.ObservedString{packageID, coreID} {
			if field.Status != success {
				result.PhysicalCores = &inventoryv1.ObservedUint64{Status: field.Status}
				return result
			}
			if field.Value == "-1" {
				result.PhysicalCores = number(0, fs.ErrNotExist)
				return result
			}
			if _, err := decimal(field.Value); err != nil {
				result.PhysicalCores = number(0, err)
				return result
			}
		}
		cores[packageID.Value+":"+coreID.Value] = true
	}
	result.PhysicalCores = number(uint64(len(cores)), nil)
	return result
}

func parseCPU(data []byte, err error) (result *inventoryv1.CpuDetails) {
	result = &inventoryv1.CpuDetails{Model: observed("", err), LogicalCores: number(0, err), PhysicalCores: number(0, err), X86_64Level: observed("", err)}
	defer func() { result.ModelSource = cpuModelSource(result.Model, "proc_cpuinfo") }()
	if err != nil {
		return result
	}
	fail := func(err error) *inventoryv1.CpuDetails {
		return &inventoryv1.CpuDetails{Model: observed("", err), LogicalCores: number(0, err), PhysicalCores: number(0, err), X86_64Level: observed("", err)}
	}
	if !nativeText(data) {
		return fail(errInvalid)
	}
	var count uint64
	cores := make(map[string]bool)
	processors := make(map[string]bool)
	var common map[string]bool
	model := ""
	topology := true
	flagsPresent := true
	for block := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n\n") {
		values := make(map[string]string)
		for line := range strings.SplitSeq(block, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				return fail(errInvalid)
			}
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
		processor, ok := values["processor"]
		if !ok {
			continue
		} // Architecture-specific trailing hardware stanza.
		if _, err := decimal(processor); err != nil || processors[processor] {
			return fail(errInvalid)
		}
		processors[processor] = true
		count++
		if model == "" {
			model = values["model name"]
			if model == "" {
				model = values["Processor"]
			}
		}
		if values["physical id"] == "" || values["core id"] == "" {
			topology = false
		} else {
			cores[values["physical id"]+":"+values["core id"]] = true
		}
		flags := make(map[string]bool)
		if values["flags"] == "" {
			flagsPresent = false
		}
		for flag := range strings.FieldsSeq(values["flags"]) {
			flags[flag] = true
		}
		if common == nil {
			common = flags
		} else {
			for flag := range common {
				if !flags[flag] {
					delete(common, flag)
				}
			}
		}
	}
	if count == 0 {
		return fail(errInvalid)
	}
	result.Model = observed(model, nil)
	result.LogicalCores = number(count, nil)
	result.PhysicalCores = number(uint64(len(cores)), nil)
	if !topology {
		result.PhysicalCores = number(0, fs.ErrNotExist)
	}
	result.X86_64Level = observed("", fs.ErrNotExist)
	if flagsPresent {
		// Linux exposes pni for SSE3, and lm for the 64-bit baseline. Linux
		// advertises AVX only when the kernel enables the required XSAVE state.
		levels := []string{"fpu cx8 cmov mmx fxsr sse sse2 syscall lm", "cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2", "avx avx2 bmi1 bmi2 f16c fma abm movbe xsave", "avx512f avx512bw avx512cd avx512dq avx512vl"}
		for i, required := range levels {
			available := true
			for flag := range strings.FieldsSeq(required) {
				if !common[flag] {
					available = false
					break
				}
			}
			if !available {
				break
			}
			result.X86_64Level = observed("x86-64-v"+strconv.Itoa(i+1), nil)
		}
	}
	return result
}

func parseMemory(data []byte, err error) *inventoryv1.MemoryDetails {
	result := &inventoryv1.MemoryDetails{TotalBytes: number(0, err), AvailableBytes: number(0, err), SwapTotalBytes: number(0, err)}
	if err != nil {
		return result
	}
	values := make(map[string]*inventoryv1.ObservedUint64)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := fields[0]
		if key != "MemTotal:" && key != "MemAvailable:" && key != "SwapTotal:" {
			continue
		}
		if values[key] != nil {
			values[key] = number(0, errInvalid)
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			values[key] = number(0, errInvalid)
			continue
		}
		n, err := decimal(fields[1])
		if n > ^uint64(0)/1024 {
			err = errInvalid
		}
		values[key] = number(n*1024, err)
	}
	get := func(key string) *inventoryv1.ObservedUint64 {
		if v := values[key]; v != nil {
			return v
		}
		return number(0, fs.ErrNotExist)
	}
	result.TotalBytes, result.AvailableBytes, result.SwapTotalBytes = get("MemTotal:"), get("MemAvailable:"), get("SwapTotal:")
	if result.TotalBytes.Status == success && result.TotalBytes.Value == 0 {
		result.TotalBytes = number(0, errInvalid)
	}
	if result.TotalBytes.Status == success && result.AvailableBytes.Value > result.TotalBytes.Value {
		result.AvailableBytes = number(0, errInvalid)
	}
	return result
}

func collectFirmware(ctx context.Context, s detailSources) *inventoryv1.FirmwareDetails {
	result := &inventoryv1.FirmwareDetails{Mode: observed("", ctx.Err()), SecureBoot: observed("", fs.ErrNotExist)}
	if ctx.Err() != nil {
		result.SecureBoot = observed("", ctx.Err())
		return result
	}
	info, err := s.stat("/sys/firmware/efi")
	if errors.Is(err, fs.ErrNotExist) {
		result.Mode = observed("bios", nil)
		return result
	}
	if err != nil {
		result.Mode = observed("", err)
		result.SecureBoot = observed("", err)
		return result
	}
	if !info.IsDir() {
		result.Mode = observed("", errInvalid)
		result.SecureBoot = observed("", errInvalid)
		return result
	}
	result.Mode = observed("uefi", nil)
	data, err := s.file(ctx, "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		result.SecureBoot = observed("", err)
		return result
	}
	if len(data) != 5 || data[4] > 1 {
		result.SecureBoot = observed("", errInvalid)
		return result
	}
	value := "disabled"
	if data[4] == 1 {
		value = "enabled"
	}
	result.SecureBoot = observed(value, nil)
	return result
}

func collectTPM(ctx context.Context, s detailSources) *inventoryv1.TpmDetails {
	result := &inventoryv1.TpmDetails{Present: boolean(false, ctx.Err()), Version: observed("", fs.ErrNotExist)}
	if ctx.Err() != nil {
		result.Version = observed("", ctx.Err())
		return result
	}
	entries, err := s.readDir("/sys/class/tpm")
	if err != nil {
		result.Present = boolean(false, err)
		result.Version = observed("", err)
		return result
	}
	var versions []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "tpm") {
			continue
		}
		result.Present = boolean(true, nil)
		version := s.text(ctx, "/sys/class/tpm/"+entry.Name()+"/tpm_version_major")
		if version.Status != success {
			result.Version = version
			return result
		}
		if version.Value != "1" && version.Value != "2" {
			result.Version = observed("", errInvalid)
			return result
		}
		versions = append(versions, version.Value)
	}
	if len(versions) > 0 {
		result.Version = observed(strings.Join(versions, ","), nil)
	}
	return result
}

func collectPower(ctx context.Context, s detailSources) *inventoryv1.PowerDetails {
	result := &inventoryv1.PowerDetails{Chassis: s.text(ctx, "/sys/class/dmi/id/chassis_type"), Batteries: &inventoryv1.BatteryDetails{Status: statusFor(ctx.Err())}}
	if ctx.Err() != nil {
		return result
	}
	entries, err := s.readDir("/sys/class/power_supply")
	if err != nil {
		result.Batteries.Status = statusFor(err)
		return result
	}
	for _, entry := range entries {
		base := "/sys/class/power_supply/" + entry.Name() + "/"
		typ := s.text(ctx, base+"type")
		if typ.Status != success {
			result.Batteries.Status = typ.Status
			break
		}
		if typ.Value != "Battery" {
			continue
		}
		if len(result.Batteries.Items) == 32 {
			result.Batteries.Status = capacity
			break
		}
		battery := &inventoryv1.Battery{Name: entry.Name(), Status: s.text(ctx, base+"status"), CapacityPercent: s.uint(ctx, base+"capacity")}
		if battery.CapacityPercent.Value > 100 {
			battery.CapacityPercent = number(0, errInvalid)
		}
		result.Batteries.Items = append(result.Batteries.Items, battery)
	}
	if result.Batteries.Status != success {
		result.Batteries.Items = nil
	}
	return result
}

func collectBackends(ctx context.Context, s detailSources) *inventoryv1.BackendDetails {
	present := func(paths ...string) *inventoryv1.ObservedBool {
		if ctx.Err() != nil {
			return boolean(false, ctx.Err())
		}
		for _, path := range paths {
			info, err := s.stat(path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return boolean(false, err)
			}
			if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
				return boolean(false, errInvalid)
			}
			return boolean(true, nil)
		}
		return boolean(false, nil)
	}
	return &inventoryv1.BackendDetails{Dpkg: present("/usr/bin/dpkg-query"), Rpm: present("/usr/bin/rpm"), Pacman: present("/usr/bin/pacman"), Zypper: present("/usr/bin/zypper"), RpmOstree: present("/usr/bin/rpm-ostree"), Nix: present("/run/current-system/sw/bin/nix", "/nix/var/nix/profiles/default/bin/nix", "/usr/bin/nix"), Flatpak: present("/usr/bin/flatpak"), Snap: present("/usr/bin/snap")}
}
