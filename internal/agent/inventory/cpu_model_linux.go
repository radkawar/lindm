//go:build linux

package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"slices"
	"strconv"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const cpuDMITable = "/sys/firmware/dmi/tables/DMI"

func cpuModelSource(model *inventoryv1.ObservedString, source string) *inventoryv1.ObservedString {
	if model.Status != success {
		return &inventoryv1.ObservedString{Status: model.Status}
	}
	return observed(source, nil)
}

// collectCPUModel never consults distribution metadata. The upload collector
// defers privileged SMBIOS evidence to the root executor; its procfs/sysfs model
// is only interim. Malformed or denied preferred evidence is not absence.
func collectCPUModel(ctx context.Context, s detailSources, data []byte, result *inventoryv1.CpuDetails) {
	processors, arm := armCPUProcessors(data)
	if !arm {
		return
	}
	set := func(value, source string, err error) {
		result.Model = observed(value, err)
		result.ModelSource = cpuModelSource(result.Model, source)
	}
	if !s.rootObservation {
		table, err := s.file(ctx, cpuDMITable)
		var model string
		if err == nil {
			model, err = parseSMBIOSCPUModel(table)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			set(model, "smbios_type4", err)
			return
		}
	}
	models := make([]string, 0, len(processors))
	source := "arm_midr_procfs"
	for _, processor := range processors {
		if err := ctx.Err(); err != nil {
			set("", source, err)
			return
		}
		implementer, part, err := processor.identity()
		if errors.Is(err, fs.ErrNotExist) {
			source = "arm_midr_sysfs"
			midr, readErr := s.file(ctx, "/sys/devices/system/cpu/cpu"+processor.id+"/regs/identification/midr_el1")
			if readErr != nil {
				set("", source, readErr)
				return
			}
			implementer, part, err = parseARMMIDR(midr)
		}
		if err != nil {
			set("", source, err)
			return
		}
		models = append(models, armCPUName(implementer, part))
	}
	set(joinCPUModels(models), source, nil)
}

type armCPUProcessor struct {
	id          string
	implementer string
	part        string
	invalid     bool
}

// parseCPU has already validated processor IDs and the native text structure.
// Recognize fixture architecture from native fields rather than the test host.
func armCPUProcessors(data []byte) ([]armCPUProcessor, bool) {
	var processors []armCPUProcessor
	arm, x86 := false, false
	for block := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n\n") {
		var processor armCPUProcessor
		hasID, hasImplementer, hasPart := false, false, false
		for line := range strings.SplitSeq(block, "\n") {
			key, value, _ := strings.Cut(line, ":")
			value = strings.TrimSpace(value)
			switch strings.TrimSpace(key) {
			case "processor":
				processor.id, hasID = value, true
			case "CPU implementer":
				processor.invalid = processor.invalid || hasImplementer || value == ""
				processor.implementer, hasImplementer, arm = value, true, true
			case "CPU part":
				processor.invalid = processor.invalid || hasPart || value == ""
				processor.part, hasPart, arm = value, true, true
			case "CPU architecture", "Features":
				arm = true
			case "vendor_id", "flags":
				x86 = true
			}
		}
		if hasID {
			processors = append(processors, processor)
		}
	}
	return processors, arm || (!x86 && (runtime.GOARCH == "arm64" || runtime.GOARCH == "arm"))
}

func (p armCPUProcessor) identity() (uint64, uint64, error) {
	if p.invalid {
		return 0, 0, errInvalid
	}
	if p.implementer == "" && p.part == "" {
		return 0, 0, fs.ErrNotExist
	}
	implementer, err := armHex(p.implementer, 8)
	if err != nil {
		return 0, 0, err
	}
	part, err := armHex(p.part, 12)
	return implementer, part, err
}

func armHex(value string, bits int) (uint64, error) {
	if len(value) < 3 || !strings.HasPrefix(value, "0x") {
		return 0, errInvalid
	}
	n, err := strconv.ParseUint(value[2:], 16, bits)
	if err != nil {
		return 0, errInvalid
	}
	return n, nil
}

func parseARMMIDR(data []byte) (uint64, uint64, error) {
	midr, err := armHex(strings.TrimSpace(string(data)), 32)
	return (midr >> 24) & 0xff, (midr >> 4) & 0xfff, err
}

// ARM implementer 0x41 part names: util-linux v2.41, lscpu-arm.c,
// commit caa26876bc75041833c9644491cc2670d623f750:
// https://github.com/util-linux/util-linux/blob/caa26876bc75041833c9644491cc2670d623f750/sys-utils/lscpu-arm.c
// This deliberately small maintained table is not an exhaustive architecture
// registry. Unlisted implementer/part pairs remain successful exact identities.
var armParts = map[uint64]string{
	0xd03: "Cortex-A53",
	0xd04: "Cortex-A35",
	0xd05: "Cortex-A55",
	0xd07: "Cortex-A57",
	0xd08: "Cortex-A72",
	0xd09: "Cortex-A73",
	0xd0a: "Cortex-A75",
	0xd0b: "Cortex-A76",
	0xd0c: "Neoverse-N1",
	0xd0d: "Cortex-A77",
	0xd40: "Neoverse-V1",
	0xd41: "Cortex-A78",
	0xd44: "Cortex-X1",
	0xd46: "Cortex-A510",
	0xd47: "Cortex-A710",
	0xd48: "Cortex-X2",
	0xd49: "Neoverse-N2",
	0xd4a: "Neoverse-E1",
	0xd4d: "Cortex-A715",
	0xd4e: "Cortex-X3",
	0xd4f: "Neoverse-V2",
	0xd80: "Cortex-A520",
	0xd81: "Cortex-A720",
	0xd82: "Cortex-X4",
	0xd84: "Neoverse-V3",
	0xd85: "Cortex-X925",
	0xd87: "Cortex-A725",
	0xd8e: "Neoverse-N3",
}

func armCPUName(implementer, part uint64) string {
	if implementer == 0x41 {
		if name := armParts[part]; name != "" {
			return name
		}
	}
	return fmt.Sprintf("ARM implementer 0x%02x part 0x%03x", implementer, part)
}

func joinCPUModels(models []string) string {
	slices.Sort(models)
	return strings.Join(slices.Compact(models), "; ")
}

// parseSMBIOSCPUModel walks the native SMBIOS structure stream, not a dmidecode
// rendering. Type 4's processor-version string index is at offset 0x10 and its
// socket-populated status bit is at 0x18 (SMBIOS DSP0134, Processor Information).
// Validate every structure before publishing any model, including processor
// version indices and double-NUL terminators. Empty sockets are not processors.
func parseSMBIOSCPUModel(data []byte) (string, error) {
	if len(data) > maxDetailFile {
		return "", errCapacity
	}
	if len(data) == 0 {
		return "", errInvalid
	}
	var models []string
	missingVersion := false
	for len(data) > 0 {
		if len(data) < 4 || data[1] < 4 || int(data[1]) > len(data) {
			return "", errInvalid
		}
		length := int(data[1])
		end := bytes.Index(data[length:], []byte{0, 0})
		if end < 0 {
			return "", errInvalid
		}
		stringsData := data[length : length+end]
		if data[0] == 4 {
			if length < 0x1a {
				return "", errInvalid
			}
			model, err := smbiosCPUString(stringsData, int(data[0x10]))
			if err != nil {
				return "", err
			}
			if data[0x18]&0x40 != 0 {
				if meaningfulCPUVersion(model) {
					models = append(models, model)
				} else {
					missingVersion = true
				}
			}
		}
		kind := data[0]
		data = data[length+end+2:]
		if kind == 127 {
			if length != 4 || len(stringsData) != 0 {
				return "", errInvalid
			}
			for _, padding := range data {
				if padding != 0 && padding != 0xff {
					return "", errInvalid
				}
			}
			break
		}
	}
	if len(models) == 0 || missingVersion {
		return "", fs.ErrNotExist
	}
	return joinCPUModels(models), nil
}

func smbiosCPUString(data []byte, index int) (string, error) {
	if index == 0 {
		return "", nil
	}
	for len(data) > 0 {
		end := bytes.IndexByte(data, 0)
		if end < 0 {
			end = len(data)
		}
		if index == 1 {
			value := strings.TrimSpace(string(data[:end]))
			if !nativeText(data[:end]) {
				return "", errInvalid
			}
			for _, c := range value {
				if c < 32 || c == 127 {
					return "", errInvalid
				}
			}
			if len(value) > 4096 {
				return "", errCapacity
			}
			return value, nil
		}
		if end == len(data) {
			break
		}
		data = data[end+1:]
		index--
	}
	return "", errInvalid
}

func meaningfulCPUVersion(value string) bool {
	switch strings.ToLower(value) {
	case "", "unknown", "not specified", "not available", "not applicable", "to be filled by o.e.m.", "to be filled by oem", "default string", "none", "n/a":
		return false
	default:
		return true
	}
}
