//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// Native truth uses distribution tools and separate presentation/parsing from the
// agent. Missing optional facilities are evidence, not an empty successful value.
// No command installs software or changes the guest.
type vmInventoryOracle struct {
	vm  *guestVM
	ctx context.Context
}

const truthSuccess = inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
const truthUnavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
const truthDenied = inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED

func (o vmInventoryOracle) command(command string) ([]byte, error) {
	data, err := o.vm.run(o.ctx, "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c "+nativeQuote("set -eu; "+command), nil, 4<<20, 30*time.Second)
	if err != nil {
		return nil, errors.New("independent native inventory command failed (guest output withheld)")
	}
	return data, nil
}

func (o vmInventoryOracle) optional(tool, command string) ([]byte, inventoryv1.CollectionStatus, error) {
	script := "set -eu; if command -v " + nativeQuote(tool) + " >/dev/null 2>&1; then printf 'success\\n'; " + command + "; else printf 'unavailable\\n'; fi"
	result, err := o.vm.runResult(o.ctx, "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -c "+nativeQuote(script), nil, 4<<20, 30*time.Second)
	if err != nil {
		return nil, 0, errors.New("native optional command transport failed")
	}
	if result.ExitCode != 0 || len(result.Stderr) != 0 {
		return nil, inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE, nil
	}
	return parseTruthStatus(result.Stdout)
}

func parseTruthStatus(data []byte) ([]byte, inventoryv1.CollectionStatus, error) {
	status, value, ok := strings.Cut(string(data), "\n")
	if !ok {
		return nil, 0, errors.New("truncated native status evidence")
	}
	switch status {
	case "success":
		return []byte(value), truthSuccess, nil
	case "unavailable":
		if value == "" {
			return nil, truthUnavailable, nil
		}
	case "denied":
		if value == "" {
			return nil, truthDenied, nil
		}
	case "invalid":
		if value == "" {
			return nil, inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT, nil
		}
	}
	return nil, 0, errors.New("invalid native status evidence")
}

func (o vmInventoryOracle) file(path string) (*inventoryv1.ObservedString, error) {
	quoted := nativeQuote(path)
	data, err := o.command("if [ ! -e " + quoted + " ]; then printf 'unavailable\\n'; elif [ ! -r " + quoted + " ]; then printf 'denied\\n'; else printf 'success\\n'; cat -- " + quoted + "; fi")
	if err != nil {
		return nil, err
	}
	value, status, err := parseTruthStatus(data)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(value))
	if status == truthSuccess && text == "" {
		status = truthUnavailable
	}
	return &inventoryv1.ObservedString{Status: status, Value: text}, nil
}

func truthString(value string) *inventoryv1.ObservedString {
	if value == "" {
		return &inventoryv1.ObservedString{Status: truthUnavailable}
	}
	return &inventoryv1.ObservedString{Status: truthSuccess, Value: value}
}

func truthUint(value uint64) *inventoryv1.ObservedUint64 {
	return &inventoryv1.ObservedUint64{Status: truthSuccess, Value: value}
}

func truthBool(value bool) *inventoryv1.ObservedBool {
	return &inventoryv1.ObservedBool{Status: truthSuccess, Value: value}
}

func parseTruthUint(value string) (uint64, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, errors.New("invalid native numeric truth")
	}
	return n, nil
}

// lsblk pairs escapes unsafe bytes as hexadecimal. Do not split quoted values
// on spaces: labels and mountpoints legitimately contain them.
func parseTruthPairs(line string) (map[string]string, error) {
	result := make(map[string]string)
	for line != "" {
		key, rest, ok := strings.Cut(line, "=\"")
		if !ok || key == "" || strings.ContainsAny(key, " \t\r\n") {
			return nil, errors.New("invalid lsblk truth column")
		}
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return nil, errors.New("unterminated lsblk truth value")
		}
		value, err := strconv.Unquote("\"" + rest[:end] + "\"")
		if err != nil {
			return nil, errors.New("invalid lsblk truth escape")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("duplicate lsblk truth column")
		}
		result[key] = value
		line = strings.TrimLeft(rest[end+1:], " ")
	}
	return result, nil
}

func truthLines(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' || strings.ContainsRune(string(data), '\x00') {
		return nil, errors.New("truncated native inventory truth")
	}
	return strings.Split(string(data[:len(data)-1]), "\n"), nil
}

func truthRows(data []byte) ([][]string, error) {
	lines, err := truthLines(data)
	if err != nil {
		return nil, err
	}
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, strings.Fields(line))
		}
	}
	return rows, nil
}

func collectVMDetails(ctx context.Context, vm *guestVM) (*inventoryv1.NativeDetails, error) {
	o := vmInventoryOracle{vm: vm, ctx: ctx}
	d := new(inventoryv1.NativeDetails)
	var err error
	if d.Cpu, err = o.cpu(); err != nil {
		return nil, fmt.Errorf("CPU truth: %w", err)
	}
	if d.Memory, err = o.memory(); err != nil {
		return nil, fmt.Errorf("memory truth: %w", err)
	}
	if d.Storage, err = o.storage(); err != nil {
		return nil, fmt.Errorf("storage truth: %w", err)
	}
	if d.Network, err = o.network(); err != nil {
		return nil, fmt.Errorf("network truth: %w", err)
	}
	if d.Firmware, err = o.firmware(); err != nil {
		return nil, fmt.Errorf("firmware truth: %w", err)
	}
	if d.Tpm, err = o.tpm(); err != nil {
		return nil, fmt.Errorf("TPM truth: %w", err)
	}
	if d.Power, err = o.power(); err != nil {
		return nil, fmt.Errorf("power truth: %w", err)
	}
	if d.Sessions, err = o.sessions(); err != nil {
		return nil, fmt.Errorf("logind truth: %w", err)
	}
	if d.LocalUsers, err = o.users(); err != nil {
		return nil, fmt.Errorf("local account truth: %w", err)
	}
	if d.KernelModuleCount, err = o.number("wc -l < /proc/modules"); err != nil {
		return nil, fmt.Errorf("kernel module count truth: %w", err)
	}
	if d.BootTimeUnixSeconds, err = o.bootTime(); err != nil {
		return nil, fmt.Errorf("boot time truth: %w", err)
	}
	if d.UptimeSeconds, err = o.number("cut -d. -f1 /proc/uptime"); err != nil {
		return nil, fmt.Errorf("uptime truth: %w", err)
	}
	if d.Backends, err = o.backends(); err != nil {
		return nil, fmt.Errorf("package backend truth: %w", err)
	}
	if d.Flatpak, err = o.applications("flatpak"); err != nil {
		return nil, fmt.Errorf("flatpak truth: %w", err)
	}
	if d.Snap, err = o.applications("snap"); err != nil {
		return nil, fmt.Errorf("snap truth: %w", err)
	}
	if d.Platform, err = o.platform(); err != nil {
		return nil, fmt.Errorf("platform truth: %w", err)
	}
	return d, nil
}

func (o vmInventoryOracle) number(command string) (*inventoryv1.ObservedUint64, error) {
	data, err := o.command(command)
	if err != nil {
		return nil, err
	}
	n, err := parseTruthUint(string(data))
	if err != nil {
		return nil, err
	}
	return truthUint(n), nil
}

func (o vmInventoryOracle) bootTime() (*inventoryv1.ObservedUint64, error) {
	// The kernel exports Unix seconds directly. Unlike uptime -s followed by
	// date -d, this requires neither procps-specific flags nor a locale/timezone
	// round trip. Select the native record separately from the agent's parser.
	data, err := o.command("grep '^btime ' /proc/stat")
	if err != nil {
		return nil, err
	}
	return parseTruthBootTime(data)
}

func parseTruthBootTime(data []byte) (*inventoryv1.ObservedUint64, error) {
	value, ok := strings.CutPrefix(string(data), "btime ")
	if !ok {
		return nil, errors.New("missing native boot time record")
	}
	value, terminated := strings.CutSuffix(value, "\n")
	if !terminated || value == "" {
		return nil, errors.New("truncated native boot time record")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return nil, errors.New("invalid or duplicate native boot time record")
		}
	}
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return nil, errors.New("native boot time exceeds numeric range")
	}
	return truthUint(seconds), nil
}

type cpuTruthField struct {
	Field    string          `json:"field"`
	Data     string          `json:"data"`
	Children []cpuTruthField `json:"children"`
}

func parseCPUTruth(data []byte) (map[string]string, error) {
	var raw struct {
		CPU []cpuTruthField `json:"lscpu"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("invalid lscpu JSON truth")
	}
	fields := make(map[string]string, len(raw.CPU))
	var collect func([]cpuTruthField)
	collect = func(items []cpuTruthField) {
		for _, item := range items {
			fields[strings.TrimSuffix(item.Field, ":")] = item.Data
			collect(item.Children)
		}
	}
	collect(raw.CPU)
	return fields, nil
}

func (o vmInventoryOracle) cpu() (*inventoryv1.CpuDetails, error) {
	// RHEL 9's util-linux predates --hierarchic. Both its flat JSON and
	// newer util-linux's nested JSON carry the same named observations.
	data, err := o.command("lscpu --json")
	if err != nil {
		return nil, err
	}
	fields, err := parseCPUTruth(data)
	if err != nil {
		return nil, err
	}
	logical, err := parseTruthUint(fields["CPU(s)"])
	if err != nil {
		return nil, err
	}
	// lscpu can enrich ARM model names from sysfs. The inventory contract
	// reports models only when cpuinfo exposes them; prove that source
	// capability independently rather than inventing a marketing model.
	capabilities, err := o.command(`test -r /proc/cpuinfo; for key in 'model name|Processor' 'flags'; do if grep -Eq "^($key)[[:space:]]*:" /proc/cpuinfo; then printf '1\n'; else printf '0\n'; fi; done`)
	if err != nil {
		return nil, err
	}
	capabilityLines, err := truthLines(capabilities)
	if err != nil || len(capabilityLines) != 2 {
		return nil, errors.New("invalid CPU source capability truth")
	}
	model := truthString("")
	if capabilityLines[0] == "1" {
		model = truthString(fields["Model name"])
		if model.Status != truthSuccess {
			return nil, errors.New("CPU model truth unavailable from lscpu")
		}
	}
	level := truthString("")
	if fields["Architecture"] == "x86_64" && capabilityLines[1] == "1" {
		level = truthString(truthX86Level(fields["Flags"]))
		if level.Status != truthSuccess {
			return nil, errors.New("x86 CPU flags truth unavailable from lscpu")
		}
	}
	if logical == 0 {
		return nil, errors.New("zero logical CPU truth")
	}
	// Count kernel physical package/core IDs, not lscpu's synthesized logical
	// topology. On ARM KVM, lscpu can map two distinct kernel core IDs onto one
	// logical core; --physical preserves the independent native IDs.
	data, err = o.command("lscpu --physical --parse=SOCKET,CORE --all")
	if err != nil {
		return nil, err
	}
	lines, err := truthLines(data)
	if err != nil {
		return nil, err
	}
	cores := make(map[string]bool)
	physical := truthUint(0)
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			return nil, errors.New("invalid lscpu topology truth")
		}
		for _, part := range parts {
			if part == "" || part == "-" || part == "-1" {
				physical.Status = truthUnavailable
				continue
			}
			if _, err := parseTruthUint(part); err != nil {
				return nil, err
			}
		}
		cores[line] = true
	}
	if len(cores) == 0 {
		return nil, errors.New("incomplete lscpu truth")
	}
	if physical.Status == truthSuccess {
		physical.Value = uint64(len(cores))
	}
	return &inventoryv1.CpuDetails{Model: model, LogicalCores: truthUint(logical), PhysicalCores: physical, X86_64Level: level}, nil
}

func truthX86Level(flags string) string {
	set := make(map[string]bool)
	for _, flag := range strings.Fields(flags) {
		set[flag] = true
	}
	// Linux names pni/lahf_lm/abm correspond to SSE3/LAHF/LZCNT.
	levels := []string{
		"cx8 cmov fpu fxsr mmx syscall sse sse2",
		"cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2",
		"avx avx2 bmi1 bmi2 f16c fma abm movbe xsave",
		"avx512f avx512bw avx512cd avx512dq avx512vl",
	}
	level := 0
	for _, required := range levels {
		for _, flag := range strings.Fields(required) {
			if !set[flag] {
				if level == 0 {
					return ""
				}
				return fmt.Sprintf("x86-64-v%d", level)
			}
		}
		level++
	}
	return "x86-64-v4"
}

func (o vmInventoryOracle) memory() (*inventoryv1.MemoryDetails, error) {
	data, err := o.command("free --bytes --wide")
	if err != nil {
		return nil, err
	}
	return parseTruthMemory(data)
}

func parseTruthMemory(data []byte) (*inventoryv1.MemoryDetails, error) {
	rows, err := truthRows(data)
	if err != nil {
		return nil, err
	}
	if len(rows) != 3 || strings.Join(rows[0], " ") != "total used free shared buffers cache available" || len(rows[1]) != 8 || rows[1][0] != "Mem:" || len(rows[2]) != 4 || rows[2][0] != "Swap:" {
		return nil, errors.New("invalid free truth columns")
	}
	total, err := parseTruthUint(rows[1][1])
	if err != nil {
		return nil, err
	}
	available, err := parseTruthUint(rows[1][7])
	if err != nil {
		return nil, err
	}
	swap, err := parseTruthUint(rows[2][1])
	if err != nil {
		return nil, err
	}
	return &inventoryv1.MemoryDetails{TotalBytes: truthUint(total), AvailableBytes: truthUint(available), SwapTotalBytes: truthUint(swap)}, nil
}

// Pairs is already a flat, shell-safe presentation; lsblk rejects combining
// --pairs with --list (or --raw/--tree).
const storageTruthCommand = "lsblk --bytes --pairs --output NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,PKNAME,KNAME,TRAN,MODEL,SERIAL,WWN,REV,UUID,FSVER,PARTUUID,PARTTYPE"

func (o vmInventoryOracle) storage() (*inventoryv1.StorageDetails, error) {
	data, status, err := o.optional("lsblk", storageTruthCommand)
	if err != nil {
		return nil, err
	}
	result, err := parseTruthStorage(data, status)
	if err != nil || result.Status != truthSuccess {
		return result, err
	}
	if err := o.storageIdentities(result, data); err != nil {
		return nil, err
	}
	return result, nil
}

func parseTruthStorage(data []byte, status inventoryv1.CollectionStatus) (*inventoryv1.StorageDetails, error) {
	result := &inventoryv1.StorageDetails{Status: status}
	if status != truthSuccess {
		return result, nil
	}
	lines, err := truthLines(data)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*inventoryv1.BlockDevice)
	byKernel := make(map[string]string)
	for _, line := range lines {
		fields, err := parseTruthPairs(line)
		if err != nil {
			return nil, err
		}
		if (len(fields) != 6 && len(fields) != 16) || fields["NAME"] == "" || fields["TYPE"] == "" {
			return nil, errors.New("incomplete lsblk truth")
		}
		size, err := parseTruthUint(fields["SIZE"])
		if err != nil {
			return nil, err
		}
		device := &inventoryv1.BlockDevice{Name: fields["NAME"], Type: truthString(fields["TYPE"]), Parent: truthString(fields["PKNAME"]), SizeBytes: truthUint(size), Filesystem: truthString(fields["FSTYPE"]), Mountpoint: truthString(fields["MOUNTPOINT"]), Encryption: truthString("")}
		if len(fields) == 16 {
			device.Identity = storageTruthIdentity(fields)
		}
		if _, duplicate := byName[device.Name]; duplicate {
			return nil, errors.New("duplicate block device truth")
		}
		byName[device.Name] = device
		if kernel := fields["KNAME"]; kernel != "" {
			if prior, duplicate := byKernel[kernel]; duplicate && prior != device.Name {
				return nil, errors.New("duplicate block kernel identity truth")
			}
			byKernel[kernel] = device.Name
		}
		result.Devices = append(result.Devices, device)
	}
	for _, device := range result.Devices {
		if byName[device.Parent.Value] == nil {
			if alias := byKernel[device.Parent.Value]; alias != "" {
				device.Parent = truthString(alias)
			}
		}
	}
	for _, device := range result.Devices {
		switch {
		case device.Filesystem.Value == "crypto_LUKS":
			device.Encryption = truthString("luks")
		case device.Type.Value == "crypt":
			device.Encryption = truthString("dm-crypt")
		default:
			parent := device.Parent.Value
			complete := true
			for steps := 0; parent != ""; steps++ {
				if steps >= len(byName) {
					return nil, errors.New("cyclic block ancestry truth")
				}
				ancestor := byName[parent]
				if ancestor == nil {
					complete = false
					break
				}
				if ancestor.Type.Value == "crypt" {
					device.Encryption = truthString("inherited-dm-crypt")
					break
				}
				parent = ancestor.Parent.Value
			}
			if device.Encryption.Status != truthSuccess && complete {
				device.Encryption = truthString("none")
			}
		}
	}
	return result, nil
}

func (o vmInventoryOracle) network() (*inventoryv1.NetworkDetails, error) {
	data, status, err := o.optional("ip", "ip -o link show")
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.NetworkDetails{Status: status}
	if status != truthSuccess {
		return result, nil
	}
	rows, err := truthRows(data)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if len(row) < 3 {
			return nil, errors.New("invalid native link truth")
		}
		name := strings.TrimSuffix(row[1], ":")
		name, _, _ = strings.Cut(name, "@")
		link, mac := "", ""
		for i := 2; i+1 < len(row); i++ {
			if row[i] == "state" {
				link = row[i+1]
			}
			if strings.HasPrefix(row[i], "link/") {
				mac = row[i+1]
			}
		}
		if link == "" {
			return nil, errors.New("missing link state truth")
		}
		result.Interfaces = append(result.Interfaces, &inventoryv1.NetworkInterface{Name: name, Mac: truthString(mac), Link: truthString(link), Addresses: &inventoryv1.ObservedStrings{Status: truthSuccess}})
	}
	data, err = o.command("ip -o address show")
	if err != nil {
		return nil, err
	}
	rows, err = truthRows(data)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if len(row) < 4 || (row[2] != "inet" && row[2] != "inet6") {
			return nil, errors.New("invalid address truth")
		}
		name, _, _ := strings.Cut(row[1], "@")
		found := false
		for _, iface := range result.Interfaces {
			if iface.Name == name {
				iface.Addresses.Values = append(iface.Addresses.Values, row[3])
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("address truth has no interface")
		}
	}
	return result, nil
}

func (o vmInventoryOracle) firmware() (*inventoryv1.FirmwareDetails, error) {
	data, err := o.command("if [ -d /sys/firmware/efi ]; then printf uefi; else printf bios; fi")
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.FirmwareDetails{Mode: truthString(string(data)), SecureBoot: truthString("")}
	if result.Mode.Value == "bios" {
		return result, nil
	}
	data, err = o.command(`p=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c; if [ ! -e "$p" ]; then printf 'unavailable\n'; elif [ ! -r "$p" ]; then printf 'denied\n'; else printf 'success\n'; od -An -j4 -N1 -tu1 "$p"; fi`)
	if err != nil {
		return nil, err
	}
	value, status, err := parseTruthStatus(data)
	if err != nil {
		return nil, err
	}
	result.SecureBoot.Status = status
	if status == truthSuccess {
		switch strings.TrimSpace(string(value)) {
		case "0":
			result.SecureBoot.Value = "disabled"
		case "1":
			result.SecureBoot.Value = "enabled"
		default:
			return nil, errors.New("invalid firmware Secure Boot truth")
		}
	}
	return result, nil
}

func (o vmInventoryOracle) tpm() (*inventoryv1.TpmDetails, error) {
	data, err := o.command(`if [ ! -d /sys/class/tpm ]; then printf 'unavailable\n'; elif [ ! -r /sys/class/tpm ]; then printf 'denied\n'; else printf 'success\n'; find /sys/class/tpm -mindepth 1 -maxdepth 1 -printf '%f\n' | sort; fi`)
	if err != nil {
		return nil, err
	}
	value, status, err := parseTruthStatus(data)
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.TpmDetails{Present: &inventoryv1.ObservedBool{Status: status}, Version: truthString("")}
	if status != truthSuccess {
		result.Version.Status = status
		return result, nil
	}
	lines, err := truthLines(value)
	if err != nil {
		return nil, err
	}
	result.Present.Value = len(lines) > 0
	if len(lines) > 0 {
		result.Version, err = o.file("/sys/class/tpm/" + lines[0] + "/tpm_version_major")
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (o vmInventoryOracle) power() (*inventoryv1.PowerDetails, error) {
	chassis, err := o.file("/sys/class/dmi/id/chassis_type")
	if err != nil {
		return nil, err
	}
	data, err := o.command(`if [ ! -d /sys/class/power_supply ]; then printf 'unavailable\n'; elif [ ! -r /sys/class/power_supply ]; then printf 'denied\n'; else printf 'success\n'; for p in /sys/class/power_supply/*; do [ -e "$p" ] || continue; if [ "$(cat "$p/type")" = Battery ]; then basename "$p"; fi; done; fi`)
	if err != nil {
		return nil, err
	}
	value, status, err := parseTruthStatus(data)
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.PowerDetails{Chassis: chassis, Batteries: &inventoryv1.BatteryDetails{Status: status}}
	if status != truthSuccess {
		return result, nil
	}
	names, err := truthLines(value)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		state, err := o.file("/sys/class/power_supply/" + name + "/status")
		if err != nil {
			return nil, err
		}
		capacity, err := o.file("/sys/class/power_supply/" + name + "/capacity")
		if err != nil {
			return nil, err
		}
		number := &inventoryv1.ObservedUint64{Status: capacity.Status}
		if capacity.Status == truthSuccess {
			number.Value, err = parseTruthUint(capacity.Value)
			if err != nil || number.Value > 100 {
				return nil, errors.New("invalid battery capacity truth")
			}
		}
		result.Batteries.Items = append(result.Batteries.Items, &inventoryv1.Battery{Name: name, Status: state, CapacityPercent: number})
	}
	return result, nil
}

func (o vmInventoryOracle) sessions() (*inventoryv1.SessionCounts, error) {
	result := new(inventoryv1.SessionCounts)
	for _, item := range []struct {
		command string
		target  **inventoryv1.ObservedUint64
	}{
		{"loginctl list-users --no-legend --no-pager", &result.Users},
		{"loginctl list-sessions --no-legend --no-pager", &result.Sessions},
	} {
		data, status, err := o.optional("loginctl", item.command)
		if err != nil {
			return nil, err
		}
		rows, err := truthRows(data)
		if err != nil {
			return nil, err
		}
		*item.target = &inventoryv1.ObservedUint64{Status: status, Value: uint64(len(rows))}
	}
	return result, nil
}

func (o vmInventoryOracle) users() (*inventoryv1.LocalUsers, error) {
	data, err := o.command("getent --service=files passwd")
	if err != nil {
		return nil, err
	}
	return parseTruthUsers(data)
}

func parseTruthUsers(data []byte) (*inventoryv1.LocalUsers, error) {
	lines, err := truthLines(data)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("empty local-account truth")
	}
	result := &inventoryv1.LocalUsers{Status: truthSuccess}
	names := make(map[string]bool)
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" || names[fields[0]] {
			return nil, errors.New("invalid local-account truth")
		}
		uid, err := parseTruthUint(fields[2])
		if err != nil {
			return nil, err
		}
		names[fields[0]] = true
		result.Users = append(result.Users, &inventoryv1.LocalUser{Uid: uid, Name: fields[0], Shell: fields[6]})
	}
	return result, nil
}

func (o vmInventoryOracle) backends() (*inventoryv1.BackendDetails, error) {
	result := new(inventoryv1.BackendDetails)
	for _, item := range []struct {
		tool   string
		target **inventoryv1.ObservedBool
	}{
		{"dpkg-query", &result.Dpkg}, {"rpm", &result.Rpm}, {"pacman", &result.Pacman}, {"zypper", &result.Zypper},
		{"rpm-ostree", &result.RpmOstree}, {"nix", &result.Nix}, {"flatpak", &result.Flatpak}, {"snap", &result.Snap},
	} {
		data, err := o.command("if command -v " + nativeQuote(item.tool) + " >/dev/null 2>&1; then printf 1; else printf 0; fi")
		if err != nil {
			return nil, err
		}
		if string(data) != "0" && string(data) != "1" {
			return nil, errors.New("invalid backend presence truth")
		}
		*item.target = truthBool(string(data) == "1")
	}
	return result, nil
}

func (o vmInventoryOracle) applications(backend string) (*inventoryv1.ApplicationDetails, error) {
	command := "flatpak list --system --app --columns=application,version,arch"
	if backend == "snap" {
		command = "snap list"
	}
	data, status, err := o.optional(backend, command)
	if err != nil {
		return nil, err
	}
	result := &inventoryv1.ApplicationDetails{Status: status}
	if status != truthSuccess {
		return result, nil
	}
	lines, err := truthLines(data)
	if err != nil {
		return nil, err
	}
	for i, line := range lines {
		if backend == "snap" {
			fields := strings.Fields(line)
			if i == 0 {
				if len(fields) < 3 || fields[0] != "Name" || fields[1] != "Version" {
					return nil, errors.New("invalid Snap truth header")
				}
				continue
			}
			if len(fields) < 3 {
				return nil, errors.New("invalid Snap truth row")
			}
			result.Applications = append(result.Applications, &inventoryv1.Application{Name: fields[0], Version: truthString(fields[1]), Architecture: truthString(""), Scope: truthString("system")})
		} else {
			fields := strings.Split(line, "\t")
			if len(fields) != 3 || fields[0] == "" {
				return nil, errors.New("invalid Flatpak truth row")
			}
			result.Applications = append(result.Applications, &inventoryv1.Application{Name: fields[0], Version: truthString(fields[1]), Architecture: truthString(fields[2]), Scope: truthString("system")})
		}
	}
	return result, nil
}

// compareVMDetails checks every schema field. Repeated identities are compared as
// multisets, not by count or native presentation order. Only explicitly changing
// measurements have a tolerance; all status transitions remain exact.
func compareVMDetails(before, after, actual *inventoryv1.NativeDetails) error {
	if before == nil || after == nil || actual == nil {
		return errors.New("native inventory details omitted")
	}
	return compareTruthMessage(before.ProtoReflect(), after.ProtoReflect(), actual.ProtoReflect(), "details", before.GetMemory().GetTotalBytes().GetValue())
}

func compareTruthMessage(before, after, actual protoreflect.Message, path string, memory uint64) error {
	fields := before.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		name := path + "." + string(field.Name())
		if field.IsList() {
			a, b, c := before.Get(field).List(), after.Get(field).List(), actual.Get(field).List()
			if a.Len() != b.Len() {
				return fmt.Errorf("%s changed during inspection; no collector verdict", name)
			}
			if a.Len() != c.Len() {
				return fmt.Errorf("native comparison failed for %s count (values withheld)", name)
			}
			usedB, usedC := make([]bool, b.Len()), make([]bool, c.Len())
			for j := range a.Len() {
				bj, cj := truthListIndex(a.Get(j), b, usedB, field), truthListIndex(a.Get(j), c, usedC, field)
				if bj < 0 {
					return fmt.Errorf("%s identities changed during inspection; no collector verdict", name)
				}
				if cj < 0 {
					return fmt.Errorf("native comparison failed for %s identity (values withheld)", name)
				}
				usedB[bj], usedC[cj] = true, true
				if field.Kind() == protoreflect.MessageKind {
					if err := compareTruthMessage(a.Get(j).Message(), b.Get(bj).Message(), c.Get(cj).Message(), name, memory); err != nil {
						return err
					}
				}
			}
			continue
		}
		if field.Kind() == protoreflect.MessageKind {
			if !before.Has(field) && !after.Has(field) && !actual.Has(field) {
				continue
			}
			if !before.Has(field) || !after.Has(field) || !actual.Has(field) {
				return fmt.Errorf("native comparison missing %s", name)
			}
			if err := compareTruthMessage(before.Get(field).Message(), after.Get(field).Message(), actual.Get(field).Message(), name, memory); err != nil {
				return err
			}
			continue
		}
		a, b, c := before.Get(field), after.Get(field), actual.Get(field)
		tolerance := uint64(0)
		switch name {
		case "details.memory.available_bytes.value":
			tolerance = max(uint64(64<<20), memory/20)
		case "details.uptime_seconds.value", "details.boot_time_unix_seconds.value":
			tolerance = 2
		case "details.power.batteries.items.capacity_percent.value":
			tolerance = 1
		}
		if tolerance != 0 {
			if !truthWithin(c.Uint(), a.Uint(), b.Uint(), tolerance) {
				return fmt.Errorf("native comparison outside timing tolerance for %s", name)
			}
		} else {
			if a.Interface() != b.Interface() {
				return fmt.Errorf("%s changed during inspection; no collector verdict", name)
			}
			if a.Interface() != c.Interface() {
				if field.Kind() == protoreflect.EnumKind {
					return fmt.Errorf("native comparison failed for %s: expected %s, observed %s", name, inventoryv1.CollectionStatus(a.Enum()), inventoryv1.CollectionStatus(c.Enum()))
				}
				return fmt.Errorf("native comparison failed for %s (values withheld)", name)
			}
		}
	}
	return nil
}

func truthListIndex(value protoreflect.Value, list protoreflect.List, used []bool, field protoreflect.FieldDescriptor) int {
	for i := range list.Len() {
		if used[i] {
			continue
		}
		if field.Kind() != protoreflect.MessageKind {
			if value.Interface() == list.Get(i).Interface() {
				return i
			}
			continue
		}
		identity := value.Message().Descriptor().Fields().ByName("name")
		if identity != nil && value.Message().Get(identity).String() == list.Get(i).Message().Get(identity).String() {
			if value.Message().Descriptor().FullName() == "lindm.inventory.v1.Application" {
				architecture := value.Message().Descriptor().Fields().ByName("architecture")
				if !proto.Equal(value.Message().Get(architecture).Message().Interface(), list.Get(i).Message().Get(architecture).Message().Interface()) {
					continue
				}
			}
			return i
		}
		if identity == nil && proto.Equal(value.Message().Interface(), list.Get(i).Message().Interface()) {
			return i
		}
	}
	return -1
}

func truthWithin(value, first, last, tolerance uint64) bool {
	low, high := min(first, last), max(first, last)
	if value < low {
		return low-value <= tolerance
	}
	if value > high {
		return value-high <= tolerance
	}
	return true
}

// Record category/field statuses without private names, addresses or user data.
func vmDetailStatuses(details *inventoryv1.NativeDetails) map[string]string {
	result := make(map[string]string)
	var visit func(protoreflect.Message, string)
	visit = func(message protoreflect.Message, path string) {
		message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			name := path + "." + string(field.Name())
			if field.Name() == "status" && field.Kind() == protoreflect.EnumKind {
				result[path] = strings.TrimPrefix(inventoryv1.CollectionStatus(value.Enum()).String(), "COLLECTION_STATUS_")
			} else if field.Kind() == protoreflect.MessageKind {
				if field.IsList() {
					for i := range value.List().Len() {
						visit(value.List().Get(i).Message(), name+"["+strconv.Itoa(i)+"]")
					}
				} else {
					visit(value.Message(), name)
				}
			}
			return true
		})
	}
	visit(details.ProtoReflect(), "details")
	return result
}
