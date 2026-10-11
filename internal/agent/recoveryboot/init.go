package recoveryboot

import (
	"encoding/binary"
	"errors"
	"strings"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// The recovery image's PID 1 is the static lindm-agent itself, archived as
// /init. No original root, shell, alternate init, credential fallback or
// interpreter is present; every failure, panic or return powers off. Its only
// image-specific inputs are the signed parameters below, which replace the
// identifiers previously substituted into a shell script.
const (
	initParamsPath   = "etc/lindm/recovery-init"
	initParamsHeader = "lindm-recovery-init-v1"
	// initModeUKI is a systemd-boot-selected signed UKI: the selected entry is
	// read from LoaderEntrySelected and the booted image is copied for
	// verification. initModeMeasuredGRUB is a GRUB-measured vendor kernel and
	// initramfs: the action identity is verified by recovery-run from the
	// measured kernel options, so init reads no loader variable or ESP.
	initModeUKI          = "uki"
	initModeMeasuredGRUB = "measured_grub"
	maxInitParamsBytes   = 4096
	// systemd-boot writes a NUL-terminated UTF-16LE entry ID. The previous
	// init read at most 512 bytes after the 4-byte efivarfs attributes.
	maxLoaderEntryBytes  = 512
	moduleLoadPath       = "etc/lindm/modules.load"
	maxModuleLoadBytes   = 64 << 10
	maxModuleLoadEntries = 1024
	// The kernel's MODULE_NAME_LEN is 64 bytes including padding to the
	// unsigned-long-aligned name field; 55 visible bytes always fit.
	maxModuleNameBytes = 55
)

var errInitParams = errors.New("recoveryboot: invalid_init_parameters")

type initParams struct {
	Mode string
	// ESPUUID is the prequalified FAT volume serial for UKI mode and empty for
	// measured GRUB mode, which never mounts the ESP.
	ESPUUID string
	// StateUUID selects off-target custody on an ext4 volume. Empty selects TPM
	// custody, which measured GRUB mode does not support.
	StateUUID string
}

// initParamsFor is the only mapping from a build request to image init
// behavior; writeInitramfs and size accounting both use it.
func initParamsFor(request BuildRequest) initParams {
	if request.BootMode == agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_MEASURED_GRUB {
		return initParams{Mode: initModeMeasuredGRUB, StateUUID: request.StateUUID}
	}
	return initParams{Mode: initModeUKI, ESPUUID: request.ESPUUID, StateUUID: request.StateUUID}
}

func (p initParams) render() string {
	var out strings.Builder
	out.WriteString(initParamsHeader + "\nboot_mode " + p.Mode + "\n")
	if p.ESPUUID != "" {
		out.WriteString("esp_uuid " + p.ESPUUID + "\n")
	}
	if p.StateUUID != "" {
		out.WriteString("state_uuid " + p.StateUUID + "\n")
	}
	return out.String()
}

// parseInitParams accepts only the exact canonical rendering: header, mode,
// mode-required identifiers in fixed order and a final newline.
func parseInitParams(data []byte) (initParams, error) {
	if len(data) == 0 || len(data) > maxInitParamsBytes || data[len(data)-1] != '\n' {
		return initParams{}, errInitParams
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) < 2 || lines[0] != initParamsHeader {
		return initParams{}, errInitParams
	}
	field := func(index int, key string) (string, bool) {
		if index >= len(lines) {
			return "", false
		}
		return strings.CutPrefix(lines[index], key+" ")
	}
	var params initParams
	var ok bool
	if params.Mode, ok = field(1, "boot_mode"); !ok {
		return initParams{}, errInitParams
	}
	next := 2
	switch params.Mode {
	case initModeUKI:
		if params.ESPUUID, ok = field(next, "esp_uuid"); !ok || !fatUUID(params.ESPUUID) {
			return initParams{}, errInitParams
		}
		next++
		if state, present := field(next, "state_uuid"); present {
			if !uuidText(state) {
				return initParams{}, errInitParams
			}
			params.StateUUID = state
			next++
		}
	case initModeMeasuredGRUB:
		if params.StateUUID, ok = field(next, "state_uuid"); !ok || !uuidText(params.StateUUID) {
			return initParams{}, errInitParams
		}
		next++
	default:
		return initParams{}, errInitParams
	}
	if next != len(lines) {
		return initParams{}, errInitParams
	}
	return params, nil
}

// selectedRecoveryEntry decodes LoaderEntrySelected efivarfs bytes: 4 attribute
// bytes, then printable-ASCII UTF-16LE code units optionally terminated by one
// final NUL. The entry is only a safe path selector of the exact form
// lindm-recovery-<lowercase canonical UUID>.efi; recovery-run authenticates
// the copied image and any capsule independently.
func selectedRecoveryEntry(data []byte) (entry, actionID string, err error) {
	invalid := errors.New("recoveryboot: invalid_selected_recovery_entry")
	if len(data) < 4 || len(data) > 4+maxLoaderEntryBytes || len(data)%2 != 0 {
		return "", "", invalid
	}
	payload := data[4:]
	var text strings.Builder
	for i := 0; i < len(payload); i += 2 {
		unit := binary.LittleEndian.Uint16(payload[i:])
		if unit == 0 {
			if i != len(payload)-2 {
				return "", "", invalid
			}
			break
		}
		if unit < 0x21 || unit > 0x7e {
			return "", "", invalid
		}
		text.WriteByte(byte(unit))
	}
	entry = text.String()
	action, prefixed := strings.CutPrefix(entry, "lindm-recovery-")
	action, suffixed := strings.CutSuffix(action, ".efi")
	if !prefixed || !suffixed || !uuidText(action) {
		return "", "", invalid
	}
	return entry, action, nil
}

// parseModuleLoad reads the signed image's ordered module list. Every line is a
// newline-terminated kernel module name; the file is resolved to
// lib/modules/<running release>/<name>.ko and loaded unchanged.
func parseModuleLoad(data []byte) ([]string, error) {
	invalid := errors.New("recoveryboot: invalid_module_list")
	if len(data) > maxModuleLoadBytes || (len(data) != 0 && data[len(data)-1] != '\n') {
		return nil, invalid
	}
	if len(data) == 0 {
		return nil, nil
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > maxModuleLoadEntries {
		return nil, invalid
	}
	seen := make(map[string]bool, len(lines))
	for _, name := range lines {
		if name == "" || len(name) > maxModuleNameBytes || seen[name] {
			return nil, invalid
		}
		for _, c := range name {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
				return nil, invalid
			}
		}
		seen[name] = true
	}
	return lines, nil
}
