package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"unicode/utf16"
)

const (
	evEventTag                = 0x6
	evIPL                     = 0xd
	evEFIVariableDriverConfig = 0x80000001
	// The Linux EFI stub (drivers/firmware/efi/libstub) measures its load
	// options and the initrd it loads as EV_EVENT_TAG events in PCR 9, after
	// GRUB hands over. IDs and descriptions are the stub's fixed constants.
	stubLoadOptionsTag      = 0x8F3B22ED
	stubLoadOptionsText     = "LOADED_IMAGE::LoadOptions\x00"
	stubInitrdTag           = 0x8F3B22EC
	stubInitrdText          = "Linux initrd\x00"
	grubCommandPCR          = 8
	grubFilePCR             = 9
	secureBootPCR           = 7
	grubCommandPrefix       = "grub_cmd: "
	grubLinuxCommand        = "linux "
	grubInitrdCommand       = "initrd "
	grubKernelCmdlinePrefix = "kernel_cmdline: "
	// secureBootName is "SecureBoot" in UTF-16LE.
	secureBootName = "S\x00e\x00c\x00u\x00r\x00e\x00B\x00o\x00o\x00t\x00"
)

// efiGlobalVariableGUID is 8be4df61-93ca-11d2-aa0d-00e098032b8c in EFI_GUID
// byte order (first three fields little-endian).
var efiGlobalVariableGUID = [16]byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}

var (
	errGRUBLinuxMissing         = errors.New("measuredboot: grub_linux_missing")
	errGRUBLinuxMalformed       = errors.New("measuredboot: grub_linux_malformed")
	errGRUBMeasurementMismatch  = errors.New("measuredboot: grub_command_digest_mismatch")
	errGRUBDeviceMismatch       = errors.New("measuredboot: grub_device_mismatch")
	errGRUBKernelMeasurement    = errors.New("measuredboot: grub_kernel_measurement_invalid")
	errGRUBKernelCmdline        = errors.New("measuredboot: grub_kernel_cmdline_invalid")
	errGRUBKernelPathMismatch   = errors.New("measuredboot: grub_kernel_path_mismatch")
	errGRUBKernelOptions        = errors.New("measuredboot: grub_kernel_options_mismatch")
	errGRUBInitrdCommand        = errors.New("measuredboot: grub_initrd_command_invalid")
	errGRUBInitrdMultiple       = errors.New("measuredboot: grub_initrd_multiple")
	errGRUBInitrdMeasurement    = errors.New("measuredboot: grub_initrd_measurement_invalid")
	errGRUBSequenceIncomplete   = errors.New("measuredboot: grub_boot_sequence_incomplete")
	errGRUBTrailingMeasurement  = errors.New("measuredboot: grub_trailing_measurement")
	errSecureBootMalformed      = errors.New("measuredboot: secure_boot_event_malformed")
	errSecureBootDigestMismatch = errors.New("measuredboot: secure_boot_event_digest_mismatch")
	errSecureBootDisabled       = errors.New("measuredboot: secure_boot_disabled")
	errSecureBootCount          = errors.New("measuredboot: secure_boot_event_count")
)

// Loaded is what the final GRUB boot measured. Paths are GRUB paths without
// any "(device)" prefix.
type Loaded struct {
	KernelPath    string
	KernelOptions string
	KernelSHA256  []byte
	InitrdPath    string
	InitrdSHA256  []byte
}

// FinalGRUBBoot returns the kernel, options and initramfs loaded by the last
// PCR 8 "grub_cmd: linux" event. After it, PCR 8/9 events must be exactly the
// PCR 9 kernel file, the PCR 8 kernel_cmdline with identical options, one PCR 8
// "grub_cmd: initrd" with a single path and the PCR 9 initramfs file, all on the
// same GRUB device, or all without one. PCR 8 text must hash to its SHA-256
// digest, so the matched strings are bound to the replayed PCR value. GRUB
// `echo` commands (Debian's "Loading …" messages) may appear anywhere after
// `linux`; they load nothing and are skipped only when their text matches its
// digest. The only later PCR 8/9 events accepted are the measured kernel's own
// EFI stub events: at most one load-options event, then at most one initrd
// event whose digest is the GRUB-measured initramfs digest.
func FinalGRUBBoot(events []Event) (*Loaded, error) {
	last := -1
	for i, event := range events {
		if event.PCR != grubCommandPCR {
			continue
		}
		if text, ok := eventText(event); ok && strings.HasPrefix(text, grubCommandPrefix+grubLinuxCommand) {
			last = i
		}
	}
	if last < 0 {
		return nil, errGRUBLinuxMissing
	}
	body, err := measuredCommand(events[last], grubCommandPrefix, errGRUBLinuxMalformed)
	if err != nil {
		return nil, err
	}
	kernelArgument, options, _ := strings.Cut(strings.TrimPrefix(body, grubLinuxCommand), " ")
	device, kernelPath, ok := splitDevicePath(kernelArgument)
	if !ok {
		return nil, errGRUBLinuxMalformed
	}
	var sequence [4]Event
	var trailing []Event
	count := 0
	for _, event := range events[last+1:] {
		if event.PCR != grubCommandPCR && event.PCR != grubFilePCR {
			continue
		}
		if echo, err := grubEcho(event); err != nil {
			return nil, err
		} else if echo {
			continue
		}
		if count < len(sequence) {
			sequence[count] = event
		} else {
			trailing = append(trailing, event)
		}
		count++
	}
	// Check slots in log order so a missing or substituted event reports the
	// first expected measurement that is absent.
	slot := func(index int) (Event, error) {
		if index >= count {
			return Event{}, errGRUBSequenceIncomplete
		}
		return sequence[index], nil
	}
	event, err := slot(0)
	if err != nil {
		return nil, err
	}
	kernelSHA256, err := measuredFile(event, device, kernelPath, errGRUBKernelMeasurement, errGRUBKernelPathMismatch)
	if err != nil {
		return nil, err
	}
	if event, err = slot(1); err != nil {
		return nil, err
	}
	if err := checkKernelCmdline(event, device, kernelPath, options); err != nil {
		return nil, err
	}
	if event, err = slot(2); err != nil {
		return nil, err
	}
	initrdCommand, err := measuredCommand(event, grubCommandPrefix, errGRUBInitrdCommand)
	if err != nil {
		return nil, err
	}
	initrdArgument, found := strings.CutPrefix(initrdCommand, grubInitrdCommand)
	if !found {
		return nil, errGRUBInitrdCommand
	}
	if strings.Contains(initrdArgument, " ") {
		return nil, errGRUBInitrdMultiple
	}
	initrdDevice, initrdPath, ok := splitDevicePath(initrdArgument)
	if !ok {
		return nil, errGRUBInitrdCommand
	}
	if initrdDevice != device {
		return nil, errGRUBDeviceMismatch
	}
	if event, err = slot(3); err != nil {
		return nil, err
	}
	initrdSHA256, err := measuredFile(event, device, initrdPath, errGRUBInitrdMeasurement, errGRUBInitrdMeasurement)
	if err != nil {
		return nil, err
	}
	if err := checkStubEvents(trailing, stubLoadOptions(kernelArgument, options), initrdSHA256); err != nil {
		return nil, err
	}
	return &Loaded{
		KernelPath:    kernelPath,
		KernelOptions: options,
		KernelSHA256:  bytes.Clone(kernelSHA256),
		InitrdPath:    initrdPath,
		InitrdSHA256:  bytes.Clone(initrdSHA256),
	}, nil
}

// grubEcho reports whether a PCR 8 event is a digest-bound `grub_cmd: echo`.
// An echo label whose digest does not match its text is rejected outright.
func grubEcho(event Event) (bool, error) {
	text, ok := eventText(event)
	if event.PCR != grubCommandPCR || !ok || (text != grubCommandPrefix+"echo" && !strings.HasPrefix(text, grubCommandPrefix+"echo ")) {
		return false, nil
	}
	if _, err := measuredCommand(event, grubCommandPrefix, errGRUBMeasurementMismatch); err != nil {
		return false, err
	}
	return true, nil
}

// checkStubEvents admits only the Linux EFI stub's tagged PCR 9 events, in the
// stub's order and each at most once. Its load-options event must measure the
// command line GRUB passed for the measured linux command, and its initrd event
// exactly the initramfs GRUB measured.
func checkStubEvents(trailing []Event, loadOptions [][]byte, initrdSHA256 []byte) error {
	next := 0
	for _, event := range trailing {
		if event.PCR != grubFilePCR || event.Type != evEventTag || len(event.SHA256) != sha256.Size {
			return errGRUBTrailingMeasurement
		}
		id, ok := taggedEvent(event.Data)
		switch {
		case ok && id == stubLoadOptionsTag && next == 0 && string(event.Data[8:]) == stubLoadOptionsText && slices.ContainsFunc(loadOptions, func(digest []byte) bool { return bytes.Equal(event.SHA256, digest) }):
			next = 1
		case ok && id == stubInitrdTag && next < 2 && string(event.Data[8:]) == stubInitrdText && bytes.Equal(event.SHA256, initrdSHA256):
			next = 2
		default:
			return errGRUBTrailingMeasurement
		}
	}
	return nil
}

// stubLoadOptions returns the digests of the UTF-16LE load options GRUB hands
// the kernel for "linux <argument> <options>": "BOOT_IMAGE=<argument>" plus the
// options, without (GRUB 2.12) or with (GRUB 2.14) a terminating U+0000.
func stubLoadOptions(argument, options string) [][]byte {
	text := "BOOT_IMAGE=" + argument
	if options != "" {
		text += " " + options
	}
	encoded := make([]byte, 0, 2*len(text)+2)
	for _, unit := range utf16.Encode([]rune(text)) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	bare := sha256.Sum256(encoded)
	terminated := sha256.Sum256(append(encoded, 0, 0))
	return [][]byte{bare[:], terminated[:]}
}

// taggedEvent returns the ID of a TCG_PCClientTaggedEvent whose declared data
// size is exactly the rest of the event.
func taggedEvent(data []byte) (uint32, bool) {
	if len(data) < 8 || uint64(binary.LittleEndian.Uint32(data[4:8])) != uint64(len(data)-8) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[:4]), true
}

func checkKernelCmdline(event Event, device, kernelPath, options string) error {
	body, err := measuredCommand(event, grubKernelCmdlinePrefix, errGRUBKernelCmdline)
	if err != nil {
		return err
	}
	argument, measuredOptions, _ := strings.Cut(body, " ")
	measuredDevice, measuredPath, ok := splitDevicePath(argument)
	switch {
	case !ok:
		return errGRUBKernelCmdline
	case measuredDevice != device:
		return errGRUBDeviceMismatch
	case measuredPath != kernelPath:
		return errGRUBKernelPathMismatch
	case measuredOptions != options:
		return errGRUBKernelOptions
	}
	return nil
}

// measuredCommand returns the text after prefix of a PCR 8 GRUB string event
// whose SHA-256 digest is the digest of that text, as GRUB measures it.
func measuredCommand(event Event, prefix string, malformed error) (string, error) {
	text, ok := eventText(event)
	if event.PCR != grubCommandPCR || !ok {
		return "", malformed
	}
	body, found := strings.CutPrefix(text, prefix)
	if !found {
		return "", malformed
	}
	digest := sha256.Sum256([]byte(body))
	if !bytes.Equal(event.SHA256, digest[:]) {
		return "", errGRUBMeasurementMismatch
	}
	return body, nil
}

// measuredFile returns the SHA-256 digest of a PCR 9 GRUB file event for
// "(device)path".
func measuredFile(event Event, device, path string, malformed, pathMismatch error) ([]byte, error) {
	text, ok := eventText(event)
	if event.PCR != grubFilePCR || !ok || len(event.SHA256) != sha256.Size {
		return nil, malformed
	}
	measuredDevice, measuredPath, ok := splitDevicePath(text)
	switch {
	case !ok:
		return nil, malformed
	case measuredDevice != device:
		return nil, errGRUBDeviceMismatch
	case measuredPath != path:
		return nil, pathMismatch
	}
	return event.SHA256, nil
}

// eventText returns the text of an EV_IPL event whose data is a string with a
// single terminating NUL.
func eventText(event Event) (string, bool) {
	if event.Type != evIPL || len(event.Data) == 0 || event.Data[len(event.Data)-1] != 0 {
		return "", false
	}
	text := event.Data[:len(event.Data)-1]
	if bytes.IndexByte(text, 0) >= 0 {
		return "", false
	}
	return string(text), true
}

// splitDevicePath splits "(device)/path", or a bare "/path" relative to GRUB's
// $root (Debian/Ubuntu grub.d entries), where device is a nonempty token
// without spaces or parentheses and path is an absolute GRUB path without
// spaces. Callers require the same (possibly empty) device across the kernel,
// command line and initramfs; the file digests, not the labels, bind content.
func splitDevicePath(value string) (string, string, bool) {
	device, path := "", value
	if rest, found := strings.CutPrefix(value, "("); found {
		var closed bool
		device, path, closed = strings.Cut(rest, ")")
		if !closed || device == "" || strings.ContainsAny(device, " ()") {
			return "", "", false
		}
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t()") {
		return "", "", false
	}
	return device, path, true
}

// SecureBootEnabled requires exactly one PCR 7 EV_EFI_VARIABLE_DRIVER_CONFIG
// event for the EFI global SecureBoot variable, whose SHA-256 digest matches its
// data and whose value is exactly 0x01. Other PCR 7 driver-config events must
// be well formed.
func SecureBootEnabled(events []Event) error {
	found := 0
	for _, event := range events {
		if event.PCR != secureBootPCR || event.Type != evEFIVariableDriverConfig {
			continue
		}
		guid, variable, value, ok := uefiVariable(event.Data)
		if !ok {
			return errSecureBootMalformed
		}
		if guid != efiGlobalVariableGUID || string(variable) != secureBootName {
			continue
		}
		found++
		digest := sha256.Sum256(event.Data)
		if !bytes.Equal(event.SHA256, digest[:]) {
			return errSecureBootDigestMismatch
		}
		if !bytes.Equal(value, []byte{1}) {
			return errSecureBootDisabled
		}
	}
	if found != 1 {
		return errSecureBootCount
	}
	return nil
}

// uefiVariable parses UEFI_VARIABLE_DATA: VariableName GUID,
// UnicodeNameLength (UINT64), VariableDataLength (UINT64), UTF-16LE name and
// data, with no trailing bytes.
func uefiVariable(data []byte) ([16]byte, []byte, []byte, bool) {
	const header = 32
	if len(data) < header {
		return [16]byte{}, nil, nil, false
	}
	guid := [16]byte(data[:16])
	nameLength := binary.LittleEndian.Uint64(data[16:24])
	valueLength := binary.LittleEndian.Uint64(data[24:32])
	remaining := uint64(len(data) - header)
	if nameLength > remaining/2 || valueLength != remaining-2*nameLength {
		return [16]byte{}, nil, nil, false
	}
	nameEnd := header + 2*int(nameLength)
	return guid, data[header:nameEnd], data[nameEnd:], true
}

// GRUBLoaderInfo reports whether a Boot Loader Interface LoaderInfo value names
// GRUB. Upstream's bli module publishes PACKAGE_STRING ("GRUB 2.14"); the
// openSUSE build publishes "GRUB2 2.14" (observed on Tumbleweed aarch64). The
// value is a loader self-report, not an authentication of the boot chain.
func GRUBLoaderInfo(loader string) bool {
	return strings.HasPrefix(loader, "GRUB ") || strings.HasPrefix(loader, "GRUB2 ")
}
