package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
)

func TestFinalGRUBBootFixture(t *testing.T) {
	loaded, err := FinalGRUBBoot(fixtureEvents(t))
	if err != nil {
		t.Fatalf("FinalGRUBBoot: %v", err)
	}
	if loaded.KernelPath != fixtureKernelPath || loaded.InitrdPath != fixtureInitrdPath || loaded.KernelOptions != fixtureKernelOptions ||
		!bytes.Equal(loaded.KernelSHA256, mustHex(t, fixtureKernelSHA256)) || !bytes.Equal(loaded.InitrdSHA256, mustHex(t, fixtureInitrdSHA256)) {
		t.Fatalf("FinalGRUBBoot = %+v", loaded)
	}
}

func TestFinalGRUBBootRejects(t *testing.T) {
	events := fixtureEvents(t)
	const (
		device = "(hd0,gpt3)"
		kernel = device + fixtureKernelPath
		initrd = device + fixtureInitrdPath
	)
	secondInitrd := replaceEvents(events, fixtureInitrdCommand, fixtureInitrdIndex+1,
		grubCommand(t, "grub_cmd: initrd "+initrd+" "+device+"/boot/extra.img"),
		events[fixtureInitrdIndex],
		grubFile(device+"/boot/extra.img", []byte("extra")),
	)
	relabeled := bytes.Clone(events[fixtureCmdlineIndex].Data)
	relabeled[len(relabeled)-2] = 'X'
	tamperedLabel := events[fixtureCmdlineIndex]
	tamperedLabel.Data = relabeled
	unmeasuredKernel := events[fixtureKernelIndex]
	unmeasuredKernel.SHA256 = nil

	for name, test := range map[string]struct {
		events []Event
		want   error
	}{
		"no linux command":   {events[:fixtureLinuxIndex], errGRUBLinuxMissing},
		"second initrd path": {secondInitrd, errGRUBInitrdMultiple},
		"trailing grub command": {
			append(events[:len(events):len(events)], grubCommand(t, "grub_cmd: insmod evil")), errGRUBTrailingMeasurement,
		},
		"trailing file measurement": {
			append(events[:len(events):len(events)], grubFile(device+"/boot/evil", []byte("evil"))), errGRUBTrailingMeasurement,
		},
		"changed options": {
			replaceEvents(events, fixtureCmdlineIndex, fixtureCmdlineIndex+1, grubCommand(t, "kernel_cmdline: "+kernel+" "+fixtureKernelOptions+" init=/bin/sh")),
			errGRUBKernelOptions,
		},
		"mismatched initrd device": {
			replaceEvents(events, fixtureInitrdCommand, fixtureInitrdIndex+1,
				grubCommand(t, "grub_cmd: initrd (hd1,gpt1)"+fixtureInitrdPath),
				grubFile("(hd1,gpt1)"+fixtureInitrdPath, []byte("initrd")),
			),
			errGRUBDeviceMismatch,
		},
		"mismatched kernel file device": {
			replaceEvents(events, fixtureKernelIndex, fixtureKernelIndex+1, grubFile("(hd1,gpt3)"+fixtureKernelPath, []byte("kernel"))),
			errGRUBDeviceMismatch,
		},
		"missing kernel_cmdline": {
			replaceEvents(events, fixtureCmdlineIndex, fixtureCmdlineIndex+1), errGRUBKernelCmdline,
		},
		"missing initrd": {
			replaceEvents(events, fixtureInitrdCommand, fixtureInitrdIndex+1), errGRUBSequenceIncomplete,
		},
		"kernel_cmdline label not bound to digest": {
			replaceEvents(events, fixtureCmdlineIndex, fixtureCmdlineIndex+1, tamperedLabel), errGRUBMeasurementMismatch,
		},
		"kernel file without sha256": {
			replaceEvents(events, fixtureKernelIndex, fixtureKernelIndex+1, unmeasuredKernel), errGRUBKernelMeasurement,
		},
		"linux without device after device-labelled files": {
			replaceEvents(events, fixtureLinuxIndex, fixtureLinuxIndex+1, grubCommand(t, "grub_cmd: linux "+fixtureKernelPath+" "+fixtureKernelOptions)),
			errGRUBDeviceMismatch,
		},
		"linux with empty device": {
			replaceEvents(events, fixtureLinuxIndex, fixtureLinuxIndex+1, grubCommand(t, "grub_cmd: linux ()"+fixtureKernelPath+" "+fixtureKernelOptions)),
			errGRUBLinuxMalformed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FinalGRUBBoot(test.events); !errors.Is(err, test.want) {
				t.Fatalf("FinalGRUBBoot error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestFinalGRUBBootUsesLastLinuxCommand(t *testing.T) {
	events := fixtureEvents(t)
	// An earlier, abandoned linux command is superseded by the final one.
	events = replaceEvents(events, fixtureLinuxIndex, fixtureLinuxIndex,
		grubCommand(t, "grub_cmd: linux (hd0,gpt3)/boot/vmlinuz-old quiet"),
	)
	loaded, err := FinalGRUBBoot(events)
	if err != nil || loaded.KernelPath != fixtureKernelPath {
		t.Fatalf("FinalGRUBBoot = %+v, %v", loaded, err)
	}
}

// Debian/Ubuntu grub.d entries name files relative to $root ("linux /vmlinuz").
// A sequence whose every measurement omits the device is consistent.
func TestFinalGRUBBootAcceptsRootRelativePaths(t *testing.T) {
	events := fixtureEvents(t)
	const kernel, initrd = "/vmlinuz-6.8.0-142-generic", "/initrd.img-6.8.0-142-generic"
	for index, event := range map[int]Event{
		fixtureLinuxIndex:    grubCommand(t, "grub_cmd: linux "+kernel+" "+fixtureKernelOptions),
		fixtureKernelIndex:   grubFile(kernel, []byte("kernel")),
		fixtureCmdlineIndex:  grubCommand(t, "kernel_cmdline: "+kernel+" "+fixtureKernelOptions),
		fixtureInitrdCommand: grubCommand(t, "grub_cmd: initrd "+initrd),
		fixtureInitrdIndex:   grubFile(initrd, []byte("initrd")),
	} {
		events = replaceEvents(events, index, index+1, event)
	}
	loaded, err := FinalGRUBBoot(events)
	kernelDigest := sha256.Sum256([]byte("kernel"))
	if err != nil || loaded.KernelPath != kernel || !bytes.Equal(loaded.KernelSHA256, kernelDigest[:]) {
		t.Fatalf("FinalGRUBBoot = %+v, %v", loaded, err)
	}
}

func TestSecureBootEnabled(t *testing.T) {
	events := fixtureEvents(t)
	if err := SecureBootEnabled(events); err != nil {
		t.Fatalf("SecureBootEnabled: %v", err)
	}
	disabled := events[fixtureSecureBoot]
	disabled.Data = bytes.Clone(disabled.Data)
	disabled.Data[len(disabled.Data)-1] = 0
	digest := sha256.Sum256(disabled.Data)
	disabled.SHA256 = digest[:]
	relabeled := events[fixtureSecureBoot]
	relabeled.Data = disabled.Data
	malformed := events[fixtureSecureBoot]
	malformed.Data = malformed.Data[:len(malformed.Data)-1]

	for name, test := range map[string]struct {
		events []Event
		want   error
	}{
		"disabled":    {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1, disabled), errSecureBootDisabled},
		"relabeled":   {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1, relabeled), errSecureBootDigestMismatch},
		"missing":     {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1), errSecureBootCount},
		"duplicate":   {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot, events[fixtureSecureBoot]), errSecureBootCount},
		"malformed":   {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1, malformed), errSecureBootMalformed},
		"wrong pcr":   {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1, Event{PCR: 1, Type: evEFIVariableDriverConfig, SHA256: events[fixtureSecureBoot].SHA256, Data: events[fixtureSecureBoot].Data}), errSecureBootCount},
		"two-byte on": {replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1, secureBootEvent(t, events[fixtureSecureBoot], []byte{1, 0})), errSecureBootMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			if err := SecureBootEnabled(test.events); !errors.Is(err, test.want) {
				t.Fatalf("SecureBootEnabled error = %v, want %v", err, test.want)
			}
		})
	}
}

// secureBootEvent appends value bytes to the SecureBoot event without updating
// VariableDataLength, producing a structurally inconsistent event.
func secureBootEvent(t *testing.T, event Event, value []byte) Event {
	t.Helper()
	data := append(bytes.Clone(event.Data[:len(event.Data)-1]), value...)
	digest := sha256.Sum256(data)
	return Event{PCR: event.PCR, Type: event.Type, SHA256: digest[:], Data: data}
}

// Ubuntu 24.04 arm64 stock boot (signed shim+GRUB 2.12, kernel 6.8.0-142, swtpm,
// AAVMF Secure Boot): device-less grub.d paths, then the kernel EFI stub's own
// PCR 9 load-options and initrd tagged events.
const (
	ubuntuFixturePath       = "testdata/ubuntu2404-arm64-stock.eventlog"
	ubuntuLoadOptionsIndex  = 115
	ubuntuStubInitrdIndex   = 116
	ubuntuFixtureKernelPath = "/vmlinuz-6.8.0-142-generic"
	ubuntuFixtureInitrdPath = "/initrd.img-6.8.0-142-generic"
)

func ubuntuFixtureEvents(t *testing.T) []Event {
	t.Helper()
	data, err := os.ReadFile(ubuntuFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	events, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	return events
}

func TestFinalGRUBBootAcceptsKernelStubEvents(t *testing.T) {
	events := ubuntuFixtureEvents(t)
	loaded, err := FinalGRUBBoot(events)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KernelPath != ubuntuFixtureKernelPath || loaded.InitrdPath != ubuntuFixtureInitrdPath || !bytes.Equal(loaded.InitrdSHA256, events[ubuntuStubInitrdIndex].SHA256) {
		t.Fatalf("FinalGRUBBoot = %+v", loaded)
	}
	// The stub's initrd event is optional; its load-options event is too.
	for _, trimmed := range [][]Event{events[:ubuntuStubInitrdIndex], replaceEvents(events, ubuntuLoadOptionsIndex, ubuntuLoadOptionsIndex+1)} {
		if _, err := FinalGRUBBoot(trimmed); err != nil {
			t.Fatalf("stub subset refused: %v", err)
		}
	}
}

func TestFinalGRUBBootRejectsForeignStubEvents(t *testing.T) {
	events := ubuntuFixtureEvents(t)
	options, initrd := events[ubuntuLoadOptionsIndex], events[ubuntuStubInitrdIndex]
	otherInitrd := initrd
	otherInitrd.SHA256 = bytes.Repeat([]byte{7}, sha256.Size)
	wrongPCR := initrd
	wrongPCR.PCR = grubCommandPCR
	unknownTag := initrd
	unknownTag.Data = bytes.Clone(initrd.Data)
	unknownTag.Data[0] ^= 1
	badSize := initrd
	badSize.Data = append(bytes.Clone(initrd.Data), 0)
	ipl := initrd
	ipl.Type = evIPL
	for name, trailing := range map[string][]Event{
		"different initrd digest": {options, otherInitrd},
		"duplicate initrd":        {options, initrd, initrd},
		"duplicate load options":  {options, options, initrd},
		"options after initrd":    {initrd, options},
		"wrong pcr":               {options, wrongPCR},
		"unknown tag":             {options, unknownTag},
		"inconsistent tag size":   {options, badSize},
		"untagged event":          {options, ipl},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FinalGRUBBoot(append(events[:ubuntuLoadOptionsIndex:ubuntuLoadOptionsIndex], trailing...)); !errors.Is(err, errGRUBTrailingMeasurement) {
				t.Fatalf("FinalGRUBBoot error = %v", err)
			}
		})
	}
}
