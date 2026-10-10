//go:build linux

package vmlab

import (
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestRuntimeFirmwareRequiresObservedSecureBootOnAndOff(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		hardware := &VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{SecureBoot: enabled}}
		want, opposite := "disabled", "enabled"
		if enabled {
			want, opposite = opposite, want
		}
		observed := &inventoryv1.FirmwareDetails{Mode: truthString("uefi"), SecureBoot: truthString(want)}
		if err := compareVMFirmware(hardware, observed); err != nil {
			t.Fatalf("matching observed Secure Boot %q rejected: %v", want, err)
		}
		observed.SecureBoot = truthString(opposite)
		if err := compareVMFirmware(hardware, observed); err == nil {
			t.Fatalf("requested Secure Boot %q accepted observed %q", want, opposite)
		}
		for _, status := range []inventoryv1.CollectionStatus{truthUnavailable, truthDenied, inventoryv1.CollectionStatus_COLLECTION_STATUS_INVALID_OUTPUT} {
			observed.SecureBoot = &inventoryv1.ObservedString{Status: status, Value: want}
			if err := compareVMFirmware(hardware, observed); err == nil {
				t.Fatalf("requested Secure Boot %q accepted unproven value with status %s", want, status)
			}
		}
		observed.SecureBoot = truthString(want)
		observed.Mode = truthString("bios")
		if err := compareVMFirmware(hardware, observed); err == nil {
			t.Fatal("explicit UEFI accepted BIOS observation")
		}
		if err := compareVMFirmware(hardware, nil); err == nil {
			t.Fatal("explicit UEFI accepted missing firmware evidence")
		}
	}
}

func TestRuntimeBIOSDoesNotRequireEFIVariables(t *testing.T) {
	hardware := &VMHardwareOptions{}
	observed := &inventoryv1.FirmwareDetails{Mode: truthString("bios"), SecureBoot: truthString("")}
	if err := compareVMFirmware(hardware, observed); err != nil {
		t.Fatalf("BIOS with legitimately unavailable Secure Boot rejected: %v", err)
	}
	observed.Mode = truthString("uefi")
	if err := compareVMFirmware(hardware, observed); err == nil {
		t.Fatal("BIOS request accepted UEFI observation")
	}
	observed.Mode = truthString("")
	if err := compareVMFirmware(hardware, observed); err == nil {
		t.Fatal("BIOS request accepted unobserved mode")
	}
}

func TestRuntimeFirmwareWithholdsUnexpectedGuestValues(t *testing.T) {
	hardware := &VMHardwareOptions{Firmware: &EncryptedFirmwareOptions{}}
	observed := &inventoryv1.FirmwareDetails{Mode: truthString("uefi"), SecureBoot: truthString("private-guest-value")}
	err := compareVMFirmware(hardware, observed)
	if err == nil || strings.Contains(err.Error(), "private-guest-value") {
		t.Fatalf("unexpected guest value accepted or leaked: %v", err)
	}
}

func TestRuntimeFirmwareSetupModeMustBeObserved(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		setup, err := parseFirmwareSetupMode([]byte(" 0\n"), enabled)
		if err != nil || setup == nil || *setup {
			t.Fatalf("observed enrolled setup mode: %v, %v", setup, err)
		}
		setup, err = parseFirmwareSetupMode([]byte(" 1\n"), enabled)
		if enabled {
			if err == nil || setup != nil {
				t.Fatal("requested Secure Boot accepted firmware SetupMode")
			}
		} else if err != nil || setup == nil || !*setup {
			t.Fatalf("observed SetupMode lost with Secure Boot off: %v, %v", setup, err)
		}
		for _, invalid := range []string{"", "2\n", "-1\n", "0\n1\n", "unavailable\n"} {
			if setup, err := parseFirmwareSetupMode([]byte(invalid), enabled); err == nil || setup != nil {
				t.Fatalf("accepted invalid SetupMode %q: %v, %v", invalid, setup, err)
			}
		}
	}
}
