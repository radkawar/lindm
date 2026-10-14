// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/core"
)

func TestRootEncryptionUsesOnlyObservedRootClassification(t *testing.T) {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	failed := inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE
	text := func(value string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: success, Value: value}
	}
	block := func(name, mountpoint, encryption string) *inventoryv1.BlockDevice {
		return &inventoryv1.BlockDevice{Name: name, Mountpoint: text(mountpoint), Encryption: text(encryption)}
	}
	details := func(status inventoryv1.CollectionStatus, devices ...*inventoryv1.BlockDevice) []byte {
		t.Helper()
		// Neighbouring fields are skipped rather than decoded or misread as storage.
		encoded, err := proto.Marshal(&inventoryv1.NativeDetails{
			Cpu:      &inventoryv1.CpuDetails{Model: text("fixture cpu")},
			Storage:  &inventoryv1.StorageDetails{Status: status, Devices: devices},
			Sessions: &inventoryv1.SessionCounts{Users: &inventoryv1.ObservedUint64{Status: success, Value: 2}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	unknownRoot := block("sda2", "/", "")
	unknownRoot.Encryption.Status = failed
	unmountedRoot := block("sda2", "/", "none")
	unmountedRoot.Mountpoint.Status = failed
	const (
		unknown      = adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_UNKNOWN
		encrypted    = adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_ENCRYPTED
		notEncrypted = adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_NOT_ENCRYPTED
	)
	for _, test := range []struct {
		name    string
		details []byte
		want    adminv1.DeviceRootEncryption
	}{
		{"never reported", nil, unknown},
		{"luks mapping", details(success, block("sda", "", "none"), block("sda2", "", "luks"), block("root", "/", "dm-crypt")), encrypted},
		{"inherited dm-crypt", details(success, block("vg-root", "/", "inherited-dm-crypt")), encrypted},
		{"luks container mounted", details(success, block("sda2", "/", "luks")), encrypted},
		{"explicit none", details(success, block("sda1", "/boot/efi", "luks"), block("sda2", "/", "none")), notEncrypted},
		{"unclassified root", details(success, block("sda2", "/", "")), unknown},
		{"failed root classification", details(success, unknownRoot), unknown},
		{"root mount not observed", details(success, unmountedRoot), unknown},
		{"no root", details(success, block("sda1", "/home", "none")), unknown},
		{"conflicting roots", details(success, block("a", "/", "none"), block("b", "/", "dm-crypt")), unknown},
		{"storage collection failed", details(failed, block("sda2", "/", "none")), unknown},
		{"unrecognised signature", details(success, block("sda2", "/", "zfs-native")), unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := rootEncryption(test.details)
			if err != nil || got != test.want {
				t.Fatalf("rootEncryption = %s, %v; want %s", got, err, test.want)
			}
		})
	}
	if _, err := rootEncryption([]byte{0x1a, 0x05, 0x08}); !errors.Is(err, core.ErrInternalState) {
		t.Fatalf("truncated stored details were not an internal-state failure: %v", err)
	}
}
