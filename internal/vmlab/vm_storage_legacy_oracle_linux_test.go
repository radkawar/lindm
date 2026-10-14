// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const truthCommandFailure = inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE

// Real util-linux 2.32.1 replies; provenance.json records the image and method.
func TestStorageTruthCapturedEL8LegacyPairs(t *testing.T) {
	data, err := os.ReadFile("../agent/inventory/testdata/lsblk-almalinux810-aarch64/lsblk.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture map[string]struct {
		Command  []string `json:"command"`
		Stdout   string   `json:"stdout"`
		Stderr   string   `json:"stderr"`
		ExitCode int      `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	var commands []string
	pairs, status, err := storageTruthPairs(func(tool, command string) ([]byte, inventoryv1.CollectionStatus, error) {
		commands = append(commands, command)
		for _, reply := range capture {
			if tool != "lsblk" || reply.Command[0] != "/usr/bin/lsblk" || strings.Join(append([]string{"lsblk"}, reply.Command[1:]...), " ") != command {
				continue
			}
			// Mirrors optional: a nonzero exit or any stderr is a native failure.
			if reply.ExitCode != 0 || reply.Stderr != "" {
				return nil, truthCommandFailure, nil
			}
			return []byte(reply.Stdout), truthSuccess, nil
		}
		t.Fatalf("uncaptured native command %q", command)
		return nil, 0, nil
	})
	if err != nil || status != truthSuccess || !slices.Equal(commands, []string{storageTruthCommand, "lsblk --version", legacyStorageTruthCommand}) {
		t.Fatalf("native lsblk selection = %v, %v, %v", commands, status, err)
	}
	storage, err := parseTruthStorage(pairs, status)
	if err != nil || storage.Status != truthSuccess || len(storage.Devices) != 5 {
		t.Fatalf("legacy storage truth = %v, %v", storage, err)
	}
	devices := make(map[string]*inventoryv1.BlockDevice)
	for _, device := range storage.Devices {
		devices[device.Name] = device
		// The agent reports these uncollected columns as UNAVAILABLE too.
		if device.Identity.GptDiskGuid.Status != truthUnavailable || device.Identity.LuksVersion.Status != truthUnavailable {
			t.Fatalf("uncollected column reported: %v", device)
		}
	}
	disk, root, appliance := devices["sda"], devices["sda3"], devices["sdb"]
	if disk == nil || root == nil || appliance == nil {
		t.Fatalf("captured devices missing: %v", storage)
	}
	if disk.SizeBytes.Value != 10737418240 || disk.Identity.Model.Value != "QEMU HARDDISK" || disk.Identity.Serial.Value != "hd0" ||
		disk.Identity.Firmware.Value != "2.5+" || disk.Identity.Transport.Status != truthUnavailable {
		t.Fatalf("captured disk = %v", disk)
	}
	if root.Mountpoint.Value != "/" || root.Filesystem.Value != "xfs" || root.Parent.Value != "sda" || root.Encryption.Value != "none" ||
		root.Identity.FilesystemUuid.Value != "95e58dd6-7888-4110-8de2-40a665c36bb2" ||
		root.Identity.PartitionUuid.Value != "da60e1cf-a0bc-4573-93f8-ab75ac95b33a" ||
		root.Identity.PartitionType.Value != "0fc63daf-8483-4772-8e79-3d69d8477de4" {
		t.Fatalf("captured root partition = %v", root)
	}
	if devices["sda1"].Mountpoint.Value != "/boot/efi" || appliance.Mountpoint.Status != truthUnavailable || appliance.Filesystem.Value != "ext2" {
		t.Fatalf("captured mounts = %v / %v", devices["sda1"], appliance)
	}
}

func TestStorageTruthLegacyRequiresPredatingRelease(t *testing.T) {
	transport := errors.New("transport lost")
	for _, tc := range []struct {
		name          string
		first         inventoryv1.CollectionStatus
		version       string
		versionStatus inventoryv1.CollectionStatus
		versionErr    error
		calls         int
		want          inventoryv1.CollectionStatus
		wantErr       error
	}{
		{name: "success needs no probe", first: truthSuccess, calls: 1, want: truthSuccess},
		{name: "missing tool", first: truthUnavailable, calls: 1, want: truthUnavailable},
		{name: "modern failure stands", first: truthCommandFailure, version: "lsblk from util-linux 2.39.3\n", versionStatus: truthSuccess, calls: 2, want: truthCommandFailure},
		{name: "release candidate is modern", first: truthCommandFailure, version: "lsblk from util-linux 2.37-rc1\n", versionStatus: truthSuccess, calls: 2, want: truthCommandFailure},
		{name: "unrecognized release", first: truthCommandFailure, version: "util-linux 2.32.1\n", versionStatus: truthSuccess, calls: 2, want: truthCommandFailure},
		{name: "probe failure", first: truthCommandFailure, versionStatus: truthCommandFailure, calls: 2, want: truthCommandFailure},
		{name: "probe transport", first: truthCommandFailure, versionErr: transport, calls: 2, wantErr: transport},
		{name: "util-linux 2.36", first: truthCommandFailure, version: "lsblk from util-linux 2.36.1\n", versionStatus: truthSuccess, calls: 3, want: truthSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var commands []string
			_, status, err := storageTruthPairs(func(_, command string) ([]byte, inventoryv1.CollectionStatus, error) {
				commands = append(commands, command)
				switch command {
				case storageTruthCommand:
					return nil, tc.first, nil
				case "lsblk --version":
					return []byte(tc.version), tc.versionStatus, tc.versionErr
				case legacyStorageTruthCommand:
					return nil, truthSuccess, nil
				}
				t.Fatalf("unexpected command %q", command)
				return nil, 0, nil
			})
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && status != tc.want) || len(commands) != tc.calls {
				t.Fatalf("status = %v, %v after %v", status, err, commands)
			}
		})
	}
}

func TestStorageTruthLegacyFieldsMatchAgentClassification(t *testing.T) {
	// Constructed in the captured 2.32.1 pairs presentation; no LUKS media
	// was captured.
	const legacy = `NAME="vda1" TYPE="part" SIZE="900" FSTYPE="crypto_LUKS" MOUNTPOINT="" PKNAME="vda" KNAME="vda1" TRAN="" MODEL="" SERIAL="" WWN="" REV="" UUID="32cfd1cf-6a1c-4d7c-a792-664b3a0f4508" PARTUUID="06d130c8-da08-419e-970c-9a712a936392" PARTTYPE="0fc63daf-8483-4772-8e79-3d69d8477de4"` + "\n"
	storage, err := parseTruthStorage([]byte(legacy), truthSuccess)
	if err != nil || len(storage.Devices) != 1 {
		t.Fatalf("legacy LUKS truth = %v, %v", storage, err)
	}
	id := storage.Devices[0].Identity
	// As in the agent, a failed header read is reported on the version that
	// lsblk could not supply, while lsblk's LUKS UUID remains observed.
	truthLUKSUnobserved(id, truthDenied)
	if storage.Devices[0].Encryption.Value != "luks" || id.LuksUuid.Value != "32cfd1cf-6a1c-4d7c-a792-664b3a0f4508" || id.LuksUuid.Status != truthSuccess ||
		id.LuksVersion.Status != truthDenied || id.LuksKeyslotCount.Status != truthDenied || id.FilesystemUuid.Status != truthUnavailable {
		t.Fatalf("legacy LUKS identity = %v", id)
	}
	modern := strings.Replace(strings.Replace(legacy, `MOUNTPOINT=""`, `MOUNTPOINT="" MOUNTPOINTS=""`, 1), `PARTTYPE="0fc63daf-8483-4772-8e79-3d69d8477de4"`, `PARTTYPE="0fc63daf-8483-4772-8e79-3d69d8477de4" FSVER="2" PTTYPE="" PTUUID=""`, 1)
	storage, err = parseTruthStorage([]byte(modern), truthSuccess)
	if err != nil {
		t.Fatal(err)
	}
	id = storage.Devices[0].Identity
	truthLUKSUnobserved(id, truthDenied)
	if id.LuksVersion.Status != truthSuccess || id.LuksVersion.Value != "2" {
		t.Fatalf("observed lsblk LUKS version replaced: %v", id.LuksVersion)
	}
	// Fifteen columns that are not the legacy set are not a legacy row.
	mixed := strings.Replace(legacy, `UUID="32cfd1cf-6a1c-4d7c-a792-664b3a0f4508"`, `FSVER="2"`, 1)
	if _, err := parseTruthStorage([]byte(mixed), truthSuccess); err == nil {
		t.Fatal("accepted a partial modern column set as legacy truth")
	}
}
