// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

type capturedCommand struct {
	Command  []string `json:"command"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
	ExitCode int      `json:"exit_code"`
}

// capturedLsblk replays real util-linux 2.32.1 replies; see provenance.json.
// A native nonzero exit is a command failure even after its stdout was
// consumed, as in runCommand.
func capturedLsblk(t *testing.T, calls *[][]string) nativeRunner {
	t.Helper()
	var capture map[string]capturedCommand
	if err := json.Unmarshal(detailFixture(t, "lsblk-almalinux810-aarch64/lsblk.json"), &capture); err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		*calls = append(*calls, b.args)
		for _, reply := range capture {
			if reply.Command[0] != b.path || !slices.Equal(reply.Command[1:], b.args) {
				continue
			}
			status := parse(strings.NewReader(reply.Stdout))
			if reply.ExitCode != 0 || reply.Stderr != "" {
				return commandFailure
			}
			return status
		}
		t.Fatalf("uncaptured native command: %s %v", b.path, b.args)
		return invalid
	}
}

func TestCapturedEL8LegacyLsblkStorage(t *testing.T) {
	var calls [][]string
	got := collectStorage(t.Context(), detailSources{run: capturedLsblk(t, &calls)})
	if len(calls) != 3 || calls[0][len(calls[0])-1] != storageColumns || !slices.Equal(calls[1], []string{"--version"}) || calls[2][len(calls[2])-1] != legacyStorageColumns {
		t.Fatalf("native lsblk selection = %v", calls)
	}
	if got.Status != success || len(got.Devices) != 5 {
		t.Fatalf("legacy storage = %v", got)
	}
	devices := make(map[string]*inventoryv1.BlockDevice)
	for _, device := range got.Devices {
		devices[device.Name] = device
		// FSVER/PTTYPE/PTUUID were not collected: unobserved, never empty success.
		if device.Identity.GptDiskGuid.Status != unavailable || device.Identity.LuksVersion.Status != unavailable {
			t.Fatalf("uncollected column reported: %v", device)
		}
	}
	disk, root, appliance := devices["sda"], devices["sda3"], devices["sdb"]
	if disk == nil || root == nil || appliance == nil {
		t.Fatalf("captured devices missing: %v", got)
	}
	if disk.SizeBytes.Value != 10737418240 || disk.Identity.Model.Value != "QEMU HARDDISK" || disk.Identity.Serial.Value != "hd0" ||
		disk.Identity.Firmware.Value != "2.5+" || disk.Identity.Transport.Status != unavailable || !disk.Identity.RootBacking.Value {
		t.Fatalf("captured disk = %v", disk)
	}
	if root.Mountpoint.Value != "/" || root.Filesystem.Value != "xfs" || root.Parent.Value != "sda" || root.Encryption.Value != "none" ||
		root.Identity.FilesystemUuid.Value != "95e58dd6-7888-4110-8de2-40a665c36bb2" ||
		root.Identity.PartitionUuid.Value != "da60e1cf-a0bc-4573-93f8-ab75ac95b33a" ||
		root.Identity.PartitionType.Value != "0fc63daf-8483-4772-8e79-3d69d8477de4" ||
		root.Identity.BackingDisk.Value != "sda" || !root.Identity.RootBacking.Value || root.Identity.Serial.Value != "hd0" {
		t.Fatalf("captured root partition = %v", root)
	}
	if devices["sda1"].Mountpoint.Value != "/boot/efi" || appliance.Mountpoint.Status != unavailable || appliance.Filesystem.Value != "ext2" ||
		appliance.Identity.RootBacking.Status != success || appliance.Identity.RootBacking.Value {
		t.Fatalf("captured mounts = %v / %v", devices["sda1"], appliance)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestLsblkLegacyColumnsRequirePredatingRelease(t *testing.T) {
	const legacy = `{"blockdevices":[{"name":"vda","kname":"vda","type":"disk","size":"1000","fstype":null,"uuid":null,"partuuid":null,"parttype":null,"tran":null,"model":null,"serial":"lab","wwn":null,"rev":null,"mountpoint":null,"pkname":null}]}`
	for _, tc := range []struct {
		name    string
		first   inventoryv1.CollectionStatus
		version string // "" fails the release probe natively
		last    inventoryv1.CollectionStatus
		calls   int
		want    inventoryv1.CollectionStatus
	}{
		{name: "success needs no probe", first: success, calls: 1, want: success},
		{name: "missing tool", first: unavailable, calls: 1, want: unavailable},
		{name: "timeout", first: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT, calls: 1, want: inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT},
		{name: "modern failure stands", first: commandFailure, version: "lsblk from util-linux 2.39.3\n", calls: 2, want: commandFailure},
		{name: "release candidate is modern", first: commandFailure, version: "lsblk from util-linux 2.37-rc1\n", calls: 2, want: commandFailure},
		{name: "unrecognized release", first: commandFailure, version: "util-linux 2.32.1\n", calls: 2, want: commandFailure},
		{name: "unterminated release", first: commandFailure, version: "lsblk from util-linux 2.32.1", calls: 2, want: commandFailure},
		{name: "probe failure", first: commandFailure, calls: 2, want: commandFailure},
		{name: "util-linux 2.36", first: commandFailure, version: "lsblk from util-linux 2.36.1\n", last: success, calls: 3, want: success},
		{name: "legacy failure", first: commandFailure, version: "lsblk from util-linux 2.32.1\n", last: commandFailure, calls: 3, want: commandFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls [][]string
			got := collectStorage(t.Context(), detailSources{run: func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
				calls = append(calls, b.args)
				if b.path != "/usr/bin/lsblk" {
					t.Fatalf("unexpected native command: %+v", b)
				}
				switch {
				case slices.Equal(b.args, []string{"--version"}):
					if tc.version == "" {
						return commandFailure
					}
					return parse(strings.NewReader(tc.version))
				case b.args[len(b.args)-1] == storageColumns:
					if tc.first == success {
						return parse(strings.NewReader(`{"blockdevices":[]}`))
					}
					return tc.first
				case b.args[len(b.args)-1] == legacyStorageColumns:
					if tc.last == success {
						return parse(strings.NewReader(legacy))
					}
					return tc.last
				}
				t.Fatalf("unexpected lsblk arguments: %v", b.args)
				return invalid
			}})
			if got.Status != tc.want || len(calls) != tc.calls {
				t.Fatalf("status = %v after %v", got.Status, calls)
			}
			if tc.calls > 1 && !slices.Equal(calls[1], []string{"--version"}) {
				t.Fatalf("release probe = %v", calls)
			}
			if tc.want == success && tc.calls == 3 && (len(got.Devices) != 1 || got.Devices[0].Identity.Serial.Value != "lab" || got.Devices[0].Identity.GptDiskGuid.Status != unavailable) {
				t.Fatalf("legacy storage = %v", got)
			}
		})
	}
}

// util-linux 2.32.1 has no FSVER: the LUKS version is cryptsetup's alone, and a
// failed header read is reported on it rather than an empty success.
func TestLegacyLsblkLUKSVersionNeedsHeaderRead(t *testing.T) {
	const legacy = `{"blockdevices":[{"name":"vda","kname":"vda","type":"disk","size":"1000","fstype":null,"uuid":null,"partuuid":null,"parttype":null,"tran":null,"model":null,"serial":null,"wwn":null,"rev":null,"mountpoint":null,"pkname":null,
"children":[{"name":"vda1","kname":"vda1","type":"part","size":"900","fstype":"crypto_LUKS","uuid":"32cfd1cf-6a1c-4d7c-a792-664b3a0f4508","partuuid":"06d130c8-da08-419e-970c-9a712a936392","parttype":"0fc63daf-8483-4772-8e79-3d69d8477de4","tran":null,"model":null,"serial":null,"wwn":null,"rev":null,"mountpoint":null,"pkname":"vda"}]}]}`
	got := collectStorage(t.Context(), detailSources{
		openBlock: func(string) (*os.File, error) { return nil, fs.ErrPermission },
		run: func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			switch {
			case slices.Equal(b.args, []string{"--version"}):
				return parse(strings.NewReader("lsblk from util-linux 2.32.1\n"))
			case b.args[len(b.args)-1] == legacyStorageColumns:
				return parse(strings.NewReader(legacy))
			case b.args[len(b.args)-1] == storageColumns:
				return commandFailure
			}
			t.Fatalf("unexpected native command: %+v", b)
			return invalid
		},
	})
	if got.Status != success || len(got.Devices) != 2 {
		t.Fatalf("legacy storage = %v", got)
	}
	id := got.Devices[1].Identity
	denied := inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED
	if got.Devices[1].Encryption.Value != "luks" || id.LuksUuid.Value != "32cfd1cf-6a1c-4d7c-a792-664b3a0f4508" || id.LuksVersion.Status != denied ||
		id.LuksKeyslotCount.Status != denied || id.FilesystemUuid.Status != unavailable {
		t.Fatalf("legacy LUKS identity = %v", id)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}
