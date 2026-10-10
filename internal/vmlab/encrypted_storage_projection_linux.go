//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

var storagePublicType = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,127}$`)

// This allowlist intentionally excludes even public-looking token payload fields:
// native JSON may contain TPM sealed blobs, salts, digests and key material.
func projectStorageLUKS(data []byte) ([]byte, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("LUKS metadata exceeds capture bound")
	}
	// Reuse the strict duplicate-member/depth checker used by the independent
	// header oracle before encoding only selected public members.
	if _, err := encryptedHeaderJSON(data); err != nil {
		return nil, errors.New("invalid LUKS JSON metadata")
	}
	var raw struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
		Tokens   map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || raw.Keyslots == nil || raw.Tokens == nil || len(raw.Keyslots) > 32 || len(raw.Tokens) > 32 {
		return nil, errors.New("incomplete LUKS2 public metadata")
	}
	type slot struct {
		Type string `json:"type"`
	}
	type token struct {
		Type     string   `json:"type"`
		Keyslots []string `json:"keyslots"`
	}
	public := struct {
		Keyslots map[string]slot  `json:"keyslots"`
		Tokens   map[string]token `json:"tokens"`
	}{make(map[string]slot), make(map[string]token)}
	for id, value := range raw.Keyslots {
		var entry slot
		if !storageSlotID(id) || json.Unmarshal(value, &entry) != nil || entry.Type != "luks2" {
			return nil, errors.New("invalid LUKS2 public keyslot")
		}
		public.Keyslots[id] = entry
	}
	for id, value := range raw.Tokens {
		var entry token
		if !storageSlotID(id) || json.Unmarshal(value, &entry) != nil || !storagePublicType.MatchString(entry.Type) || entry.Keyslots == nil || len(entry.Keyslots) > 32 {
			return nil, errors.New("invalid LUKS2 public token")
		}
		seen := make(map[string]bool)
		for _, keyslot := range entry.Keyslots {
			if _, exists := public.Keyslots[keyslot]; !exists || seen[keyslot] {
				return nil, errors.New("invalid LUKS2 token keyslot reference")
			}
			seen[keyslot] = true
		}
		public.Tokens[id] = entry
	}
	return json.MarshalIndent(public, "", "  ")
}

func storageSlotID(value string) bool {
	n, err := strconv.ParseUint(value, 10, 5)
	return err == nil && strconv.FormatUint(n, 10) == value
}

func projectStorageLUKSText(data []byte, uuid string) ([]byte, error) {
	if len(data) > 1<<20 || !encryptedLUKSUUID(uuid) {
		return nil, errors.New("invalid public LUKS text input")
	}
	var output strings.Builder
	section := ""
	versionSeen, uuidSeen := false, false
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "Version:") {
			if versionSeen || strings.TrimSpace(strings.TrimPrefix(line, "Version:")) != "2" {
				return nil, errors.New("invalid LUKS text version")
			}
			versionSeen = true
			output.WriteString(line + "\n")
		} else if strings.HasPrefix(line, "UUID:") {
			if uuidSeen || strings.TrimSpace(strings.TrimPrefix(line, "UUID:")) != uuid {
				return nil, errors.New("LUKS text UUID differs from stopped oracle")
			}
			uuidSeen = true
			output.WriteString(line + "\n")
		}
		if line == "Keyslots:" || line == "Tokens:" {
			section = line
			output.WriteString(line + "\n")
			continue
		}
		if len(line) != 0 && line[0] != ' ' && line[0] != '\t' {
			section = ""
		}
		if section == "" || len(line) < 3 || line[:2] != "  " || line[2] < '0' || line[2] > '9' {
			continue
		}
		id, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || !storageSlotID(id) || !storagePublicType.MatchString(strings.TrimSpace(value)) {
			return nil, errors.New("invalid LUKS text public type line")
		}
		output.WriteString(line + "\n")
	}
	if !versionSeen || !uuidSeen {
		return nil, errors.New("LUKS text lacks public identity")
	}
	return []byte(output.String()), nil
}

func projectStorageUdev(data []byte) ([]byte, error) {
	if len(data) > 4<<20 || strings.ContainsRune(string(data), '\x00') {
		return nil, errors.New("invalid udev export size or encoding")
	}
	var output strings.Builder
	count := 0
	for record := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n\n") {
		block := false
		for line := range strings.SplitSeq(record, "\n") {
			if line == "E: SUBSYSTEM=block" {
				block = true
			}
		}
		if !block {
			continue
		}
		count++
		for line := range strings.SplitSeq(record, "\n") {
			if strings.HasPrefix(line, "P: ") || strings.HasPrefix(line, "N: ") {
				output.WriteString(line + "\n")
				continue
			}
			key, _, ok := strings.Cut(strings.TrimPrefix(line, "E: "), "=")
			if !ok || !strings.HasPrefix(line, "E: ") {
				continue
			}
			switch key {
			case "SUBSYSTEM", "DEVNAME", "DEVTYPE", "MAJOR", "MINOR", "ID_BUS", "ID_REVISION", "ID_MODEL", "ID_SERIAL", "ID_SERIAL_SHORT", "ID_WWN", "ID_WWN_WITH_EXTENSION", "ID_FS_TYPE", "ID_FS_VERSION", "ID_FS_UUID", "ID_PART_ENTRY_UUID", "ID_PART_ENTRY_TYPE":
				output.WriteString(line + "\n")
			}
		}
		output.WriteByte('\n')
	}
	if count == 0 {
		return nil, errors.New("udev export contains no block records")
	}
	return []byte(output.String()), nil
}

// Serial/WWN belong to QEMU's controller configuration, not the on-disk header.
// UUID and keyslot/token summary have a separate stopped-appliance comparison.
func compareEncryptedStorage(truth, actual *inventoryv1.StorageDetails, uuid string) (string, error) {
	if truth.GetStatus() != truthSuccess || actual.GetStatus() != truthSuccess {
		return "", errors.New("storage inspection was not successful")
	}
	byName := make(map[string]*inventoryv1.BlockDevice)
	for _, device := range actual.GetDevices() {
		if device.GetName() == "" || byName[device.GetName()] != nil {
			return "", errors.New("duplicate or empty agent block identity")
		}
		byName[device.GetName()] = device
	}
	if len(byName) != len(truth.Devices) {
		return "", errors.New("native and agent block device count differs")
	}
	luks := ""
	for _, expected := range truth.Devices {
		device := byName[expected.Name]
		if device == nil || device.GetType().GetStatus() != truthSuccess || device.GetType().GetValue() != expected.Type.Value || device.GetSizeBytes().GetStatus() != truthSuccess || device.GetSizeBytes().GetValue() != expected.SizeBytes.Value || device.GetParent().GetValue() != expected.Parent.Value {
			return "", errors.New("native and agent block topology or size differs")
		}
		if expected.Type.Value == "disk" {
			for _, pair := range [][2]*inventoryv1.ObservedString{{expected.GetIdentity().GetSerial(), device.GetIdentity().GetSerial()}, {expected.GetIdentity().GetWwn(), device.GetIdentity().GetWwn()}} {
				if pair[0].GetStatus() != pair[1].GetStatus() || pair[0].GetValue() != pair[1].GetValue() {
					return "", errors.New("native and agent disk serial or WWN differs")
				}
			}
		}
		if expected.GetIdentity().GetLuksUuid().GetValue() != uuid {
			continue
		}
		id := device.GetIdentity()
		if luks != "" || id.GetLuksUuid().GetStatus() != truthSuccess || id.GetLuksUuid().GetValue() != uuid || id.GetLuksVersion().GetValue() != "2" || id.GetRootBacking().GetStatus() != truthSuccess || !id.GetRootBacking().GetValue() {
			return "", errors.New("agent root LUKS identity differs from stopped header oracle")
		}
		luks = expected.Name
	}
	if luks == "" {
		return "", errors.New("stopped root LUKS UUID absent from native inventory")
	}
	nativeByName := make(map[string]*inventoryv1.BlockDevice, len(truth.Devices))
	for _, device := range truth.Devices {
		nativeByName[device.Name] = device
	}
	rootBacked := false
	for _, device := range truth.Devices {
		if device.GetMountpoint().GetValue() != "/" {
			continue
		}
		for current, steps := device, 0; current != nil; steps++ {
			if steps >= len(nativeByName) {
				return "", errors.New("cyclic native root ancestry")
			}
			if current.Name == luks {
				rootBacked = true
				break
			}
			current = nativeByName[current.GetParent().GetValue()]
		}
	}
	if !rootBacked {
		return "", errors.New("stopped LUKS container is not an ancestor of native root")
	}
	return luks, nil
}

func compareStorageController(actual *inventoryv1.StorageDetails, bus, root string) error {
	var disk, target *inventoryv1.BlockDevice
	for _, device := range actual.GetDevices() {
		if device.GetName() == root {
			target = device
		}
		if device.GetType().GetValue() == "disk" && device.GetIdentity().GetSerial().GetValue() == "lindm-lab-0" {
			if disk != nil {
				return errors.New("duplicate QEMU root disk serial")
			}
			disk = device
		}
	}
	if disk == nil || target == nil || !disk.GetIdentity().GetRootBacking().GetValue() || target.GetIdentity().GetBackingDisk().GetValue() != disk.Name {
		return errors.New("root inventory does not match host-owned QEMU root disk")
	}
	wwn := labControllerWWN(bus)
	for _, device := range []*inventoryv1.BlockDevice{disk, target} {
		if device.GetIdentity().GetWwn().GetValue() != wwn || device.GetIdentity().GetSerial().GetValue() != "lindm-lab-0" {
			return errors.New("inventory serial/WWN differs from host-owned QEMU controller")
		}
	}
	return nil
}

// labControllerWWN returns the WWN the lab assigns to the single QEMU root
// controller on bus, or "" for buses that expose no WWN (virtio-blk).
func labControllerWWN(bus string) string {
	switch bus {
	case "sata", "virtio-scsi":
		return "0x5000000000000001"
	case "nvme":
		return "eui.0200000000000001"
	}
	return ""
}

func compareStoragePublicSummary(actual *inventoryv1.StorageDetails, uuid string, projected []byte) error {
	var metadata struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
		Tokens   map[string]struct {
			Type string `json:"type"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(projected, &metadata); err != nil {
		return err
	}
	var types []string
	for _, token := range metadata.Tokens {
		types = append(types, token.Type)
	}
	sort.Strings(types)
	for _, device := range actual.GetDevices() {
		id := device.GetIdentity()
		if id.GetLuksUuid().GetValue() != uuid {
			continue
		}
		if id.GetLuksKeyslotCount().GetStatus() != truthSuccess || id.GetLuksKeyslotCount().GetValue() != uint64(len(metadata.Keyslots)) || id.GetLuksTokenCount().GetStatus() != truthSuccess || id.GetLuksTokenCount().GetValue() != uint64(len(metadata.Tokens)) || id.GetLuksTokenTypes().GetValue() != strings.Join(types, ",") {
			return errors.New("agent public LUKS summary differs from stopped header oracle")
		}
		return nil
	}
	return errors.New("agent has no matching public LUKS summary")
}

func storageOwnedDirectory(path string, private bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || resolved != absolute || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0700) {
		return errors.New("storage capture directory must be caller-owned, nonsymlink and not group/world writable; output parent requires mode 0700")
	}
	return nil
}

func stoppedStoragePartitionSize(ctx context.Context, vm *EncryptedVM, device string) (_ uint64, err error) {
	if vm.guest != nil || vm.tpm != nil || vm.recoveryActive {
		return 0, errors.New("partition size oracle requires stopped owned VM")
	}
	const prefix = "/dev/disk/guestfs/encrypted"
	suffix := strings.TrimPrefix(device, prefix)
	if !strings.HasPrefix(device, prefix) || strings.Trim(suffix, "0123456789") != "" {
		return 0, errors.New("invalid appliance partition identity")
	}
	path := filepath.Join(vm.dir, "disk.qcow2")
	disk, err := openRegular(path)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, disk.Close()) }()
	if err := encryptedQCOWChain(disk, path, 0); err != nil {
		return 0, err
	}
	descriptor := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), disk.Fd())
	data, err := encryptedHostOutput(ctx, vm.dir, 3*time.Minute, "guestfish", "--ro", "--", "add-drive-opts", descriptor, "readonly:true", "format:qcow2", "label:encrypted", ":", "run", ":", "blockdev-getsize64", device)
	if err != nil {
		return 0, err
	}
	size, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || size == 0 {
		return 0, errors.New("invalid stopped appliance partition size")
	}
	return size, nil
}
