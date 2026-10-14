// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Readiness contains public native facts only. It is not artifact admission or a
// staging grant. ObserveReadiness never provisions custody or changes boot state.
type Readiness struct {
	ESPUUID              string
	FreeBytes            uint64
	AllocationUnitBytes  uint64
	SecureBoot           bool
	UKICapable           bool
	BootMode             agentv1.RecoveryBootMode
	MeasuredKernelSHA256 []byte
}

// ObserveReadiness observes the configured, protected ESP as the root executor.
// A failure may retain already observed facts but cannot imply availability.
func ObserveReadiness(ctx context.Context, espPath string) (Readiness, error) {
	result := Readiness{BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if os.Geteuid() != 0 {
		return result, errors.New("recovery_readiness_root_required")
	}
	if err := rootDirectory(espPath); err != nil {
		return result, errors.New("recovery_readiness_esp_unreadable")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(espPath, &filesystem); err != nil {
		return result, errors.New("recovery_readiness_esp_unreadable")
	}
	var err error
	result.FreeBytes, result.AllocationUnitBytes, err = readinessCapacity(filesystem)
	if err != nil {
		return result, err
	}
	var esp unix.Stat_t
	if err := unix.Stat(espPath, &esp); err != nil {
		return result, errors.New("recovery_readiness_esp_unreadable")
	}
	var partitionUUID string
	result.ESPUUID, partitionUUID, err = readinessESPIdentity(uint64(esp.Dev))
	if err != nil {
		return result, err
	}
	release, platformErr := HostRecoveryPlatform()
	result.SecureBoot, err = readinessSecureBootForPolicy(os.ReadFile, platformErr == nil && release.Quirks.RecoveryOwnerKey)
	if err != nil {
		return result, err
	}
	loader, err := readEFString("LoaderInfo", loaderGUID)
	if err != nil || !strings.HasPrefix(loader, "systemd-boot ") {
		return result, errors.New("recovery_readiness_systemd_boot_required")
	}
	// The configured ESP must be the running systemd-boot ESP, not another
	// mounted FAT filesystem with enough free space.
	partition, err := readEFString("LoaderDevicePartUUID", loaderGUID)
	if err != nil || !efiPartitionUUID(partition) {
		return result, errors.New("recovery_readiness_loader_esp_unavailable")
	}
	if !strings.EqualFold(partitionUUID, partition) {
		return result, errors.New("recovery_readiness_loader_esp_mismatch")
	}
	result.UKICapable = true
	return result, ctx.Err()
}

// ObserveUnconfiguredReadiness reports only the release's boot-trust
// prerequisite. It never guesses an ESP or makes an unconfigured host ready.
func ObserveUnconfiguredReadiness(ctx context.Context) (Readiness, error) {
	result := Readiness{}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if os.Geteuid() != 0 {
		return result, errors.New("recovery_readiness_root_required")
	}
	release, err := HostRecoveryPlatform()
	if err != nil || !release.Quirks.RecoveryOwnerKey {
		return result, errors.New("recovery_readiness_not_configured")
	}
	result.BootMode = agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI
	result.SecureBoot, err = readinessSecureBootForPolicy(os.ReadFile, true)
	if err != nil {
		return result, err
	}
	return result, errors.New("recovery_readiness_not_configured")
}

// ErrOwnerKeyRequired is the readiness refusal of a release whose UKI recovery
// requires an owner-enrolled Secure Boot key while Secure Boot is off.
var ErrOwnerKeyRequired = errors.New("recovery_readiness_owner_key_required")

func readinessSecureBootForPolicy(read func(string) ([]byte, error), ownerKey bool) (bool, error) {
	secure, err := readinessSecureBoot(read)
	if err != nil && err.Error() == "recovery_readiness_secure_boot_required" && ownerKey {
		return false, ErrOwnerKeyRequired
	}
	return secure, err
}

func readinessCapacity(filesystem unix.Statfs_t) (free, allocation uint64, err error) {
	if filesystem.Type != unix.MSDOS_SUPER_MAGIC || filesystem.Flags&unix.ST_RDONLY != 0 {
		return 0, 0, errors.New("recovery_readiness_esp_unsupported")
	}
	unit := filesystem.Frsize
	if unit == 0 {
		unit = filesystem.Bsize
	}
	if unit <= 0 || filesystem.Bavail > ^uint64(0)/uint64(unit) {
		return 0, 0, errors.New("recovery_readiness_esp_capacity_invalid")
	}
	return filesystem.Bavail * uint64(unit), uint64(unit), nil
}

func readinessSecureBoot(read func(string) ([]byte, error)) (bool, error) {
	for _, variable := range []struct {
		name  string
		value byte
	}{{"SecureBoot", 1}, {"SetupMode", 0}} {
		data, err := read(efivars + variable.name + "-" + globalGUID)
		if err != nil || len(data) != 5 {
			return false, errors.New("recovery_readiness_secure_boot_unavailable")
		}
		if data[4] != variable.value {
			return false, errors.New("recovery_readiness_secure_boot_required")
		}
	}
	return true, nil
}

// The executor's PrivateDevices mount intentionally has no /dev/disk links.
// Root-owned udev metadata indexes the mounted filesystem's kernel device
// number without granting block access or relaxing the device sandbox.
func readinessESPIdentity(device uint64) (string, string, error) {
	data, err := udevBlockData(device)
	if err != nil {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	return parseReadinessESPIdentity(data)
}

// bootFilesystemUUID returns the filesystem UUID of the separate /boot
// (ext2/3/4, XFS or btrfs) that a grub.d entry locates with `search --fs-uuid`.
func bootFilesystemUUID(device uint64) (string, error) {
	data, err := udevBlockData(device)
	if err != nil {
		return "", errors.New("recoveryboot: boot_filesystem_uuid_unavailable")
	}
	return parseBootFilesystemUUID(data)
}

func udevBlockData(device uint64) (_ string, err error) {
	const directory = "/run/udev/data"
	if err := rootDirectory(directory); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s/b%d:%d", directory, unix.Major(device), unix.Minor(device))
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, file.Close()) }()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != 0 || info.Mode&0022 != 0 || info.Size > 64<<10 {
		return "", errors.Join(errors.New("recoveryboot: unsafe_udev_data"), err)
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return "", errors.Join(errors.New("recoveryboot: unsafe_udev_data"), err)
	}
	return string(data), nil
}

// parseBootFilesystemUUID requires exactly one supported filesystem type and
// one canonical lowercase UUID, so the value is safe GRUB script text.
func parseBootFilesystemUUID(data string) (string, error) {
	var filesystem, filesystemUUID string
	for line := range strings.SplitSeq(data, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		var destination *string
		switch key {
		case "E:ID_FS_TYPE":
			destination = &filesystem
		case "E:ID_FS_UUID":
			destination = &filesystemUUID
		default:
			continue
		}
		if *destination != "" || value == "" {
			return "", errors.New("recoveryboot: boot_filesystem_uuid_unavailable")
		}
		*destination = value
	}
	if !slices.Contains([]string{"ext2", "ext3", "ext4", "xfs", "btrfs"}, filesystem) || !uuidText(filesystemUUID) {
		return "", errors.New("recoveryboot: boot_filesystem_uuid_unavailable")
	}
	return filesystemUUID, nil
}

func parseReadinessESPIdentity(data string) (string, string, error) {
	var filesystem, filesystemUUID, partitionUUID string
	for line := range strings.SplitSeq(data, "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		var destination *string
		switch key {
		case "E:ID_FS_TYPE":
			destination = &filesystem
		case "E:ID_FS_UUID":
			destination = &filesystemUUID
		case "E:ID_PART_ENTRY_UUID":
			destination = &partitionUUID
		default:
			continue
		}
		if *destination != "" || value == "" {
			return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
		}
		*destination = value
	}
	if filesystem != "vfat" || len(filesystemUUID) != 9 || filesystemUUID[4] != '-' || !uuidText(partitionUUID) {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	if _, err := strconv.ParseUint(filesystemUUID[:4]+filesystemUUID[5:], 16, 32); err != nil {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	return filesystemUUID, partitionUUID, nil
}

// systemd-boot's EFI GUID_FORMAT_STR emits uppercase hexadecimal. Kernel boot
// IDs remain canonical lowercase, but firmware partition UUIDs are case-neutral.
func efiPartitionUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	_, err := uuid.Parse(value)
	return err == nil
}
