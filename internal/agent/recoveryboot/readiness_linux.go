package recoveryboot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// Readiness contains public native facts only. It is not artifact admission or a
// staging grant. ObserveReadiness never provisions custody or changes boot state.
type Readiness struct {
	ESPUUID             string
	FreeBytes           uint64
	AllocationUnitBytes uint64
	SecureBoot          bool
	UKICapable          bool
}

// ObserveReadiness observes the configured, protected ESP as the root executor.
// A failure may retain already observed facts but cannot imply availability.
func ObserveReadiness(ctx context.Context, espPath string) (Readiness, error) {
	var result Readiness
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
	result.SecureBoot, err = readinessSecureBoot(os.ReadFile)
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
func readinessESPIdentity(device uint64) (_ string, _ string, err error) {
	const directory = "/run/udev/data"
	if err := rootDirectory(directory); err != nil {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	name := fmt.Sprintf("%s/b%d:%d", directory, unix.Major(device), unix.Minor(device))
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, file.Close()) }()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != 0 || info.Mode&0022 != 0 || info.Size > 64<<10 {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return "", "", errors.New("recovery_readiness_esp_uuid_unavailable")
	}
	return parseReadinessESPIdentity(string(data))
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
