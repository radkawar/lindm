//go:build linux

package actionprovider

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Recheck the backing disk through a pinned descriptor, not a cached udev GUID.
// The partition's kernel ancestry must still name that exact physical disk.
func verifyFallbackDisk(disk, partition blockNode, target *agentv1.StorageTarget) (err error) {
	if partition.Type != "part" || !canonicalBlockDeviceNumber(disk.Device) || !canonicalBlockDeviceNumber(partition.Device) || filepath.Dir(disk.Path) != "/dev" || filepath.Clean(disk.Path) != disk.Path {
		return fmt.Errorf("%w: fallback_disk_identity_changed", ErrConflict)
	}
	diskSysfs, err := filepath.EvalSymlinks("/sys/dev/block/" + disk.Device)
	if err != nil {
		return err
	}
	partitionSysfs, err := filepath.EvalSymlinks("/sys/dev/block/" + partition.Device)
	if err != nil || filepath.Dir(partitionSysfs) != diskSysfs {
		return errors.Join(ErrConflict, err)
	}
	fd, err := unix.Open(disk.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "fallback-backing-disk")
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	evidence := nativeBlockIdentity(disk.Device)
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK || fmt.Sprintf("%d:%d", unix.Major(stat.Rdev), unix.Minor(stat.Rdev)) != disk.Device || !absentNativeWWN(evidence) || !sameNativeBlockIdentity(disk, evidence) {
		return fmt.Errorf("%w: fallback_disk_identity_changed", ErrConflict)
	}
	size, err := blockSize(file)
	if err != nil || size != target.GetDiskSizeBytes() {
		return errors.Join(ErrConflict, err)
	}
	sector, err := unix.IoctlGetInt(fd, unix.BLKSSZGET)
	if err != nil {
		return err
	}
	guid, err := readGPTDiskGUID(file, sector)
	if err != nil || guid != target.GetGptDiskGuid() {
		return errors.Join(fmt.Errorf("%w: gpt_disk_identity_changed", ErrConflict), err)
	}
	return nil
}

func readGPTDiskGUID(reader io.ReaderAt, sector int) (string, error) {
	if sector < 512 || sector > 4096 || sector&(sector-1) != 0 {
		return "", ErrUnsupported
	}
	var header [4096]byte
	if _, err := reader.ReadAt(header[:sector], int64(sector)); err != nil {
		return "", err
	}
	length := binary.LittleEndian.Uint32(header[12:16])
	if string(header[:8]) != "EFI PART" || binary.LittleEndian.Uint32(header[8:12]) != 0x10000 || length < 92 || length > uint32(sector) || binary.LittleEndian.Uint64(header[24:32]) != 1 {
		return "", ErrConflict
	}
	checksum := binary.LittleEndian.Uint32(header[16:20])
	clear(header[16:20])
	if crc32.ChecksumIEEE(header[:length]) != checksum {
		return "", ErrConflict
	}
	guid := header[56:72]
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(guid[:4]), binary.LittleEndian.Uint16(guid[4:6]), binary.LittleEndian.Uint16(guid[6:8]), guid[8:10], guid[10:]), nil
}
