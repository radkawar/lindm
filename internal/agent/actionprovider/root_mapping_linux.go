//go:build linux

package actionprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func deviceNumber(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// btrfsIocFSInfo is BTRFS_IOC_FS_INFO, _IOR(0x94, 31, struct
// btrfs_ioctl_fs_info_args); it needs no privilege beyond an open descriptor.
const btrfsIocFSInfo = 0x8400941f

// btrfsFSInfo is struct btrfs_ioctl_fs_info_args (1024 bytes, linux/btrfs.h).
type btrfsFSInfo struct {
	MaxID, NumDevices                    uint64
	FSID                                 [16]byte
	NodeSize, SectorSize, CloneAlignment uint32
	CSumType, CSumSize                   uint16
	Flags, Generation                    uint64
	MetadataUUID                         [16]byte
	_                                    [944]byte
}

// rootBlockDevices names the block devices backing the mounted root. A block
// filesystem's st_dev is that device, but Btrfs reports a per-subvolume
// anonymous device (major 0) with no /sys/dev/block entry, so a Btrfs root
// (Omarchy, openSUSE) resolves through its filesystem ID to every member the
// kernel lists. Any other root without a block device is unsupported.
func rootBlockDevices() (_ []string, err error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	var root unix.Stat_t
	if err := unix.Fstat(fd, &root); err != nil {
		return nil, err
	}
	if unix.Major(root.Dev) != 0 {
		return []string{fmt.Sprintf("%d:%d", unix.Major(root.Dev), unix.Minor(root.Dev))}, nil
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return nil, err
	}
	if filesystem.Type != unix.BTRFS_SUPER_MAGIC {
		return nil, fmt.Errorf("%w: root_without_block_device", ErrUnsupported)
	}
	var info btrfsFSInfo
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), btrfsIocFSInfo, uintptr(unsafe.Pointer(&info))); errno != 0 {
		return nil, errno
	}
	return btrfsMemberDevices(info.FSID, info.NumDevices, os.ReadDir, os.ReadFile)
}

// btrfsMemberDevices reads one mounted Btrfs filesystem's member list from
// /sys/fs/btrfs/<fsid>/devices and requires it to be complete: a missing or
// device-less member would hide part of the root from the erase scope.
func btrfsMemberDevices(fsid [16]byte, count uint64, readDir func(string) ([]os.DirEntry, error), readFile func(string) ([]byte, error)) ([]string, error) {
	base := fmt.Sprintf("/sys/fs/btrfs/%x-%x-%x-%x-%x/devices", fsid[0:4], fsid[4:6], fsid[6:8], fsid[8:10], fsid[10:16])
	entries, err := readDir(base)
	if err != nil {
		return nil, err
	}
	if count == 0 || uint64(len(entries)) != count {
		return nil, ErrConflict
	}
	devices := make([]string, 0, len(entries))
	for _, entry := range entries {
		value, err := readFile(base + "/" + entry.Name() + "/dev")
		if err != nil {
			return nil, err
		}
		device := strings.TrimSpace(string(value))
		if !deviceNumber(device) || strings.HasPrefix(device, "0:") {
			return nil, ErrConflict
		}
		devices = append(devices, device)
	}
	sort.Strings(devices)
	return devices, nil
}

// rootMapping freezes the real mounted-root dependency graph, kernel dm UUIDs
// and redacted crypt tables. No keys are requested from device mapper. Only the
// backing device of the single root LUKS2 mapping qualifies; a LUKS volume merely
// sharing the root's disk does not. LVM above that mapping is supported.
func (p *Provider) rootMapping(ctx context.Context, targets []*targetHandle) (int, []byte, error) {
	rootDevices, err := rootBlockDevices()
	if err != nil {
		return -1, nil, err
	}
	seen := make(map[string]bool)
	var facts []string
	var cryptIDs []string
	var visit func(string) error
	visit = func(device string) error {
		if !deviceNumber(device) || seen[device] {
			return ErrConflict
		}
		seen[device] = true
		base := "/sys/dev/block/" + device
		uuid, err := os.ReadFile(base + "/dm/uuid")
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		id := strings.TrimSpace(string(uuid))
		facts = append(facts, device+"="+id)
		if strings.HasPrefix(id, "CRYPT-") {
			cryptIDs = append(cryptIDs, id)
		}
		children, err := os.ReadDir(base + "/slaves")
		if os.IsNotExist(err) && id == "" {
			return nil
		}
		if err != nil {
			return err
		}
		for _, child := range children {
			value, err := os.ReadFile(base + "/slaves/" + child.Name() + "/dev")
			if err != nil {
				return err
			}
			next := strings.TrimSpace(string(value))
			facts = append(facts, device+">"+next)
			if err := visit(next); err != nil {
				return err
			}
		}
		return nil
	}
	for _, device := range rootDevices {
		if err := visit(device); err != nil {
			return -1, nil, err
		}
	}
	rootIndex, err := matchRootBacking(targets, seen, cryptIDs)
	if err != nil {
		return -1, nil, err
	}
	// The fixed helper's default output masks key material. Hash it in memory;
	// never put native table text in the plan, logs or public diagnostics.
	table, err := p.run(ctx, nativeRequest{command: dmsetup, args: []string{"table", "--target", "crypt"}})
	if err != nil || len(table) == 0 {
		return -1, nil, ErrConflict
	}
	defer clear(table)
	facts = append(facts, strings.Split(strings.TrimSpace(string(table)), "\n")...)
	sort.Strings(facts)
	digest := sha256.Sum256([]byte(strings.Join(facts, "\n")))
	return rootIndex, digest[:], nil
}

func matchRootBacking(targets []*targetHandle, ancestors map[string]bool, cryptIDs []string) (int, error) {
	if len(cryptIDs) != 1 {
		return -1, ErrUnsupported
	}
	rootIndex := -1
	for index, target := range targets {
		if !ancestors[target.node.Device] {
			continue
		}
		prefix := "CRYPT-LUKS2-" + strings.ReplaceAll(target.qualification.GetTarget().GetLuksUuid(), "-", "") + "-"
		if rootIndex >= 0 || !strings.HasPrefix(cryptIDs[0], prefix) {
			return -1, ErrConflict
		}
		rootIndex = index
	}
	if rootIndex < 0 {
		return -1, ErrUnsupported
	}
	return rootIndex, nil
}
