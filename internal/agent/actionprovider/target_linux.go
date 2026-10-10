//go:build linux

package actionprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type blockNode struct {
	Path        string      `json:"path"`
	Type        string      `json:"type"`
	Size        uint64      `json:"size"`
	WWN         string      `json:"wwn"`
	Serial      string      `json:"serial"`
	UUID        string      `json:"uuid"`
	Rotational  bool        `json:"rota"`
	Mountpoints []*string   `json:"mountpoints"`
	Filesystem  string      `json:"fstype"`
	Device      string      `json:"maj:min"`
	Children    []blockNode `json:"children"`
}

type targetHandle struct {
	file          *os.File
	node          blockNode
	qualification *agentv1.QualifiedActionTarget
}

func specTarget(spec *agentv1.DeviceActionSpec) *agentv1.StorageTarget {
	switch action := spec.GetAction().(type) {
	case *agentv1.DeviceActionSpec_EscrowRotate:
		return action.EscrowRotate.GetTarget()
	case *agentv1.DeviceActionSpec_Tpm2Bind:
		return action.Tpm2Bind.GetTarget()
	case *agentv1.DeviceActionSpec_CryptoErase:
		return action.CryptoErase.GetTarget()
	case *agentv1.DeviceActionSpec_Sanitize:
		return action.Sanitize.GetTarget()
	default:
		return nil
	}
}

func destructive(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetCryptoErase() != nil || spec.GetSanitize() != nil
}

func (p *Provider) qualified(target *agentv1.StorageTarget) (*agentv1.QualifiedActionTarget, error) {
	for _, candidate := range p.config.GetTargets() {
		if proto.Equal(candidate.GetTarget(), target) {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("%w: target_not_allowlisted", ErrUnsupported)
}

func (p *Provider) openTarget(ctx context.Context, spec *agentv1.DeviceActionSpec, writable bool) (_ *targetHandle, err error) {
	target := specTarget(spec)
	qualification, err := p.qualified(target)
	if err != nil {
		return nil, err
	}
	output, err := p.run(ctx, nativeRequest{command: lsblk, args: []string{"--json", "--tree", "--bytes", "--output", "PATH,TYPE,SIZE,WWN,SERIAL,UUID,ROTA,MOUNTPOINTS,FSTYPE,MAJ:MIN"}})
	if err != nil {
		return nil, err
	}
	var topology struct {
		Devices []blockNode `json:"blockdevices"`
	}
	if err := json.Unmarshal(output, &topology); err != nil {
		return nil, fmt.Errorf("decode block identity: %w", err)
	}
	var matches []*blockNode
	roots := make(map[*blockNode]*blockNode)
	var visit func([]blockNode, *blockNode)
	visit = func(nodes []blockNode, disk *blockNode) {
		for i := range nodes {
			n := &nodes[i]
			if n.Type == "disk" {
				disk = n
			}
			if disk != nil {
				if n.WWN == "" {
					n.WWN = disk.WWN
				}
				if n.Serial == "" {
					n.Serial = disk.Serial
				}
			}
			// Distinguish equal-sized encrypted partitions on the same medium.
			// An absent UUID remains eligible for offline post-erase readback;
			// pre-effect callers independently verify native luksUUID.
			uuidMatches := target.GetLuksUuid() == "" || n.UUID == "" || n.UUID == target.GetLuksUuid()
			if uuidMatches && n.WWN == target.GetWwn() && n.Serial == target.GetSerial() && n.Size == target.GetSizeBytes() {
				matches = append(matches, n)
				roots[n] = disk
			}
			visit(n.Children, disk)
		}
	}
	visit(topology.Devices, nil)
	if len(matches) != 1 {
		return nil, fmt.Errorf("%w: target_identity_ambiguous", ErrConflict)
	}
	node := *matches[0]
	if target.GetWwn() == "" || target.GetSerial() == "" || filepath.Dir(node.Path) != "/dev" || filepath.Clean(node.Path) != node.Path {
		return nil, fmt.Errorf("%w: incomplete_target_identity", ErrUnsupported)
	}
	flags := unix.O_RDONLY
	if writable {
		flags = unix.O_RDWR
	}
	fd, err := unix.Open(node.Path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "qualified-block-target")
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	actual := fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || actual != node.Device {
		return nil, fmt.Errorf("%w: target_device_changed", ErrConflict)
	}
	if destructive(spec) {
		disk := roots[matches[0]]
		if disk == nil || (spec.GetSanitize() != nil && node.Type != "disk") {
			return nil, ErrUnsupported
		}
		if err := p.offlineTarget(ctx, spec, *disk, qualification); err != nil {
			return nil, err
		}
		// BLKEXCL prevents opening a mounted filesystem/device-mapper backing device
		// between the graph observation and the destructive effect.
		if writable {
			if err := file.Close(); err != nil {
				return nil, err
			}
			fd, err = unix.Open(node.Path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_EXCL|unix.O_NONBLOCK, 0)
			if err != nil {
				return nil, err
			}
			file = os.NewFile(uintptr(fd), "exclusive-qualified-target")
			if err := unix.Fstat(fd, &st); err != nil {
				return nil, err
			}
			if st.Mode&unix.S_IFMT != unix.S_IFBLK || fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)) != actual {
				return nil, ErrConflict
			}
		}
	}
	return &targetHandle{file: file, node: node, qualification: qualification}, nil
}

func (p *Provider) offlineTarget(ctx context.Context, spec *agentv1.DeviceActionSpec, node blockNode, qualification *agentv1.QualifiedActionTarget) error {
	if !p.config.GetRecoveryEnvironment() || qualification.GetQualificationId() == "" || node.Type != "disk" || p.config.GetProtectedStateDirectory() == "" {
		return fmt.Errorf("%w: recovery_qualification_required", ErrUnsupported)
	}
	if err := protectedDirectory(p.config.GetProtectedStateDirectory()); err != nil {
		return err
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(p.config.GetProtectedStateDirectory(), &filesystem); err != nil {
		return err
	}
	if err := p.checkRecoveryState(ctx, spec, filesystem.Type); err != nil {
		return err
	}
	var state, root unix.Stat_t
	if err := unix.Stat(p.config.GetProtectedStateDirectory(), &state); err != nil {
		return err
	}
	if err := unix.Stat("/", &root); err != nil {
		return err
	}
	return checkOfflineTree(node, state.Dev, root.Dev, func(device string) (bool, error) {
		// Kernel device numbers, not remote data, select the sysfs directory.
		parts := strings.Split(device, ":")
		if len(parts) != 2 {
			return false, ErrConflict
		}
		for _, part := range parts {
			if _, err := strconv.ParseUint(part, 10, 32); err != nil {
				return false, ErrConflict
			}
		}
		entries, err := os.ReadDir("/sys/dev/block/" + device + "/holders")
		return len(entries) != 0, err
	})
}

func (p *Provider) checkRecoveryState(ctx context.Context, spec *agentv1.DeviceActionSpec, filesystemType int64) error {
	if filesystemType == unix.OVERLAYFS_SUPER_MAGIC {
		return fmt.Errorf("%w: durable_off_target_state_required", ErrUnsupported)
	}
	if p.recoveryCustody != nil {
		if !p.config.GetRecoveryEnvironment() || spec.GetSanitize().GetRecovery() == nil {
			return fmt.Errorf("%w: signed_recovery_scope_required", ErrUnsupported)
		}
		return p.recoveryCustody(ctx, spec)
	}
	if filesystemType == unix.TMPFS_MAGIC || filesystemType == unix.RAMFS_MAGIC {
		return fmt.Errorf("%w: durable_off_target_state_required", ErrUnsupported)
	}
	return nil
}

func checkOfflineTree(node blockNode, stateDevice, rootDevice uint64, hasHolders func(string) (bool, error)) error {
	if node.Device == fmt.Sprintf("%d:%d", unix.Major(stateDevice), unix.Minor(stateDevice)) || node.Device == fmt.Sprintf("%d:%d", unix.Major(rootDevice), unix.Minor(rootDevice)) {
		return fmt.Errorf("%w: protected_target", ErrUnsupported)
	}
	for _, mount := range node.Mountpoints {
		if mount != nil && *mount != "" {
			return fmt.Errorf("%w: mounted_target", ErrUnsupported)
		}
	}
	if node.Filesystem == "swap" {
		return fmt.Errorf("%w: swap_target", ErrUnsupported)
	}
	holders, err := hasHolders(node.Device)
	if err != nil {
		return err
	}
	if holders {
		return fmt.Errorf("%w: active_block_holder", ErrUnsupported)
	}
	for _, child := range node.Children {
		if err := checkOfflineTree(child, stateDevice, rootDevice, hasHolders); err != nil {
			return err
		}
	}
	return nil
}

func encryptedTree(node blockNode) bool {
	if node.Filesystem == "crypto_LUKS" {
		return true
	}
	for _, child := range node.Children {
		if encryptedTree(child) {
			return true
		}
	}
	return false
}
