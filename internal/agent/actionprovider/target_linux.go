// SPDX-License-Identifier: Apache-2.0

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
	Path           string      `json:"path"`
	Type           string      `json:"type"`
	Size           uint64      `json:"size"`
	WWN            string      `json:"wwn"`
	Serial         string      `json:"serial"`
	UUID           string      `json:"uuid"`
	PartitionTable string      `json:"pttype"`
	DiskGUID       string      `json:"ptuuid"`
	Rotational     bool        `json:"rota"`
	Mountpoints    []*string   `json:"mountpoints"`
	Filesystem     string      `json:"fstype"`
	Device         string      `json:"maj:min"`
	Children       []blockNode `json:"children"`

	nativeWWN    bool
	nativeSerial bool
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
	output, err := p.run(ctx, nativeRequest{command: lsblk, args: []string{"--json", "--tree", "--bytes", "--output", "PATH,TYPE,SIZE,WWN,SERIAL,UUID,ROTA,MOUNTPOINTS,FSTYPE,MAJ:MIN,PTTYPE,PTUUID"}})
	if err != nil {
		return nil, err
	}
	var topology struct {
		Devices []blockNode `json:"blockdevices"`
	}
	if err := json.Unmarshal(output, &topology); err != nil {
		return nil, fmt.Errorf("decode block identity: %w", err)
	}
	selected, disk, diagnostic := resolveTargetIdentity(topology.Devices, target, spec.GetSanitize() != nil, nativeBlockIdentity)
	if diagnostic.MatchCount != 1 {
		return nil, fmt.Errorf("%w: target_identity_ambiguous %s", ErrConflict, diagnostic.encode())
	}
	node := *selected
	if filepath.Dir(node.Path) != "/dev" || filepath.Clean(node.Path) != node.Path {
		return nil, fmt.Errorf("%w: incomplete_target_identity", ErrUnsupported)
	}
	flags := unix.O_RDONLY
	if writable {
		flags = unix.O_RDWR
	}
	// The executor's private /dev contains only the provisioned nodes. A LUKS
	// target is bound at its stable UUID alias (see SandboxDevices), so the
	// boot-local kernel name lsblk reports may be absent there. The device
	// number check below still binds whichever path opens to the selected node.
	path := node.Path
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) && node.UUID != "" && node.UUID == target.GetLuksUuid() {
		path = stableTargetAlias(target)
		fd, err = unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
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
			fd, err = unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_EXCL|unix.O_NONBLOCK, 0)
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
	size, err := blockSize(file)
	if err != nil || size != target.GetSizeBytes() {
		return nil, errors.Join(fmt.Errorf("%w: target_size_changed", ErrConflict), err)
	}
	if node.Type == "disk" {
		// Re-observe kernel identity after pinning the selected descriptor (and
		// after its exclusive reopen). Boot-local names never establish identity.
		if !sameNativeBlockIdentity(node, nativeBlockIdentity(actual)) {
			return nil, fmt.Errorf("%w: target_native_identity_changed", ErrConflict)
		}
	}
	if target.GetIdentityBasis() == agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS {
		if err := verifyFallbackDisk(*disk, node, target); err != nil {
			return nil, err
		}
	}
	return &targetHandle{file: file, node: node, qualification: qualification}, nil
}

func resolveTargetIdentity(nodes []blockNode, target *agentv1.StorageTarget, wholeDisk bool, native func(string) sysfsBlockIdentity) (selected, root *blockNode, diagnostic targetIdentityDiagnostic) {
	diagnostic.Approved = identityDiagnosticTarget(target)
	serialDisks := 0
	var visit func([]blockNode, *blockNode, string)
	visit = func(nodes []blockNode, parent *blockNode, parentError string) {
		for i := range nodes {
			n := &nodes[i]
			candidate := identityDiagnosticNode(*n)
			// The parent belongs to this branch only. A preceding disk at the
			// same tree level is not the backing disk of an orphan partition.
			disk, identityError := parent, parentError
			if n.Type == "disk" {
				disk = n
				evidence := native(n.Device)
				if n.Serial == target.GetSerial() || evidence.Serial.Value == target.GetSerial() || evidence.BlockSerial.Value == target.GetSerial() || evidence.VPDSerial.Value == target.GetSerial() {
					serialDisks++
				}
				candidate.Sysfs = evidence.diagnostic()
				identityError = resolveBlockIdentity(n, evidence)
				if target.GetIdentityBasis() == agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS && !absentNativeWWN(evidence) {
					identityError = "fallback_wwn_not_absent"
				}
			} else if disk != nil {
				if n.Type == "part" && (n.WWN != "" && n.WWN != disk.WWN || n.Serial != "" && n.Serial != disk.Serial) {
					identityError = "partition_identity_conflict"
				}
				if n.WWN == "" {
					n.WWN = disk.WWN
				}
				if n.Serial == "" {
					n.Serial = disk.Serial
				}
			}
			// An absent UUID remains eligible for offline post-erase readback;
			// pre-effect LUKS callers independently verify native luksUUID.
			uuidMatches := target.GetLuksUuid() == "" || n.UUID == "" || n.UUID == target.GetLuksUuid()
			typeMatches := !wholeDisk || n.Type == "disk"
			candidate.Matched = identityError == "" && disk != nil && typeMatches && uuidMatches &&
				target.GetSerial() != "" && target.GetSizeBytes() != 0 &&
				n.Serial == target.GetSerial() && n.Size == target.GetSizeBytes() &&
				matchesStorageBasis(n, disk, target)
			if candidate.Matched {
				diagnostic.MatchCount++
				selected, root = n, disk
			}
			candidate.EffectiveWWN = diagnosticIdentityText(n.WWN)
			candidate.EffectiveSerial = diagnosticIdentityText(n.Serial)
			candidate.IdentityError = identityError
			diagnostic.CandidateCount++
			if len(diagnostic.Candidates) < 16 {
				diagnostic.Candidates = append(diagnostic.Candidates, candidate)
			}
			visit(n.Children, disk, identityError)
		}
	}
	visit(nodes, nil, "")
	// A fallback serial must identify one physical disk even if another disk
	// has a different GUID, size or LUKS UUID. Child inheritance is not a disk.
	if diagnostic.MatchCount == 1 && target.GetIdentityBasis() == agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS {
		if serialDisks != 1 {
			diagnostic.MatchCount = 0
		}
	}
	if diagnostic.MatchCount != 1 {
		return nil, nil, diagnostic
	}
	return selected, root, diagnostic
}

func matchesStorageBasis(node, disk *blockNode, target *agentv1.StorageTarget) bool {
	switch target.GetIdentityBasis() {
	case agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL:
		return target.GetWwn() != "" && node.WWN == target.GetWwn()
	case agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS:
		return target.GetWwn() == "" && node.WWN == "" && disk.WWN == "" &&
			target.GetLuksUuid() != "" && target.GetGptDiskGuid() != "" &&
			disk.PartitionTable == "gpt" && disk.DiskGUID == target.GetGptDiskGuid() &&
			disk.Size == target.GetDiskSizeBytes() && disk.Size >= node.Size &&
			node.Type == "part" && (node.Filesystem == "crypto_LUKS" || node.UUID == "" && node.Filesystem == "")
	default:
		return false
	}
}

func absentNativeWWN(evidence sysfsBlockIdentity) bool {
	for _, value := range [...]sysfsIdentityValue{evidence.WWID, evidence.DeviceWWID} {
		if value.Value != "" || value.Error != "" && value.Error != "absent" && value.Error != "empty" {
			return false
		}
	}
	return true
}

// Identity diagnostics contain only bounded hardware identifiers, never mounts,
// filesystem labels, command output, credentials or signed recovery material.
type targetIdentityDiagnostic struct {
	Approved          targetIdentityFields      `json:"approved"`
	CandidateCount    int                       `json:"candidate_count"`
	MatchCount        int                       `json:"match_count"`
	Candidates        []targetIdentityCandidate `json:"candidates"`
	CandidatesOmitted int                       `json:"candidates_omitted"`
}

type targetIdentityFields struct {
	WWN      string                       `json:"wwn"`
	Serial   string                       `json:"serial"`
	UUID     string                       `json:"uuid"`
	Size     uint64                       `json:"size"`
	Basis    agentv1.StorageIdentityBasis `json:"identity_basis,omitempty"`
	DiskGUID string                       `json:"gpt_disk_guid,omitempty"`
	DiskSize uint64                       `json:"disk_size_bytes,omitempty"`
}

type targetIdentityCandidate struct {
	targetIdentityFields
	Path            string              `json:"path"`
	Type            string              `json:"type"`
	Device          string              `json:"device"`
	EffectiveWWN    string              `json:"effective_wwn"`
	EffectiveSerial string              `json:"effective_serial"`
	Matched         bool                `json:"matched"`
	Sysfs           *sysfsBlockIdentity `json:"sysfs,omitempty"`
	IdentityError   string              `json:"identity_error,omitempty"`
}

func (diagnostic targetIdentityDiagnostic) encode() []byte {
	// Even adversarial escaped identifiers must fit the retained 16 KiB console
	// tail. Keep the approved tuple and total/match counts if rows do not fit.
	const maximumBytes = 12 << 10
	for {
		diagnostic.CandidatesOmitted = diagnostic.CandidateCount - len(diagnostic.Candidates)
		encoded, _ := json.Marshal(diagnostic)
		if len(encoded) <= maximumBytes || len(diagnostic.Candidates) == 0 {
			return encoded
		}
		diagnostic.Candidates = diagnostic.Candidates[:len(diagnostic.Candidates)-1]
	}
}

func diagnosticIdentityText(value string) string {
	const maximumBytes = 256
	if len(value) > maximumBytes {
		return value[:maximumBytes] + "[truncated]"
	}
	return value
}

func identityDiagnosticTarget(target *agentv1.StorageTarget) targetIdentityFields {
	return targetIdentityFields{WWN: diagnosticIdentityText(target.GetWwn()), Serial: diagnosticIdentityText(target.GetSerial()), UUID: diagnosticIdentityText(target.GetLuksUuid()), Size: target.GetSizeBytes(), Basis: target.GetIdentityBasis(), DiskGUID: diagnosticIdentityText(target.GetGptDiskGuid()), DiskSize: target.GetDiskSizeBytes()}
}

func identityDiagnosticNode(node blockNode) targetIdentityCandidate {
	return targetIdentityCandidate{
		targetIdentityFields: targetIdentityFields{WWN: diagnosticIdentityText(node.WWN), Serial: diagnosticIdentityText(node.Serial), UUID: diagnosticIdentityText(node.UUID), Size: node.Size, DiskGUID: diagnosticIdentityText(node.DiskGUID)},
		Path:                 diagnosticIdentityText(node.Path),
		Type:                 diagnosticIdentityText(node.Type),
		Device:               diagnosticIdentityText(node.Device),
	}
}

func (p *Provider) offlineTarget(ctx context.Context, spec *agentv1.DeviceActionSpec, node blockNode, qualification *agentv1.QualifiedActionTarget) error {
	if !p.config.GetRecoveryEnvironment() || qualification.GetQualificationId() == "" || node.Type != "disk" || p.config.GetProtectedStateDirectory() == "" {
		return fmt.Errorf("%w: recovery_qualification_required", ErrUnsupported)
	}
	if err := privateStateDirectory(p.config.GetProtectedStateDirectory()); err != nil {
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
