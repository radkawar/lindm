// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"errors"
	"fmt"
	"io/fs"
	"math/bits"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// NVMeScopeRefusal is an explicit, fixed-code refusal to derive a namespace's
// approval identity from sysfs. Reason is a stable lower_snake identifier.
type NVMeScopeRefusal struct{ Reason string }

func (e *NVMeScopeRefusal) Error() string { return "nvme_scope_refused: " + e.Reason }

// Is keeps a refusal an unsupported native capability for generic callers.
func (e *NVMeScopeRefusal) Is(target error) bool { return target == ErrUnsupported }

func refuseNVMeScope(reason string) error { return &NVMeScopeRefusal{Reason: reason} }

const sysfsAttributeLimit = 256

var nvmeEUIWWID = regexp.MustCompile(`^eui\.([0-9a-f]{16}|[0-9a-f]{32})$`)

// readNVMeSysfsScope reads the namespace located by the pinned descriptor's
// device number. Every attribute is the kernel's own copy of Identify data it
// read at probe time (Linux drivers/nvme/host/sysfs.c), except VID/SSVID, which
// come from the PCI function's configuration header that NVMe defines as the
// same values; the kernel's wwid fallback (Identify VID) cross-checks VID.
func readNVMeSysfsScope(sys fs.FS, rdev, size uint64, target *agentv1.StorageTarget, nsid uint32) (*agentv1.NVMeSanitizeScope, error) {
	ns := fmt.Sprintf("dev/block/%d:%d", unix.Major(rdev), unix.Minor(rdev))
	if _, err := fs.Stat(sys, ns+"/partition"); err == nil {
		return nil, refuseNVMeScope("nvme_sysfs_partition")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	text, err := sysfsAttribute(sys, ns+"/nsid", "nvme_sysfs_nsid_absent")
	if err != nil {
		return nil, err
	}
	if id, err := strconv.ParseUint(text, 10, 32); err != nil || uint32(id) != nsid {
		return nil, refuseNVMeScope("nvme_sysfs_nsid_mismatch")
	}
	controller, err := nvmeSysfsController(sys, ns+"/device")
	if err != nil {
		return nil, err
	}
	transport, err := sysfsAttribute(sys, controller+"/transport", "nvme_sysfs_transport_absent")
	if err != nil {
		return nil, err
	}
	if transport != "pcie" {
		return nil, refuseNVMeScope("nvme_transport_not_pcie")
	}
	vid, err := sysfsHex16(sys, controller+"/device/vendor", "nvme_pci_vendor_absent")
	if err != nil {
		return nil, err
	}
	if vid == 0 {
		return nil, refuseNVMeScope("nvme_vendor_identity_absent")
	}
	ssvid, err := sysfsHex16(sys, controller+"/device/subsystem_vendor", "nvme_pci_subsystem_vendor_absent")
	if err != nil {
		return nil, err
	}
	serial, err := sysfsIdentifyString(sys, controller+"/serial", 20, "nvme_sysfs_serial")
	if err != nil {
		return nil, err
	}
	model, err := sysfsIdentifyString(sys, controller+"/model", 40, "nvme_sysfs_model")
	if err != nil {
		return nil, err
	}
	firmware, err := sysfsIdentifyString(sys, controller+"/firmware_rev", 8, "nvme_sysfs_firmware")
	if err != nil {
		return nil, err
	}
	text, err = sysfsAttribute(sys, ns+"/queue/logical_block_size", "nvme_sysfs_block_size_absent")
	if err != nil {
		return nil, err
	}
	blockBytes, err := strconv.ParseUint(text, 10, 32)
	if err != nil || blockBytes < 512 || blockBytes > 4096 || bits.OnesCount64(blockBytes) != 1 {
		return nil, refuseNVMeScope("nvme_lba_layout")
	}
	shift := uint32(bits.TrailingZeros64(blockBytes))
	text, err = sysfsAttribute(sys, ns+"/size", "nvme_sysfs_size_absent")
	if err != nil {
		return nil, err
	}
	// sysfs size is in 512-byte sectors; the pinned descriptor's size binds it.
	sectors, err := strconv.ParseUint(text, 10, 64)
	if err != nil || sectors > size>>9 || sectors<<9 != size {
		return nil, refuseNVMeScope("nvme_sysfs_size_mismatch")
	}
	if size < 4096 || size%blockBytes != 0 {
		return nil, refuseNVMeScope("nvme_namespace_capacity")
	}
	if serial != target.GetSerial() || size != target.GetSizeBytes() {
		return nil, refuseNVMeScope("nvme_exact_identity_changed")
	}
	wwid, err := sysfsAttribute(sys, ns+"/wwid", "nvme_sysfs_wwid_absent")
	if err != nil {
		return nil, err
	}
	basis, err := nvmeSysfsBasis(wwid, target.GetWwn(), fmt.Sprintf("nvme.%04x-%x-%x-%08x", vid, serial, model, nsid))
	if err != nil {
		return nil, err
	}
	return &agentv1.NVMeSanitizeScope{
		NamespaceId: nsid,
		Identity: &agentv1.NVMeSanitizeIdentity{
			Basis: basis, VendorId: uint32(vid), SubsystemVendorId: uint32(ssvid),
			ControllerSerial: serial, ControllerModel: model, ControllerFirmware: firmware,
			NamespaceSizeBytes: size, LbaDataSizeShift: shift,
		},
	}, nil
}

// nvmeSysfsBasis follows Linux wwid_show: a UUID, then NGUID, then EUI64 NID,
// otherwise the controller VID/serial/model/NSID fallback. A UUID-only
// namespace needs the distinct descriptor implementation, so it is refused.
func nvmeSysfsBasis(wwid, targetWWN, fallback string) (agentv1.NvmeIdentityBasis, error) {
	switch {
	case nvmeEUIWWID.MatchString(wwid):
		if targetWWN != wwid {
			return 0, refuseNVMeScope("nvme_namespace_identity_changed")
		}
		return agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_NAMESPACE_NID, nil
	case wwid == fallback:
		if targetWWN != "" && targetWWN != wwid {
			return 0, refuseNVMeScope("nvme_namespace_identity_changed")
		}
		return agentv1.NvmeIdentityBasis_NVME_IDENTITY_BASIS_CONTROLLER_SERIAL_NSID, nil
	case strings.HasPrefix(wwid, "uuid."):
		return 0, refuseNVMeScope("nvme_uuid_namespace_identity")
	case strings.HasPrefix(wwid, "nvme."):
		// The kernel spells the fallback from Identify VID/serial/model; any
		// difference means the PCI vendor or a sysfs string is not Identify's.
		return 0, refuseNVMeScope("nvme_sysfs_identity_inconsistent")
	default:
		return 0, refuseNVMeScope("nvme_sysfs_wwid_invalid")
	}
}

// nvmeSysfsController resolves the namespace's controller. A multipath head
// disk's parent is the subsystem; only a subsystem with exactly one controller
// is accepted (execution still refuses any CMIC sharing from Identify).
func nvmeSysfsController(sys fs.FS, parent string) (string, error) {
	if _, err := fs.Stat(sys, parent+"/cntlid"); err == nil {
		return parent, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	entries, err := fs.ReadDir(sys, parent)
	if errors.Is(err, fs.ErrNotExist) {
		return "", refuseNVMeScope("nvme_sysfs_controller_absent")
	}
	if err != nil {
		return "", err
	}
	var controllers []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "nvme") || strings.Trim(name[4:], "0123456789") != "" || len(name) == 4 {
			continue
		}
		if _, err := fs.Stat(sys, parent+"/"+name+"/cntlid"); err == nil {
			controllers = append(controllers, parent+"/"+name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	switch len(controllers) {
	case 0:
		return "", refuseNVMeScope("nvme_sysfs_controller_absent")
	case 1:
		return controllers[0], nil
	default:
		return "", refuseNVMeScope("nvme_multiple_controllers")
	}
}

// sysfsAttribute returns one bounded attribute without its single trailing
// newline. A missing attribute is the named refusal.
func sysfsAttribute(sys fs.FS, name, absent string) (string, error) {
	file, err := sys.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return "", refuseNVMeScope(absent)
	}
	if err != nil {
		return "", err
	}
	buffer := make([]byte, sysfsAttributeLimit+1)
	n, readErr := file.Read(buffer)
	if err := file.Close(); err != nil {
		return "", err
	}
	if readErr != nil && n == 0 || n > sysfsAttributeLimit {
		return "", refuseNVMeScope(absent)
	}
	return strings.TrimSuffix(string(buffer[:n]), "\n"), nil
}

func sysfsHex16(sys fs.FS, name, absent string) (uint16, error) {
	text, err := sysfsAttribute(sys, name, absent)
	if err != nil {
		return 0, err
	}
	digits, ok := strings.CutPrefix(text, "0x")
	value, parseErr := strconv.ParseUint(digits, 16, 16)
	if !ok || len(digits) != 4 || parseErr != nil {
		return 0, refuseNVMeScope(absent)
	}
	return uint16(value), nil
}

// sysfsIdentifyString applies the Identify ASCII rule: printable bytes with
// trailing space padding removed (older kernels print the padded field).
func sysfsIdentifyString(sys fs.FS, name string, limit int, reason string) (string, error) {
	text, err := sysfsAttribute(sys, name, reason+"_absent")
	if err != nil {
		return "", err
	}
	text = strings.TrimRight(text, " ")
	if text == "" || len(text) > limit {
		return "", refuseNVMeScope(reason + "_invalid")
	}
	for i := range len(text) {
		if text[i] < 0x20 || text[i] > 0x7e {
			return "", refuseNVMeScope(reason + "_invalid")
		}
	}
	return text, nil
}
