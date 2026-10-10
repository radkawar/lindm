//go:build linux

package actionprovider

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fixed little-endian structures from the NVMe Identify Controller/Namespace,
// Namespace List and Sanitize Status log definitions (libnvme nvme/types.h).
// No human-readable nvme-cli output is used as completion evidence.
const (
	nvmeIdentifyBytes     = 4096
	nvmeSanitizeLogBytes  = 512
	nvmeMaximumNamespaces = 256
)

type nvmeController struct {
	serial, model, firmware string
	id, oacs                uint16
	vid, ssvid              uint16
	cmic, fna               byte
	sanicap, namespaces     uint32
	digest                  [sha256.Size]byte
}

type nvmeNamespace struct {
	size        uint64
	lbaf, shift byte
	nguid       [16]byte
	eui64       [8]byte
	digest      [sha256.Size]byte
}

type nvmeSanitizeStatus struct {
	progress, status uint16
	command          uint32
}

func nvmeASCII(data []byte) (string, error) {
	for _, b := range data {
		if b < 0x20 || b > 0x7e {
			return "", fmt.Errorf("%w: nvme_identity_encoding", ErrUnsupported)
		}
	}
	value := strings.TrimRight(string(data), " ")
	if value == "" {
		return "", fmt.Errorf("%w: nvme_identity_absent", ErrUnsupported)
	}
	return value, nil
}

func parseNVMeController(data []byte) (nvmeController, error) {
	var result nvmeController
	if len(data) != nvmeIdentifyBytes {
		return result, fmt.Errorf("%w: nvme_identify_controller_length", ErrUnsupported)
	}
	var err error
	if result.serial, err = nvmeASCII(data[4:24]); err != nil {
		return result, err
	}
	if result.model, err = nvmeASCII(data[24:64]); err != nil {
		return result, err
	}
	if result.firmware, err = nvmeASCII(data[64:72]); err != nil {
		return result, err
	}
	result.vid = binary.LittleEndian.Uint16(data[0:2])
	result.ssvid = binary.LittleEndian.Uint16(data[2:4])
	if result.vid == 0 {
		return result, fmt.Errorf("%w: nvme_vendor_identity_absent", ErrUnsupported)
	}
	result.cmic = data[76]
	result.id = binary.LittleEndian.Uint16(data[78:80])
	result.oacs = binary.LittleEndian.Uint16(data[256:258])
	result.sanicap = binary.LittleEndian.Uint32(data[328:332])
	result.namespaces = binary.LittleEndian.Uint32(data[516:520])
	result.fna = data[524]
	result.digest = sha256.Sum256(data)
	// No shared, multi-port, virtual-function or asymmetric-access subsystem:
	// the namespace's offline graph cannot establish custody over those paths.
	if result.cmic != 0 || result.namespaces == 0 {
		return result, fmt.Errorf("%w: nvme_shared_controller", ErrUnsupported)
	}
	return result, nil
}

func parseNVMeNamespace(data []byte) (nvmeNamespace, error) {
	var result nvmeNamespace
	if len(data) != nvmeIdentifyBytes {
		return result, fmt.Errorf("%w: nvme_identify_namespace_length", ErrUnsupported)
	}
	// Preserve the current simple LBA format. Metadata, protection information,
	// shared namespaces, extended LBA formats and an in-progress format are not
	// supported by this implementation; never silently change the native layout.
	result.lbaf = data[26] & 0xf
	if data[26]&0xf0 != 0 || result.lbaf > data[25] || data[29] != 0 || data[30] != 0 || data[32]&0x7f != 0 {
		return result, fmt.Errorf("%w: nvme_namespace_layout", ErrUnsupported)
	}
	format := data[128+int(result.lbaf)*4 : 132+int(result.lbaf)*4]
	result.shift = format[2]
	if binary.LittleEndian.Uint16(format[:2]) != 0 || result.shift < 9 || result.shift > 12 {
		return result, fmt.Errorf("%w: nvme_lba_layout", ErrUnsupported)
	}
	blocks := binary.LittleEndian.Uint64(data[:8])
	capacity := binary.LittleEndian.Uint64(data[8:16])
	if blocks == 0 || capacity == 0 || capacity > blocks || blocks > (uint64(1)<<63-1)>>result.shift {
		return result, fmt.Errorf("%w: nvme_namespace_capacity", ErrUnsupported)
	}
	result.size = blocks << result.shift
	if result.size < 4096 {
		return result, ErrUnsupported
	}
	copy(result.nguid[:], data[104:120])
	copy(result.eui64[:], data[120:128])
	// NUSE and FPI are mutable operation counters, not identity/layout. Clear
	// precisely those bytes in the canonical hash so post-erase readback binds
	// the same namespace despite changed utilization/progress counters.
	hash := sha256.New()
	var zeros [8]byte
	_, _ = hash.Write(data[:16])
	_, _ = hash.Write(zeros[:])
	_, _ = hash.Write(data[24:32])
	_, _ = hash.Write(zeros[:1])
	_, _ = hash.Write(data[33:])
	copy(result.digest[:], hash.Sum(nil))
	return result, nil
}

func (n nvmeNamespace) matchesWWN(wwn string) bool {
	// Linux NVMe exposes NGUID/EUI64 as eui.<hex>. A UUID-only namespace needs
	// the distinct namespace-identification-descriptor implementation; refuse it.
	return n.nguid != [16]byte{} && wwn == "eui."+hex.EncodeToString(n.nguid[:]) ||
		n.eui64 != [8]byte{} && wwn == "eui."+hex.EncodeToString(n.eui64[:])
}

func (c nvmeController) fallbackWWN(nsid uint32) string {
	// Linux drivers/nvme/host/sysfs.c:wwid_show uses this only when no NID
	// survives the kernel's namespace-identifier checks. Derive it from native
	// Identify bytes, never a controller pathname or sysfs identity lookup.
	return fmt.Sprintf("nvme.%04x-%x-%x-%08x", c.vid, c.serial, c.model, nsid)
}

func parseNVMeNamespaceList(data []byte) ([]uint32, error) {
	if len(data) != nvmeIdentifyBytes {
		return nil, fmt.Errorf("%w: nvme_namespace_list_length", ErrUnsupported)
	}
	var ids []uint32
	terminated := false
	var previous uint32
	for offset := 0; offset < len(data); offset += 4 {
		id := binary.LittleEndian.Uint32(data[offset : offset+4])
		if id == 0 {
			terminated = true
			continue
		}
		if terminated || id <= previous || id == ^uint32(0) || len(ids) == nvmeMaximumNamespaces {
			return nil, fmt.Errorf("%w: nvme_namespace_list_ambiguous", ErrUnsupported)
		}
		ids = append(ids, id)
		previous = id
	}
	if len(ids) == 0 || !terminated {
		return nil, fmt.Errorf("%w: nvme_namespace_list_incomplete", ErrUnsupported)
	}
	return ids, nil
}

func parseNVMeSanitizeStatus(data []byte) (nvmeSanitizeStatus, error) {
	var result nvmeSanitizeStatus
	if len(data) != nvmeSanitizeLogBytes {
		return result, fmt.Errorf("%w: nvme_sanitize_status_length", ErrNotVerified)
	}
	result.progress = binary.LittleEndian.Uint16(data[:2])
	result.status = binary.LittleEndian.Uint16(data[2:4])
	result.command = binary.LittleEndian.Uint32(data[4:8])
	if result.status&7 > 4 || result.status&0xfe00 != 0 || result.status&7 != 2 && result.progress != 0xffff {
		return result, fmt.Errorf("%w: nvme_sanitize_status_invalid", ErrNotVerified)
	}
	return result, nil
}

func (s nvmeSanitizeStatus) complete(command uint32) bool {
	// We never request No-Deallocate, so status 4 is not our completion. GDE
	// must be set and the retained command must match, not a prior other method.
	return s.status == 0x101 && s.progress == 0xffff && s.command == command
}
