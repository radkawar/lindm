//go:build linux

package actionprovider

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// NVME_IOCTL_ID is _IO('N', 0x40) from linux/nvme_ioctl.h. It returns the
// namespace ID for this already identity-checked block descriptor, never a
// namespace/controller inferred from the spelling of a /dev path.
func nvmeNamespaceID(file *os.File) (uint32, error) {
	id, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), 0x4e40, 0)
	runtime.KeepAlive(file)
	if errno != 0 || id == 0 || id >= uintptr(^uint32(0)) {
		return 0, fmt.Errorf("%w: nvme_namespace_descriptor: %v", ErrUnsupported, errno)
	}
	return uint32(id), nil
}

// ReadNVMeSanitizeScope discovers approval identity from the kernel's sysfs
// projection of the Identify data it read at probe time, so it needs no
// CAP_SYS_ADMIN on any kernel (Linux <6.2 refuses unprivileged Identify). The
// caller owns the pinned read-only block descriptor and supplies the
// independently observed storage target. An absent or unusable attribute is an
// explicit *NVMeScopeRefusal, never a fallback to another source. This does not
// authorize erasure, qualify a method, or select controller-wide scope.
func ReadNVMeSanitizeScope(ctx context.Context, file *os.File, target *agentv1.StorageTarget) (*agentv1.NVMeSanitizeScope, error) {
	nsid, rdev, err := pinnedNVMeNamespace(ctx, file, target)
	if err != nil {
		return nil, err
	}
	size, err := blockSize(file)
	if err != nil {
		return nil, err
	}
	return readNVMeSysfsScope(os.DirFS("/sys"), rdev, size, target, nsid)
}

// ReadNVMeIdentifyScope derives the same approval identity from native Identify
// Controller/Namespace admin passthrough. It is the parity oracle for the sysfs
// reader; inventory never uses it.
func ReadNVMeIdentifyScope(ctx context.Context, file *os.File, target *agentv1.StorageTarget) (*agentv1.NVMeSanitizeScope, error) {
	nsid, _, err := pinnedNVMeNamespace(ctx, file, target)
	if err != nil {
		return nil, err
	}
	p := &Provider{run: runNative}
	return p.readNVMeSanitizeScope(ctx, file, target, nsid)
}

func pinnedNVMeNamespace(ctx context.Context, file *os.File, target *agentv1.StorageTarget) (uint32, uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if file == nil || target == nil {
		return 0, 0, ErrUnsupported
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return 0, 0, err
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return 0, 0, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return 0, 0, fmt.Errorf("%w: nvme_read_only_namespace_required", ErrUnsupported)
	}
	nsid, err := nvmeNamespaceID(file)
	if err != nil {
		return 0, 0, err
	}
	return nsid, stat.Rdev, nil
}

func (p *Provider) readNVMeIdentify(ctx context.Context, file *os.File, nsid uint32) ([]byte, []byte, error) {
	controller, err := p.nvmeAdmin(ctx, file, 6, 0, 1, nvmeIdentifyBytes)
	if err != nil {
		return nil, nil, err
	}
	namespace, err := p.nvmeAdmin(ctx, file, 6, nsid, 0, nvmeIdentifyBytes)
	if err != nil {
		return nil, nil, err
	}
	return controller, namespace, nil
}

func (p *Provider) readNVMeSanitizeScope(ctx context.Context, file *os.File, target *agentv1.StorageTarget, nsid uint32) (*agentv1.NVMeSanitizeScope, error) {
	controllerData, namespaceData, err := p.readNVMeIdentify(ctx, file, nsid)
	if err != nil {
		return nil, err
	}
	controller, err := parseNVMeController(controllerData)
	if err != nil {
		return nil, err
	}
	namespace, err := parseNVMeNamespace(namespaceData)
	if err != nil {
		return nil, err
	}
	basis, err := nvmeIdentityBasis(target, nsid, controller, namespace)
	if err != nil {
		return nil, err
	}
	return &agentv1.NVMeSanitizeScope{
		NamespaceId: nsid,
		Identity: &agentv1.NVMeSanitizeIdentity{
			Basis:              basis,
			VendorId:           uint32(controller.vid),
			SubsystemVendorId:  uint32(controller.ssvid),
			ControllerSerial:   controller.serial,
			ControllerModel:    controller.model,
			ControllerFirmware: controller.firmware,
			NamespaceSizeBytes: namespace.size,
			LbaDataSizeShift:   uint32(namespace.shift),
		},
	}, nil
}

// nvmeAdmin submits precisely one Linux NVME_IOCTL_ADMIN_CMD through nvme-cli's
// documented admin-passthru interface. All opcodes/dwords are locally derived,
// not caller argv. Unlike `nvme format`, passthru does not perform a controller
// reset, namespace rescan or implicit second format. The inherited namespace fd
// keeps the exact device pinned. CAP_SYS_ADMIN is required, not CAP_SYS_RAWIO;
// no controller character-device or PCI configuration access is needed.
func (p *Provider) nvmeAdmin(ctx context.Context, file *os.File, opcode, nsid, cdw10 uint32, length int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := []string{
		"admin-passthru", descriptor(0),
		"--opcode=" + strconv.FormatUint(uint64(opcode), 10),
		"--namespace-id=" + strconv.FormatUint(uint64(nsid), 10),
		"--cdw10=" + strconv.FormatUint(uint64(cdw10), 10),
		"--timeout=60000",
	}
	if length != 0 {
		args = append(args, "--data-len="+strconv.Itoa(length), "--read", "--raw-binary")
	}
	data, err := p.run(ctx, nativeRequest{command: nvme, args: args, files: []*os.File{file}})
	if err != nil {
		return nil, err
	}
	if length != 0 && len(data) != length {
		return nil, fmt.Errorf("%w: nvme_native_response_length", ErrNotVerified)
	}
	return data, nil
}

func (p *Provider) nvmeStatus(ctx context.Context, file *os.File) (nvmeSanitizeStatus, error) {
	// Get Log Page 81h, 512 bytes (NUMDL=127), retain asynchronous events.
	data, err := p.nvmeAdmin(ctx, file, 0x02, ^uint32(0), 127<<16|1<<15|0x81, nvmeSanitizeLogBytes)
	if err != nil {
		return nvmeSanitizeStatus{}, err
	}
	return parseNVMeSanitizeStatus(data)
}

func invalidateNVMeSamples(file *os.File) error {
	// Firmware erasure bypasses the Linux block page cache. Without BLKFLSBUF,
	// ordinary reads could falsely report pre-command cached bytes as readback.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), unix.BLKFLSBUF, 0)
	runtime.KeepAlive(file)
	if errno != 0 {
		return errno
	}
	return nil
}

const nvmeSampleCount = 257

type nvmeSamples struct {
	digest  [sha256.Size]byte
	blocks  [nvmeSampleCount][sha256.Size]byte
	nonzero [nvmeSampleCount]bool
	read    uint32
}

// Native erase contents are explicitly indeterminate in NVMe, so zeros are not
// the only valid output. Require readable, distributed post-command samples and
// reject every unchanged previously nonzero sample. This is an operational
// cross-check of controller completion, not proof of inaccessible-cell erasure.
func readNVMeSamples(ctx context.Context, reader io.ReaderAt, size uint64, before *nvmeSamples) (nvmeSamples, error) {
	var result nvmeSamples
	if size < 4096 || size%4096 != 0 || size > uint64(1)<<63-1 {
		return result, ErrUnsupported
	}
	var buffer [4096]byte
	var encodedOffset [8]byte
	hash := sha256.New()
	for index := uint64(0); index < nvmeSampleCount; index++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		offset := ((size - 4096) / 256 * index) / 4096 * 4096
		if index == nvmeSampleCount-1 {
			offset = size - 4096
		}
		n, err := reader.ReadAt(buffer[:], int64(offset))
		if err != nil || n != len(buffer) {
			return result, errors.Join(ErrNotVerified, err, io.ErrUnexpectedEOF)
		}
		result.blocks[index] = sha256.Sum256(buffer[:])
		for _, value := range buffer {
			if value != 0 {
				result.nonzero[index] = true
				break
			}
		}
		result.read++
		if before != nil && before.nonzero[index] && before.blocks[index] == result.blocks[index] {
			return result, fmt.Errorf("%w: nvme_unchanged_sample", ErrNotVerified)
		}
		binary.LittleEndian.PutUint64(encodedOffset[:], offset)
		_, _ = hash.Write(encodedOffset[:])
		_, _ = hash.Write(buffer[:])
	}
	copy(result.digest[:], hash.Sum(nil))
	return result, nil
}
