// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativeexec"
)

const maximumHeaderBytes = 128 << 20

// luksHeaderExtent includes both metadata areas and the entire keyslot area up to
// the sole data segment. Detached headers, reencryption/multiple segments and
// unusual oversized layouts are unsupported rather than partially destroyed.
func luksHeaderExtent(file *os.File, metadata *luksMetadata, size uint64) (uint64, error) {
	var primary [4096]byte
	if _, err := file.ReadAt(primary[:], 0); err != nil {
		return 0, err
	}
	if !bytes.Equal(primary[:6], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) || binary.BigEndian.Uint16(primary[6:8]) != 2 {
		return 0, ErrUnsupported
	}
	metadataSize := binary.BigEndian.Uint64(primary[8:16])
	if metadataSize < 16384 || metadataSize > 4<<20 || metadataSize&(metadataSize-1) != 0 {
		return 0, ErrUnsupported
	}
	var secondary [4096]byte
	if _, err := file.ReadAt(secondary[:], int64(metadataSize)); err != nil {
		return 0, err
	}
	if !bytes.Equal(secondary[:6], []byte{'S', 'K', 'U', 'L', 0xba, 0xbe}) || binary.BigEndian.Uint16(secondary[6:8]) != 2 || binary.BigEndian.Uint64(secondary[8:16]) != metadataSize {
		return 0, ErrUnsupported
	}
	if len(metadata.Segments) != 1 {
		return 0, ErrUnsupported
	}
	for _, segment := range metadata.Segments {
		offset, err := strconv.ParseUint(segment.Offset, 10, 64)
		if err != nil || segment.Type != "crypt" || offset < 2*metadataSize || offset > maximumHeaderBytes || offset >= size || offset%4096 != 0 {
			return 0, ErrUnsupported
		}
		return offset, nil
	}
	return 0, ErrUnsupported
}

func blockSize(file *os.File) (uint64, error) {
	var size uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(file)
	if errno != 0 {
		return 0, errno
	}
	return size, nil
}

func overwriteRange(ctx context.Context, file *os.File, length uint64) error {
	zeros := make([]byte, 1<<20)
	for offset := uint64(0); offset < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := min(uint64(len(zeros)), length-offset)
		written, err := file.WriteAt(zeros[:count], int64(offset))
		if err != nil {
			return err
		}
		if written != int(count) {
			return io.ErrShortWrite
		}
		offset += count
	}
	return file.Sync()
}

func verifyZeroRange(ctx context.Context, file *os.File, length uint64) error {
	buffer := make([]byte, 1<<20)
	for offset := uint64(0); offset < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := min(uint64(len(buffer)), length-offset)
		if _, err := file.ReadAt(buffer[:count], int64(offset)); err != nil {
			return err
		}
		for _, value := range buffer[:count] {
			if value != 0 {
				return ErrNotVerified
			}
		}
		offset += count
	}
	return nil
}

// Sampling is operational verification, not a claim about remapped sectors,
// firmware caches or physical sanitization. Qualification decides media/method.
func verifyZeroSamples(ctx context.Context, file *os.File, size uint64) error {
	if size < 4096 || size > uint64(^uint64(0)>>1) {
		return ErrUnsupported
	}
	var sample [4096]byte
	for index := uint64(0); index < 257; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		offset := ((size - 4096) / 256 * index) / 512 * 512
		if index == 256 {
			offset = size - 4096
		}
		if _, err := file.ReadAt(sample[:], int64(offset)); err != nil {
			return err
		}
		for _, value := range sample {
			if value != 0 {
				return ErrNotVerified
			}
		}
	}
	return nil
}

func (p *Provider) erase(ctx context.Context, plan *agentv1.DeviceActionPlan, target *targetHandle, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	metadata, digest, err := p.metadata(ctx, target.file)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, plan.GetBefore().GetMetadataSha256()) {
		return nil, ErrConflict
	}
	extent, err := luksHeaderExtent(target.file, metadata, target.node.Size)
	if err != nil {
		return nil, err
	}
	if extent != plan.GetBefore().GetLuksHeaderBytes() {
		return nil, ErrConflict
	}
	size, err := blockSize(target.file)
	if err != nil || size != plan.GetSpec().GetCryptoErase().GetTarget().GetSizeBytes() {
		return nil, errors.Join(ErrConflict, err)
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if _, err := p.crypt(ctx, target.file, []string{"luksErase", "--batch-mode", descriptor(0)}); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := overwriteRange(ctx, target.file, extent); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := p.verifyErasedHeader(ctx, target.file, extent); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	after := proto.CloneOf(plan.GetBefore())
	after.ObservedAt = timestamppb.New(p.clock())
	after.Encrypted = false
	after.LindmKeyslots = nil
	after.OccupiedKeyslots = nil
	after.LuksTokens = nil
	after.Tpm2Bound = false
	after.MetadataSha256 = nil
	if _, err := p.run(ctx, nativeRequest{command: systemctl, args: []string{"poweroff", "--no-block"}}); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return &agentv1.DeviceActionVerification{Verified: true, After: after, Evidence: "luksErase completed; both LUKS2 headers and complete keyslot extent zero-read verified; independent native luksDump rejected header. Local header destruction only: escrow/header backups are not destroyed. Poweroff requested after verification; lost report remains outcome_unknown."}, nil
}

func (p *Provider) verifyErasedHeader(ctx context.Context, file *os.File, extent uint64) error {
	if extent == 0 || extent > maximumHeaderBytes {
		return ErrConflict
	}
	if err := verifyZeroRange(ctx, file, extent); err != nil {
		return err
	}
	return p.verifyNotLUKS(ctx, file)
}

func (p *Provider) verifyNotLUKS(ctx context.Context, file *os.File) error {
	_, err := p.crypt(ctx, file, []string{"luksDump", descriptor(0)})
	var exit *nativeexec.ExitError
	// Invalid metadata can produce EINVAL/status 1 or ENODEV/status 4 depending
	// on cryptsetup version. Require its fixed C-locale invalid-LUKS diagnostic
	// as well as complete zero-read proof; argument/permission/I/O errors alone
	// never establish success. Native diagnostics themselves are never exposed.
	if !errors.Is(err, errNativeNotLUKS) || !errors.As(err, &exit) || (exit.ExitCode() != 1 && exit.ExitCode() != 4) {
		return errors.Join(ErrNotVerified, err)
	}
	return nil
}

func (p *Provider) sanitize(ctx context.Context, plan *agentv1.DeviceActionPlan, target *targetHandle, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	if encryptedTree(target.node) || target.node.Type != "disk" {
		return nil, ErrUnsupported
	}
	if nativeSanitizeMethod(plan.GetSpec().GetSanitize().GetMethod()) {
		return p.sanitizeNVMe(ctx, plan, target, gate)
	}
	size, err := blockSize(target.file)
	if err != nil || size != plan.GetSpec().GetSanitize().GetTarget().GetSizeBytes() || size < 4096 || size%512 != 0 || size > uint64(^uint64(0)>>1) {
		return nil, errors.Join(ErrConflict, err)
	}
	method := plan.GetSpec().GetSanitize().GetMethod()
	if method == agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE && (!target.node.Rotational || !target.qualification.GetAllowOverwrite()) {
		return nil, ErrUnsupported
	}
	if method == agentv1.SanitizeMethod_SANITIZE_METHOD_DISCARD && !target.qualification.GetAllowDiscard() {
		return nil, ErrUnsupported
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	switch method {
	case agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE:
		err = overwriteRange(ctx, target.file, size)
	case agentv1.SanitizeMethod_SANITIZE_METHOD_DISCARD:
		span := [2]uint64{0, size}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, target.file.Fd(), unix.BLKDISCARD, uintptr(unsafe.Pointer(&span)))
		runtime.KeepAlive(target.file)
		if errno != 0 {
			err = errno
		} else {
			err = target.file.Sync()
		}
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := verifyZeroSamples(ctx, target.file, size); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	after := proto.CloneOf(plan.GetBefore())
	after.ObservedAt = timestamppb.New(p.clock())
	return &agentv1.DeviceActionVerification{Verified: true, After: after, Evidence: fmt.Sprintf("Qualified %s completed across exact %d-byte offline target; 257 distributed zero-read samples verified. Operational verification only, not firmware secure erase, inaccessible/remapped-sector proof, organizational validation or physical sanitization certification.", method.String(), size)}, nil
}

func (p *Provider) verifyDestruction(ctx context.Context, plan *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification) (_ *agentv1.DeviceActionVerification, err error) {
	if !result.GetVerified() || !result.GetAfter().GetRecoveryEnvironment() || !result.GetAfter().GetOffTargetJournal() {
		return nil, ErrNotVerified
	}
	target, err := p.resolve(ctx, plan.GetSpec(), false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, target.file.Close()) }()
	if nativeSanitizeMethod(plan.GetSpec().GetSanitize().GetMethod()) {
		return p.verifyNVMe(ctx, plan, result, target)
	}
	if plan.GetSpec().GetCryptoErase() != nil {
		if err := p.verifyErasedHeader(ctx, target.file, plan.GetBefore().GetLuksHeaderBytes()); err != nil {
			return nil, err
		}
	} else if err := verifyZeroSamples(ctx, target.file, target.node.Size); err != nil {
		return nil, err
	}
	return proto.CloneOf(result), nil
}
