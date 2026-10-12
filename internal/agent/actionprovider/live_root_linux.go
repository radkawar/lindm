//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func LiveRootHeaderErase(spec *agentv1.DeviceActionSpec) bool {
	return spec.GetCryptoErase().GetMode() == agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER
}

// Every locally configured encrypted volume is mandatory, even if it was only
// configured for escrow/TPM. Such a volume must also be explicitly qualified for
// erasure; silently skipping it would not implement a whole-device crypto erase.
// The server independently requires its complete escrow catalog in this spec.
func (p *Provider) liveRootScope(spec *agentv1.DeviceActionSpec) error {
	if !LiveRootHeaderErase(spec) || !p.config.GetAllowLiveRootCryptoErase() || spec.GetCryptoErase().GetTarget() != nil {
		return ErrUnsupported
	}
	targets := spec.GetCryptoErase().GetTargets()
	if len(targets) == 0 || len(targets) > 8 {
		return ErrUnsupported
	}
	count := 0
	for _, qualified := range p.config.GetTargets() {
		if qualified.GetTarget().GetLuksUuid() == "" {
			continue
		}
		count++
		found := 0
		for _, target := range targets {
			if proto.Equal(target, qualified.GetTarget()) {
				found++
			}
		}
		if found != 1 || !qualified.GetAllowCryptoErase() || qualified.GetQualificationId() == "" {
			return fmt.Errorf("%w: complete_qualified_encrypted_scope_required", ErrConflict)
		}
	}
	if count != len(targets) {
		return ErrConflict
	}
	for index, target := range targets {
		if target.GetLuksUuid() == "" || target.GetIdentityBasis() == agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_UNSPECIFIED {
			return ErrConflict
		}
		for _, previous := range targets[:index] {
			if previous.GetLuksUuid() == target.GetLuksUuid() {
				return ErrConflict
			}
		}
	}
	return nil
}

func closeTargets(targets []*targetHandle) error {
	var err error
	for _, target := range targets {
		err = errors.Join(err, target.file.Close())
	}
	return err
}

func (p *Provider) liveRootPreflight(ctx context.Context, spec *agentv1.DeviceActionSpec, writable bool) (_ *agentv1.DeviceActionObservation, handles []*targetHandle, err error) {
	if err := p.liveRootScope(spec); err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeTargets(handles))
			handles = nil
		}
	}()
	observation := &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true, Encrypted: true}
	for _, target := range spec.GetCryptoErase().GetTargets() {
		// Resolve the exact stable native identity without the offline exclusive
		// open. This exception never reaches sanitize or whole-disk overwrite.
		lookup := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: target}}}
		handle, e := p.resolve(ctx, lookup, writable)
		if e != nil {
			return nil, handles, e
		}
		handles = append(handles, handle)
		if handle.node.Type != "disk" && handle.node.Type != "part" {
			return nil, handles, ErrUnsupported
		}
		size, e := blockSize(handle.file)
		if e != nil || size != target.GetSizeBytes() {
			return nil, handles, errors.Join(ErrConflict, e)
		}
		id, e := p.crypt(ctx, handle.file, []string{"luksUUID", descriptor(0)})
		if e != nil || strings.TrimSpace(string(id)) != target.GetLuksUuid() {
			return nil, handles, errors.Join(ErrConflict, e)
		}
		metadata, digest, e := p.metadata(ctx, handle.file)
		if e != nil {
			return nil, handles, e
		}
		extent, e := luksHeaderExtent(handle.file, metadata, size)
		if e != nil {
			return nil, handles, e
		}
		observation.CryptoEraseTargets = append(observation.CryptoEraseTargets, &agentv1.CryptoEraseTargetPlan{Target: proto.CloneOf(target), MetadataSha256: digest, LuksHeaderBytes: extent})
	}
	root, mappingDigest, e := p.rootMapping(ctx, handles)
	if e != nil {
		return nil, handles, e
	}
	for index, target := range observation.CryptoEraseTargets {
		target.RootBacking = index == root
		target.RootMappingSha256 = bytes.Clone(mappingDigest)
	}
	return observation, handles, nil
}

func (p *Provider) observeLiveRoot(ctx context.Context, spec *agentv1.DeviceActionSpec) (*agentv1.DeviceActionObservation, error) {
	before, handles, err := p.liveRootPreflight(ctx, spec, false)
	return before, errors.Join(err, closeTargets(handles))
}

func sameEraseTargets(a, b []*agentv1.CryptoEraseTargetPlan) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for index := range a {
		if !proto.Equal(a[index], b[index]) {
			return false
		}
	}
	return true
}

func (p *Provider) applyLiveRoot(ctx context.Context, plan *agentv1.DeviceActionPlan, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	fresh, handles, err := p.liveRootPreflight(ctx, plan.GetSpec(), true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeTargets(handles)) }()
	if !sameEraseTargets(plan.GetCryptoEraseTargets(), fresh.GetCryptoEraseTargets()) || !sameEraseTargets(plan.GetBefore().GetCryptoEraseTargets(), fresh.GetCryptoEraseTargets()) {
		return nil, ErrConflict
	}
	// Reserve and fault in both overwrite and raw-read buffers before authority
	// consumption. No post-effect credential or journal load is necessary.
	memory, err := lockedMemory(2 << 20)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, releaseMemory(memory)) }()
	state, err := p.run(ctx, nativeRequest{command: systemctl, args: []string{"show", "--property=ActiveState", "--value", LiveRootPoweroffService}})
	if err != nil || strings.TrimSpace(string(state)) != "inactive" {
		return nil, errors.Join(ErrConflict, err)
	}
	return p.executeLiveRoot(ctx, plan, handles, memory, gate)
}

func (p *Provider) executeLiveRoot(ctx context.Context, plan *agentv1.DeviceActionPlan, targets []*targetHandle, memory []byte, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	if len(targets) != len(plan.GetCryptoEraseTargets()) || len(targets) == 0 || len(memory) != 2<<20 || p.flushHeader == nil {
		return nil, ErrConflict
	}
	after := proto.CloneOf(plan.GetBefore())
	after.CryptoEraseTargets = nil // destroyed metadata is not a current observation
	result := &agentv1.DeviceActionVerification{After: after, Evidence: "Live-root action consumed, but independent poweroff readiness was not established. No header effect was attempted. Outcome remains UNKNOWN; escrow and external header backups are not destroyed."}
	for _, target := range plan.GetCryptoEraseTargets() {
		result.CryptoEraseResults = append(result.CryptoEraseResults, &agentv1.CryptoEraseTargetResult{Target: proto.CloneOf(target.GetTarget()), HeaderBytes: target.GetLuksHeaderBytes()})
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	// Type=notify only returns after the independent helper has armed its fixed
	// timer. The service cannot be canceled by losing this RPC/process/cgroup.
	if _, err := p.run(ctx, nativeRequest{command: systemctl, args: []string{"start", LiveRootPoweroffService}}); err != nil {
		return result, errors.Join(ErrOutcomeUnknown, err)
	}
	result.Evidence = "Independent forced-poweroff deadline armed. Live-root header destruction or verification is incomplete: inspect each approved volume's proof flags. Active mappings persist only until forced poweroff. Outcome remains UNKNOWN; escrow and external header backups are not destroyed."
	// Network loss, grant expiry and executor shutdown cannot revoke a consumed
	// effect. The independent helper still powers off if this worker is killed.
	work, cancel := context.WithTimeout(context.Background(), liveRootEffectTimeout)
	defer cancel()
	// Closing an erased LUKS device makes udev re-probe it: its LUKS-UUID
	// device unit vanishes, systemd stops the bound systemd-cryptsetup unit and
	// cascades through the local file systems (Tumbleweed unmounted its /home,
	// /opt, /root, /srv and /usr/local subvolumes and stopped the agent and this
	// executor before any result was attested). With the forced poweroff
	// armed, udev processes no further events until it powers off. A failure
	// still erases every approved target; the result just stays UNKNOWN.
	_, failures := p.run(work, nativeRequest{command: udevadm, args: []string{"control", "--stop-exec-queue"}})
	for index, target := range targets {
		proof := result.CryptoEraseResults[index]
		_, nativeErr := p.crypt(work, target.file, []string{"luksErase", "--batch-mode", descriptor(0)})
		proof.NativeLuksErase = nativeErr == nil
		// Still destroy this entire header and attempt every other approved
		// target after a partial native failure. Never retry authority/effects.
		wipeErr := overwriteHeader(work, target.file, proof.HeaderBytes, memory[:1<<20])
		if wipeErr == nil {
			wipeErr = p.flushHeader(target.file)
		}
		verifyErr := verifyHeaderBytes(work, target.file, proof.HeaderBytes, memory[1<<20:])
		proof.RawZeroVerified = verifyErr == nil
		var dumpErr error
		if verifyErr == nil && wipeErr == nil {
			dumpErr = p.verifyNotLUKS(work, target.file)
			proof.MetadataAbsent = dumpErr == nil
		}
		failures = errors.Join(failures, nativeErr, wipeErr, verifyErr, dumpErr)
		if proof.NativeLuksErase && proof.RawZeroVerified && proof.MetadataAbsent {
			proof.Evidence = "native luksErase; full header/keyslot zero-read; native luksDump rejected metadata"
		}
	}
	after.ObservedAt = timestamppb.New(p.clock())
	if failures != nil {
		return result, errors.Join(ErrOutcomeUnknown, failures)
	}
	after.Encrypted = false
	result.Verified = true
	result.Evidence = "Live-root local crypto erase: native luksErase plus complete LUKS2 primary/secondary metadata and keyslot extent overwrite on every approved volume. Raw bytes verified and independent native luksDump rejects metadata. Active dm keys persist until independent forced poweroff; escrow and external header backups are not destroyed. Missing attestation remains UNKNOWN."
	return result, nil
}

func overwriteHeader(ctx context.Context, file *os.File, length uint64, zeros []byte) error {
	if length == 0 || length > maximumHeaderBytes || len(zeros) == 0 {
		return ErrConflict
	}
	clear(zeros)
	for offset := uint64(0); offset < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := min(uint64(len(zeros)), length-offset)
		n, err := file.WriteAt(zeros[:count], int64(offset))
		if err != nil {
			return err
		}
		if n != int(count) {
			return io.ErrShortWrite
		}
		offset += count
	}
	return file.Sync()
}

func flushBlockHeader(file *os.File) error {
	// Drop block-device cache before raw verification; this does not flush the
	// mounted decrypted root filesystem or mutate its journal.
	return unix.IoctlSetInt(int(file.Fd()), unix.BLKFLSBUF, 0)
}

func verifyHeaderBytes(ctx context.Context, file *os.File, length uint64, buffer []byte) error {
	if length == 0 || length > maximumHeaderBytes || len(buffer) == 0 {
		return ErrConflict
	}
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
