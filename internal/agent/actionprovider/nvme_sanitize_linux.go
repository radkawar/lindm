//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func (p *Provider) sanitizeNVMe(ctx context.Context, plan *agentv1.DeviceActionPlan, target *targetHandle, gate func(context.Context) error) (*agentv1.DeviceActionVerification, error) {
	action := plan.GetSpec().GetSanitize()
	if !nativeSanitizeAllowed(target.qualification, action.GetMethod()) || encryptedTree(target.node) || target.node.Type != "disk" || !p.config.GetRecoveryEnvironment() || !plan.GetBefore().GetOffTargetJournal() || !plan.GetBefore().GetRecoveryEnvironment() || gate == nil {
		return nil, ErrUnsupported
	}
	size, err := blockSize(target.file)
	if err != nil || size != action.GetTarget().GetSizeBytes() {
		return nil, errors.Join(ErrConflict, err)
	}
	fresh, err := p.observeNVMe(ctx, plan.GetSpec(), target)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(fresh, plan.GetBefore().GetNvmeSanitize()) {
		return nil, ErrConflict
	}
	namespaceData, err := p.nvmeAdmin(ctx, target.file, 6, fresh.GetScope().GetNamespaceId(), 0, nvmeIdentifyBytes)
	if err != nil {
		return nil, err
	}
	namespace, err := parseNVMeNamespace(namespaceData)
	if err != nil || !bytes.Equal(namespace.digest[:], fresh.GetIdentifyNamespaceSha256()) {
		return nil, errors.Join(ErrConflict, err)
	}
	if err := invalidateNVMeSamples(target.file); err != nil {
		return nil, err
	}
	beforeSamples, err := readNVMeSamples(ctx, target.file, size, nil)
	if err != nil {
		return nil, err
	}
	// Rebind the controller inventory immediately before the durable authority
	// gate, after potentially slow sampling. Offline exclusive ownership remains
	// held throughout; no additional namespace is ever approved implicitly.
	fresh, err = p.observeNVMe(ctx, plan.GetSpec(), target)
	if err != nil || !proto.Equal(fresh, plan.GetBefore().GetNvmeSanitize()) {
		return nil, errors.Join(ErrConflict, err)
	}
	result := &agentv1.DeviceActionVerification{
		After:        proto.CloneOf(plan.GetBefore()),
		NvmeSanitize: &agentv1.NVMeSanitizeVerification{ObservedScope: fresh},
		Evidence:     "Native command has no verified completion; a consumed/interrupted operation must not be restarted.",
	}
	if err := p.startNVMeCommand(ctx, target.file, action.GetMethod(), fresh.GetScope().GetNamespaceId(), namespace.lbaf, gate, result.NvmeSanitize); err != nil {
		if errors.Is(err, ErrOutcomeUnknown) {
			return result, err
		}
		return nil, err
	}
	// Both synchronous format completion and sanitize's retained native status
	// must be corroborated by independently reread identity/layout and media.
	afterScope, err := p.observeNVMe(ctx, plan.GetSpec(), target)
	if err != nil || !proto.Equal(afterScope, fresh) {
		return result, errors.Join(ErrOutcomeUnknown, ErrNotVerified, err)
	}
	if err := invalidateNVMeSamples(target.file); err != nil {
		return result, errors.Join(ErrOutcomeUnknown, err)
	}
	samples, err := readNVMeSamples(ctx, target.file, size, &beforeSamples)
	result.NvmeSanitize.SamplesRead = samples.read
	if err != nil {
		return result, errors.Join(ErrOutcomeUnknown, err)
	}
	result.NvmeSanitize.SampleSha256 = samples.digest[:]
	result.After.ObservedAt = timestamppb.New(p.clock())
	result.After.NvmeSanitize = afterScope
	result.Verified = true
	result.Evidence = fmt.Sprintf("Qualified %s native completion and unchanged exact controller/namespace scope read back; 257 cache-invalidated distributed samples read and every previously nonzero sample changed. Controller-reported erase plus operational sampling only, not inaccessible/remapped-cell proof or physical sanitization certification. No fallback method was substituted.", action.GetMethod())
	return result, nil
}

// The executor's gate durably consumes the exact signed plan before this sole
// command submission. Any loss after consumption remains unknown in that journal
// and its startup path never re-enters Apply. The retained sanitize status is
// polled read-only; we never issue sanitize-exit, retry, reset or resume commands.
func (p *Provider) startNVMeCommand(ctx context.Context, file *os.File, method agentv1.SanitizeMethod, nsid uint32, lbaf byte, gate func(context.Context) error, result *agentv1.NVMeSanitizeVerification) error {
	if !nativeSanitizeMethod(method) || nsid == 0 || nsid == ^uint32(0) || lbaf > 15 || gate == nil || result == nil {
		return ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := gate(ctx); err != nil {
		return err
	}
	command := nvmeSanitizeCommand(method)
	if command == 0 {
		ses := uint32(1)
		if method == agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_CRYPTO_ERASE {
			ses = 2
		}
		if _, err := p.nvmeAdmin(ctx, file, 0x80, nsid, uint32(lbaf)|ses<<9, 0); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		// Format has no durable completion log. An interrupted/missing CQE is
		// unknown even if a subsequent Identify reports no operation in progress.
		result.NativeCommandCompleted = true
		return nil
	}
	if _, err := p.nvmeAdmin(ctx, file, 0x84, 0, command, 0); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		status, err := p.nvmeStatus(ctx, file)
		if err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		result.SanitizeStatus = uint32(status.status)
		result.SanitizeProgress = uint32(status.progress)
		result.SanitizeCommandDword10 = status.command
		if status.complete(command) {
			result.NativeCommandCompleted = true
			return nil
		}
		if status.status&7 != 2 || status.command != command {
			return errors.Join(ErrOutcomeUnknown, ErrNotVerified)
		}
		select {
		case <-ctx.Done():
			return errors.Join(ErrOutcomeUnknown, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (p *Provider) verifyNVMe(ctx context.Context, plan *agentv1.DeviceActionPlan, result *agentv1.DeviceActionVerification, target *targetHandle) (*agentv1.DeviceActionVerification, error) {
	native := result.GetNvmeSanitize()
	if !result.GetVerified() || !native.GetNativeCommandCompleted() || native.GetSamplesRead() != nvmeSampleCount || len(native.GetSampleSha256()) != 32 || !proto.Equal(native.GetObservedScope(), plan.GetBefore().GetNvmeSanitize()) {
		return nil, ErrNotVerified
	}
	fresh, err := p.observeNVMe(ctx, plan.GetSpec(), target)
	if err != nil || !proto.Equal(fresh, native.GetObservedScope()) {
		return nil, errors.Join(ErrNotVerified, err)
	}
	if command := nvmeSanitizeCommand(plan.GetSpec().GetSanitize().GetMethod()); command != 0 {
		status, err := p.nvmeStatus(ctx, target.file)
		if err != nil || !status.complete(command) || uint32(status.status) != native.GetSanitizeStatus() || uint32(status.progress) != native.GetSanitizeProgress() || status.command != native.GetSanitizeCommandDword10() {
			return nil, errors.Join(ErrNotVerified, err)
		}
	}
	if err := invalidateNVMeSamples(target.file); err != nil {
		return nil, err
	}
	samples, err := readNVMeSamples(ctx, target.file, target.node.Size, nil)
	if err != nil || !bytes.Equal(samples.digest[:], native.GetSampleSha256()) {
		return nil, errors.Join(ErrNotVerified, err)
	}
	return proto.CloneOf(result), nil
}
