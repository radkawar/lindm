//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// PrepareRecovery is read-only preflight on the original boot, not permission to
// erase a mounted target. Only an explicitly signed recovery handoff spec and
// root-local opt-in may use it. Runtime authenticates the recovery image and
// establishes protected filesystem or TPM/server custody before staging boot.
// Ordinary Observe/Apply retain their separate offline effect safeguards.
func (p *Provider) PrepareRecovery(ctx context.Context, spec *agentv1.DeviceActionSpec) (_ *agentv1.DeviceActionPlan, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	target, err := p.recoveryPreflightTarget(ctx, spec)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, target.file.Close()) }()
	offTarget, err := p.recoveryOffTargetState(target.node)
	if err != nil {
		return nil, err
	}
	before := &agentv1.DeviceActionObservation{
		ObservedAt: timestamppb.New(p.clock()), Supported: true,
		Target:              proto.CloneOf(spec.GetSanitize().GetTarget()),
		RecoveryEnvironment: false, OffTargetJournal: offTarget,
	}
	if nativeSanitizeMethod(spec.GetSanitize().GetMethod()) {
		before.NvmeSanitize, err = p.observeNVMe(ctx, spec, target)
		if err != nil {
			return nil, err
		}
	}
	return p.Plan(ctx, spec, before)
}

// RecoveryTargetDevices re-resolves native media identities immediately before
// boot staging. Returned paths originate only from the pinned local native
// resolver; there is no remotely supplied path or executable in the contract.
func (p *Provider) RecoveryTargetDevices(ctx context.Context, plan *agentv1.DeviceActionPlan) (_ []string, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := p.validatePlan(plan); err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBefore().GetTarget(), plan.GetSpec().GetSanitize().GetTarget()) {
		return nil, ErrConflict
	}
	target, err := p.recoveryPreflightTarget(ctx, plan.GetSpec())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, target.file.Close()) }()
	return []string{target.node.Path}, nil
}

func (p *Provider) recoveryPreflightTarget(ctx context.Context, spec *agentv1.DeviceActionSpec) (_ *targetHandle, err error) {
	if !p.config.GetAllowRecoveryHandoff() {
		return nil, fmt.Errorf("%w: recovery_handoff_not_enabled", ErrUnsupported)
	}
	if err := p.validate.Validate(spec); err != nil {
		return nil, err
	}
	action := spec.GetSanitize()
	if action == nil || action.GetRecovery() == nil {
		return nil, fmt.Errorf("%w: signed_recovery_handoff_required", ErrUnsupported)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(action.GetTarget())
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	if !bytes.Equal(digest[:], action.GetRecovery().GetMediaSha256()) {
		return nil, ErrConflict
	}
	qualification, err := p.qualified(action.GetTarget())
	if err != nil {
		return nil, err
	}
	if qualification.GetQualificationId() == "" {
		return nil, ErrUnsupported
	}
	// This private lookup selects identity only. It is never validated as an
	// action, journaled, signed, or passed to Apply, and it opens no writable fd.
	lookup := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: action.GetTarget()}}}
	target, err := p.resolve(ctx, lookup, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, target.file.Close())
		}
	}()
	if err := qualifyRecoveryTarget(action, qualification, target.node); err != nil {
		return nil, err
	}
	return target, nil
}

func qualifyRecoveryTarget(action *agentv1.SanitizeAction, qualification *agentv1.QualifiedActionTarget, node blockNode) error {
	if node.Type != "disk" || encryptedTree(node) {
		return fmt.Errorf("%w: recovery_requires_whole_unencrypted_media", ErrUnsupported)
	}
	switch action.GetMethod() {
	case agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE:
		if !qualification.GetAllowOverwrite() || !node.Rotational {
			return ErrUnsupported
		}
	case agentv1.SanitizeMethod_SANITIZE_METHOD_DISCARD:
		if !qualification.GetAllowDiscard() {
			return ErrUnsupported
		}
	default:
		if !nativeSanitizeMethod(action.GetMethod()) || !nativeSanitizeAllowed(qualification, action.GetMethod()) {
			return ErrUnsupported
		}
	}
	return nil
}

// A false result does not waive custody: it requires the separate TPM NV/server
// path before boot staging. Never claim RAM, overlay, loop-backed or a target's
// own filesystem is durable off-target journal storage.
func (p *Provider) recoveryOffTargetState(target blockNode) (bool, error) {
	path := p.config.GetProtectedStateDirectory()
	if path == "" {
		return false, nil
	}
	if err := privateStateDirectory(path); err != nil {
		return false, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		return false, err
	}
	if filesystem.Type == unix.TMPFS_MAGIC || filesystem.Type == unix.RAMFS_MAGIC || filesystem.Type == unix.OVERLAYFS_SUPER_MAGIC {
		return false, nil
	}
	var state unix.Stat_t
	if err := unix.Stat(path, &state); err != nil {
		return false, err
	}
	if unix.Major(state.Dev) == 0 || unix.Major(state.Dev) == 7 || treeContainsDevice(target, state.Dev) {
		return false, nil
	}
	if _, err := os.Stat(fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(state.Dev), unix.Minor(state.Dev))); err != nil {
		return false, err
	}
	return true, nil
}

func treeContainsDevice(node blockNode, device uint64) bool {
	identity := fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device))
	if node.Device == identity {
		return true
	}
	for _, child := range node.Children {
		if treeContainsDevice(child, device) {
			return true
		}
	}
	return false
}
