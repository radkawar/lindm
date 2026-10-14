// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshprovider

import (
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

// ApplyNative recomputes the target from signed typed text and private custody.
// Both native file transactions are prepared before the one-use effect gate.
// sshd -t precedes reload; failure restores only unchanged files this invocation
// wrote. An interrupted or failed effect remains UNKNOWN in the journal even if
// rollback succeeds, and is never silently replayed.
func ApplyNative(ctx context.Context, _ resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if beforeEffect == nil {
		return nil, ErrUnsupported
	}
	if err := validateMessage(request); err != nil {
		return nil, err
	}
	plan := request.GetPlan()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(request.GetOwnership().GetRef(), sshRef()) || !sameObserved(request.GetBefore().GetObservation(), plan.GetBefore()) || request.GetOwnership().GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrConflict
	}
	p, err := nativeContext(ctx, plan.GetBackend().GetProduct(), request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	return p.applyNative(ctx, request, desired, beforeEffect)
}

func (p *Provider) applyNative(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, desired *resourcev1.ResourceDesiredState, gate func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	plan := request.GetPlan()
	if !proto.Equal(p.backend, plan.GetBackend()) {
		return nil, ErrConflict
	}
	fresh, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh.GetObservation(), request.GetBefore().GetObservation()) || !proto.Equal(fresh.GetSshServer(), request.GetBefore().GetSshServer()) {
		return nil, ErrConflict
	}
	target, err := p.target(ctx, desired.GetSshServer(), fresh, request.GetOwnership(), plan.GetOperation())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(target.GetSshServer(), request.GetTarget().GetSshServer()) {
		return nil, ErrConflict
	}
	digest, err := digestMessage(target.GetSshServer())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, plan.GetSshServer().GetCandidateGraphSha256()) {
		return nil, ErrConflict
	}
	expected, err := p.makePlan(desired, plan.GetOperation(), request.GetBefore(), target, request.GetOwnership())
	if err != nil {
		return nil, err
	}
	if !samePlan(expected, plan) {
		return nil, ErrConflict
	}
	// Validate the sole rendered directive before any effect. The real
	// aggregate is checked again after replacement and before reload.
	if _, err := p.run(ctx, "/usr/sbin/sshd", "-t", "-f", sshConfigPath, "-o", "Banner="+resource.SSHBannerPath); err != nil {
		return nil, configInvalid(err)
	}
	changes, err := p.prepareChanges(fresh, target, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, changes.close()) }()
	final, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh.GetObservation(), final.GetObservation()) {
		return nil, ErrConflict
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.commitChanges(ctx, plan, target, &changes)
}

type bannerChange struct {
	tx            *nativefile.Transaction
	before, after *agentv1.ResourceOwnershipSnapshot
}
type bannerChanges struct {
	files                    [2]bannerChange
	count                    int
	mutated, reloadAttempted bool
}

func (p *Provider) prepareChanges(fresh, target *agentv1.ResourceOwnershipSnapshot, operation resourcev1.ResourceOperation) (changes bannerChanges, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, changes.close())
		}
	}()
	currentFiles := [2]*agentv1.SSHNativeFileSnapshot{fresh.GetSshServer().GetBanner(), fresh.GetSshServer().GetDirective()}
	nextFiles := [2]*agentv1.SSHNativeFileSnapshot{target.GetSshServer().GetBanner(), target.GetSshServer().GetDirective()}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		currentFiles[0], currentFiles[1] = currentFiles[1], currentFiles[0]
		nextFiles[0], nextFiles[1] = nextFiles[1], nextFiles[0]
	}
	for i, current := range currentFiles {
		next := nextFiles[i]
		if sameFileImage(current, next) {
			continue
		}
		capture, err := p.capture(current.GetState().GetPath(), fresh.GetObservation())
		if err != nil {
			return changes, err
		}
		if !proto.Equal(capture.GetObservation().GetManagedFile(), current.GetState()) || !bytes.Equal(capture.GetManagedFileContent(), current.GetContent()) {
			return changes, ErrConflict
		}
		tx, err := nativefile.Prepare(capture, fileSnapshot(target, next))
		if err != nil {
			return changes, err
		}
		changes.files[changes.count] = bannerChange{tx: tx, before: capture}
		changes.count++
	}
	return changes, nil
}

func (c *bannerChanges) close() error {
	var err error
	for i := range c.count {
		err = errors.Join(err, c.files[i].tx.Close())
	}
	return err
}

func (p *Provider) commitChanges(ctx context.Context, plan *resourcev1.ResourcePlan, target *agentv1.ResourceOwnershipSnapshot, changes *bannerChanges) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	defer func() {
		if err != nil && changes.mutated {
			restore, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			err = errors.Join(err, p.rollbackChanges(restore, changes))
		}
	}()
	for i := range changes.count {
		changes.mutated = true
		after, commitErr := changes.files[i].tx.Commit(ctx, func(c context.Context) error { return c.Err() })
		changes.files[i].after = after
		if commitErr != nil {
			return nil, errors.Join(ErrOutcomeUnknown, commitErr)
		}
	}
	if _, err := p.run(ctx, "/usr/sbin/sshd", "-t", "-f", sshConfigPath); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if plan.GetSshServer().GetReload() == resourcev1.ReloadMechanism_RELOAD_MECHANISM_SYSTEMD_RELOAD {
		changes.reloadAttempted = true
		if _, err := p.run(ctx, "/usr/bin/systemctl", "reload", p.unit); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	result, err = p.snapshot(ctx)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !targetMatches(result, target) {
		return nil, ErrOutcomeUnknown
	}
	proof, err := verification(plan, result, target)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !proof.GetSshServer().GetConverged() {
		return nil, ErrOutcomeUnknown
	}
	return result, nil
}

func (p *Provider) rollbackChanges(ctx context.Context, changes *bannerChanges) error {
	for i := changes.count - 1; i >= 0; i-- {
		c := &changes.files[i]
		if c.after == nil {
			continue
		}
		undo, err := nativefile.Prepare(c.after, c.before)
		if err != nil {
			return err
		}
		_, err = undo.Commit(ctx, func(c context.Context) error { return c.Err() })
		err = errors.Join(err, undo.Close())
		if err != nil {
			return err
		}
	}
	if changes.reloadAttempted {
		if _, err := p.run(ctx, "/usr/sbin/sshd", "-t", "-f", sshConfigPath); err != nil {
			return err
		}
		_, err := p.run(ctx, "/usr/bin/systemctl", "reload", p.unit)
		return err
	}
	return nil
}
