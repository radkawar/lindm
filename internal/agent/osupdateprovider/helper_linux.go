// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdateprovider

import (
	"bytes"
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

// ApplyNative is called only by the fixed, separately confined root helper.
// No paths, file content or unit names come from the transported request: the
// target is recomputed from the signed plan and the protected ledger, every
// file is prepared without writes, and the single gate precedes the first
// effect. Native order: stop the timer (release), replace or remove the owned
// files, reload systemd, then start or restart the timer (reconcile).
func ApplyNative(ctx context.Context, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	config := env.Config.GetOsUpdateProvider()
	if beforeEffect == nil {
		return nil, ErrUnsupported
	}
	for _, message := range []proto.Message{config, request} {
		if err := validateMessage(message); err != nil {
			return nil, err
		}
	}
	plan := request.GetPlan()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(request.GetOwnership().GetRef(), osUpdateRef()) || !sameObserved(request.GetBefore().GetObservation(), plan.GetBefore()) || request.GetOwnership().GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrConflict
	}
	p, err := nativeContext(ctx, plan.GetBackend().GetProduct(), request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	if !proto.Equal(p.backend, plan.GetBackend()) {
		return nil, ErrConflict
	}
	fresh, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh.GetObservation(), request.GetBefore().GetObservation()) || !proto.Equal(fresh.GetOsUpdate(), request.GetBefore().GetOsUpdate()) {
		return nil, ErrConflict
	}
	target, err := p.target(ctx, desired.GetOsUpdate(), fresh, request.GetOwnership(), plan.GetOperation())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(target.GetOsUpdate(), request.GetTarget().GetOsUpdate()) || !proto.Equal(target.GetObservation().GetOsUpdate(), request.GetTarget().GetObservation().GetOsUpdate()) {
		return nil, ErrConflict
	}
	digest, err := digestMessage(target.GetOsUpdate())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, plan.GetOsUpdate().GetCandidateSha256()) {
		return nil, ErrConflict
	}
	expected, err := p.makePlan(desired, plan.GetOperation(), request.GetBefore(), target, request.GetOwnership())
	if err != nil {
		return nil, err
	}
	if !samePlan(expected, plan) {
		return nil, ErrConflict
	}
	var changes []*nativefile.Transaction
	defer func() {
		for _, tx := range changes {
			err = errors.Join(err, tx.Close())
		}
	}()
	for _, kind := range plan.GetOsUpdate().GetChangedFiles() {
		current, next := nativeFile(fresh, kind), nativeFile(target, kind)
		if current == nil || next == nil {
			return nil, ErrConflict
		}
		// Prepare needs the exact per-file native revision; it must still
		// describe the object captured in the protected before-state.
		capture, err := nativefile.Capture(resource.OSUpdateNativePath(kind), fresh.GetObservation())
		if err != nil {
			return nil, err
		}
		if !proto.Equal(capture.GetObservation().GetManagedFile(), current.GetState()) || !bytes.Equal(capture.GetManagedFileContent(), current.GetContent()) {
			return nil, ErrConflict
		}
		tx, err := nativefile.Prepare(capture, fileSnapshot(target, next))
		if err != nil {
			return nil, err
		}
		changes = append(changes, tx)
	}
	final, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh.GetObservation(), final.GetObservation()) || !proto.Equal(fresh.GetOsUpdate(), final.GetOsUpdate()) {
		return nil, ErrConflict
	}
	if err := beforeEffect(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release := plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	if release && plan.GetOsUpdate().GetTimerChange() {
		if err := p.manager.Runtime(ctx, "StopUnit"); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	for _, tx := range changes {
		if _, err := tx.Commit(ctx, func(c context.Context) error { return c.Err() }); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if len(changes) != 0 {
		if err := p.manager.Reload(ctx); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if !release && plan.GetOsUpdate().GetTimerChange() {
		method := "StartUnit"
		if fresh.GetOsUpdate().GetTimerActive() {
			method = "RestartUnit"
		}
		if err := p.manager.Runtime(ctx, method); err != nil {
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
	return result, nil
}
