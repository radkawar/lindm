// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/rpcreason"
)

// The unbuffered handoff serializes refresh with periodic collection and spool
// mutation. Cancellation joins the request; the bounded reply never blocks the
// inventory owner if management has already stopped.
type inventoryRefreshJob struct {
	ctx    context.Context
	status *agentv1.DeviceActionStatus
	done   chan error
}

func (r *runner) requestInventoryRefresh(ctx context.Context, status *agentv1.DeviceActionStatus) error {
	job := inventoryRefreshJob{ctx: ctx, status: status, done: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.refreshes <- job:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-job.done:
		return err
	}
}

func (r *runner) refreshInventory(ctx context.Context, status *agentv1.DeviceActionStatus) error {
	// Re-read protected state after waiting for the sole spool owner. A stale
	// wakeup or a completed action must not cause another collection.
	current, err := rpc(ctx, r.executor.GetDeviceAction, &agentv1.GetDeviceActionRequest{ActionId: status.GetActionId()})
	if err != nil {
		return err
	}
	var digest [sha256.Size]byte
	copy(digest[:], status.GetIntentSha256())
	if err := checkDeviceActionStatus(current.GetStatus(), status.GetActionId(), digest); err != nil {
		return err
	}
	if current.GetStatus().GetState() == agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED {
		return nil
	}
	if !current.GetStatus().GetRefreshInventory() || current.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_RUNNING {
		return errors.New("inventory refresh no longer running")
	}
	authority, err := synchronize(ctx, r.executor, &r.cache, r.authorityGate)
	if err != nil {
		return err
	}
	if err := r.bind(ctx, authority.connection); err != nil {
		return err
	}
	if err := r.store.Synchronize(ctx, authority.state.GetHostSequence(), authority.state.GetPackageSequence()); err != nil {
		return err
	}
	// Publication may have committed before a lost confirmation or a process
	// restart. The server retains this action's exact admitted tuple even after
	// ordinary receipt handling has removed both local pending payloads.
	if err := r.confirmInventoryPublication(ctx, authority.authorized, status.GetActionId(), digest); err == nil {
		return nil
	} else if connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcreason.Get(err) != "inventory_refresh_not_published" {
		return err
	}
	startedAt := current.GetStatus().GetStartedAt().AsTime()
	host, pendingHost, err := r.store.PendingHost(ctx)
	if err != nil {
		return err
	}
	packages, pendingPackages, err := r.store.PendingPackage(ctx)
	if err != nil {
		return err
	}
	queuedHost, queuedPackages, err := r.store.QueuedForRefresh(ctx, startedAt)
	if err != nil {
		return err
	}
	freshHost := pendingHost && !host.Observation.GetStartedAt().AsTime().Before(startedAt)
	freshPackages := pendingPackages && !packages.StartedAt.Before(startedAt)
	// A durable collection from this consumed start must remain immutable,
	// including a crash between queueing, promotion and individual receipts.
	collectFresh := !freshHost && !freshPackages && !queuedHost && !queuedPackages
	if !freshHost && !freshPackages && queuedHost && !queuedPackages {
		// A remaining host with no package slot can follow a package ACK.
		// A present but failed/stale package slot is instead an incomplete
		// routine collection, not an already-durable full refresh.
		_, incompletePackages, err := r.store.Queued(ctx)
		if err != nil {
			return err
		}
		collectFresh = incompletePackages
	}
	if collectFresh {
		if r.collectInventory == nil {
			return errors.New("inventory collector is unavailable")
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		observation, err := r.collectNativeObservation(call)
		cancel()
		if err != nil {
			return fmt.Errorf("collect refreshed inventory: %w", err)
		}
		if observation.GetHost() == nil || observation.GetPackages().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS ||
			observation.GetHost().GetStartedAt().AsTime().Before(startedAt) || observation.GetPackages().GetStartedAt().AsTime().Before(startedAt) {
			return errors.New("refresh did not collect a fresh full inventory snapshot")
		}
		// Capacity must not degrade this explicit full refresh to a failure
		// attempt. The new bytes become durable before old pending is removed.
		if err := r.store.Queue(ctx, observation); err != nil {
			return err
		}
		r.status.LastCollectionFinishedAt = observation.GetPackages().GetFinishedAt()
		queuedHost, queuedPackages = true, true
	}
	oldHost := pendingHost && !freshHost
	oldPackages := pendingPackages && !freshPackages
	// Supersession is atomic across old domains: each needs its own durable
	// fresh queued replacement. Fresh pending siblings are never replaced.
	// Without a replacement, leave old bytes alone and try the fresh survivor.
	if (!oldHost || queuedHost) && (!oldPackages || queuedPackages) &&
		(oldHost || oldPackages || !freshHost && !freshPackages && queuedHost && queuedPackages) {
		if err := r.store.SupersedeForRefresh(ctx, startedAt); err != nil {
			return err
		}
		pendingHost = pendingHost && !oldHost
		pendingPackages = pendingPackages && !oldPackages
	}
	// A missing domain can already have its server receipt: periodic upload may
	// have advanced either half after a crash. Upload only available fresh
	// evidence; never drain an unrelated prechallenge pending/queued domain.
	r.waiting = nil
	r.nextCollection = time.Now().Add(collectionInterval)
	if !pendingHost && queuedHost {
		if _, err := r.store.PromoteHost(ctx); err != nil {
			return err
		}
		freshHost = true
	}
	if !pendingPackages && queuedPackages {
		packages, err = r.store.PromotePackage(ctx)
		if err != nil {
			return err
		}
		freshPackages = true
	}
	var hostErr, packageErr error
	if freshHost {
		hostErr = flushHost(ctx, r.store, authority.authorized, r.status)
		if hostErr != nil && !continueAfter(hostErr) {
			return hostErr
		}
	}
	if freshPackages && packages.Success {
		packageErr = flushPackage(ctx, r.store, authority.authorized, r.status)
	}
	// A newer queued half may hit its routine limiter while the action's exact
	// earlier half is already admitted. Only the signed, action-bound receipt
	// can turn that partial upload into success; otherwise preserve the error.
	if err := r.confirmInventoryPublication(ctx, authority.authorized, status.GetActionId(), digest); err != nil {
		return errors.Join(hostErr, packageErr, err)
	}
	return nil
}

func (r *runner) confirmInventoryPublication(ctx context.Context, authority *authorized, actionID string, digest [sha256.Size]byte) error {
	published, err := rpc(ctx, authority.servers.device.ConfirmRefreshInventoryPublication, &devicev1.ConfirmRefreshInventoryPublicationRequest{
		SessionEpoch: authority.epoch, ActionId: actionID,
	})
	if err != nil {
		return fmt.Errorf("confirm inventory publication: %w", err)
	}
	if err := validateManagementMessage(published); err != nil {
		return err
	}
	confirmed, err := rpc(ctx, r.executor.ConfirmDeviceActionInventory, &agentv1.ConfirmDeviceActionInventoryRequest{ActionId: actionID, ReceiptEnvelope: published.GetReceiptEnvelope()})
	if err != nil {
		return err
	}
	if err := checkDeviceActionStatus(confirmed.GetStatus(), actionID, digest); err != nil {
		return err
	}
	if confirmed.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED || confirmed.GetStatus().GetVerification().GetInventorySequence() == 0 {
		return errors.New("executor did not confirm refreshed publication")
	}
	return nil
}
