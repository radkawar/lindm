package transport

import (
	"context"
	"errors"
	"fmt"
	"math"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/agent/spool"
	"lindm/internal/rpcreason"
)

func flush(ctx context.Context, store *spool.Store, authority *authorized, status *agentv1.TransportStatus) error {
	hostErr := flushHost(ctx, store, authority, status)
	if hostErr != nil && !continueAfter(hostErr) {
		return fmt.Errorf("upload host observation: %w", hostErr)
	}
	packageErr := flushPackage(ctx, store, authority, status)
	return errors.Join(hostErr, packageErr)
}

func flushHost(ctx context.Context, store *spool.Store, authority *authorized, status *agentv1.TransportStatus) error {
	pending, ok, err := store.PendingHost(ctx)
	if err != nil {
		return err
	}
	if !ok {
		pending, err = store.PromoteHost(ctx)
		if errors.Is(err, spool.ErrEmpty) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	response, err := rpc(ctx, authority.servers.device.ReportHostObservation, &devicev1.ReportHostObservationRequest{EnrollmentGeneration: authority.connection.GetEnrollmentGeneration(), SessionEpoch: authority.epoch, Sequence: pending.Sequence, Observation: pending.Observation})
	if err != nil {
		return err
	}
	if err := recordContact(status, response.GetServerTime()); err != nil {
		return err
	}
	if err := store.AcknowledgeHost(ctx, pending.Sequence, response.GetAcceptedSequence()); err != nil {
		return err
	}
	status.HostHighWater = max(status.GetHostHighWater(), response.GetAcceptedSequence())
	return nil
}

func flushPackage(ctx context.Context, store *spool.Store, authority *authorized, status *agentv1.TransportStatus) error {
	pending, ok, err := store.PendingPackage(ctx)
	if err != nil {
		return err
	}
	if !ok {
		pending, err = store.PromotePackage(ctx)
		if errors.Is(err, spool.ErrEmpty) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	if !pending.Success {
		response, err := rpc(ctx, authority.servers.device.ReportPackageAttempt, &devicev1.ReportPackageAttemptRequest{EnrollmentGeneration: authority.connection.GetEnrollmentGeneration(), SessionEpoch: authority.epoch, Sequence: pending.Sequence, StartedAt: timestamppb.New(pending.StartedAt), FinishedAt: timestamppb.New(pending.FinishedAt), Status: pending.Status, Backend: pending.Backend})
		if err != nil {
			return err
		}
		if err := recordContact(status, response.GetServerTime()); err != nil {
			return err
		}
		return finishPackage(ctx, store, pending.Sequence, response.GetAcceptedSequence(), spool.TerminalAdmitted, status)
	}
	begun, err := rpc(ctx, authority.servers.device.BeginPackageSnapshot, &devicev1.BeginPackageSnapshotRequest{EnrollmentGeneration: authority.connection.GetEnrollmentGeneration(), SessionEpoch: authority.epoch, Manifest: pending.Manifest})
	if err != nil {
		return expireIfRejected(ctx, store, authority, pending.Sequence, err, status)
	}
	if err := recordContact(status, begun.GetServerTime()); err != nil {
		return err
	}
	if begun.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING {
		return finishSnapshotState(ctx, store, pending.Sequence, begun.GetPackageSequence(), begun.GetState(), status)
	}
	if !pending.BeginAccepted {
		if err := store.MarkBegin(ctx); err != nil {
			return err
		}
	}
	var accepted [spool.MaxBatches]bool
	for _, index := range pending.AcceptedBatches {
		if index >= uint32(pending.BatchCount) || index >= spool.MaxBatches {
			return errors.New("invalid durable batch acknowledgement")
		}
		accepted[index] = true
	}
	for index := 0; index < pending.BatchCount; index++ {
		if accepted[index] {
			continue
		}
		batch, err := store.Batch(ctx, uint32(index))
		if err != nil {
			return err
		}
		put, err := rpc(ctx, authority.servers.device.PutPackageBatch, &devicev1.PutPackageBatchRequest{EnrollmentGeneration: authority.connection.GetEnrollmentGeneration(), SessionEpoch: authority.epoch, SnapshotId: pending.Manifest.GetSnapshotId(), BatchIndex: uint32(index), Batch: batch})
		if err != nil {
			return expireIfRejected(ctx, store, authority, pending.Sequence, err, status)
		}
		if err := recordContact(status, put.GetServerTime()); err != nil {
			return err
		}
		if put.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING {
			// Put has no counter receipt. Query high-water, but retain this exact
			// terminal state as the publication/expiry evidence.
			state, err := syncState(ctx, authority, status)
			if err != nil {
				return err
			}
			return finishSnapshotState(ctx, store, pending.Sequence, state.GetPackageSequence(), put.GetState(), status)
		}
		if err := store.MarkBatchAccepted(ctx, uint32(index)); err != nil {
			return err
		}
	}
	committed, err := rpc(ctx, authority.servers.device.CommitPackageSnapshot, &devicev1.CommitPackageSnapshotRequest{EnrollmentGeneration: authority.connection.GetEnrollmentGeneration(), SessionEpoch: authority.epoch, Manifest: pending.Manifest})
	if err != nil {
		return expireIfRejected(ctx, store, authority, pending.Sequence, err, status)
	}
	if err := recordContact(status, committed.GetServerTime()); err != nil {
		return err
	}
	return finishSnapshotState(ctx, store, pending.Sequence, committed.GetPackageSequence(), committed.GetState(), status)
}

func finishSnapshotState(ctx context.Context, store *spool.Store, sequence, high uint64, state inventoryv1.SnapshotState, status *agentv1.TransportStatus) error {
	var terminal spool.Terminal
	switch state {
	case inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED:
		terminal = spool.TerminalAdmitted
	case inventoryv1.SnapshotState_SNAPSHOT_STATE_SUPERSEDED:
		terminal = spool.TerminalSuperseded
	case inventoryv1.SnapshotState_SNAPSHOT_STATE_EXPIRED:
		terminal = spool.TerminalExpired
	default:
		return errors.New("server returned a nonterminal snapshot receipt")
	}
	return finishPackage(ctx, store, sequence, high, terminal, status)
}

func finishPackage(ctx context.Context, store *spool.Store, sequence, high uint64, terminal spool.Terminal, status *agentv1.TransportStatus) error {
	if err := store.FinishPackage(ctx, sequence, high, terminal); err != nil {
		return err
	}
	status.PackageHighWater = max(status.GetPackageHighWater(), high)
	return nil
}

func expireIfRejected(ctx context.Context, store *spool.Store, authority *authorized, sequence uint64, uploadErr error, status *agentv1.TransportStatus) error {
	if connect.CodeOf(uploadErr) != connect.CodeFailedPrecondition || rpcreason.Get(uploadErr) != "snapshot_expired" {
		return uploadErr
	}
	state, err := syncState(ctx, authority, status)
	if err != nil {
		return errors.Join(uploadErr, err)
	}
	// An unsent expired manifest may exceed server high-water. Discard only
	// this exact expired attempt; its locally allocated sequence remains spent.
	return finishPackage(ctx, store, sequence, state.GetPackageSequence(), spool.TerminalExpired, status)
}

func syncState(ctx context.Context, authority *authorized, status *agentv1.TransportStatus) (*devicev1.GetSyncStateResponse, error) {
	state, err := rpc(ctx, authority.servers.device.GetSyncState, &devicev1.GetSyncStateRequest{SessionEpoch: authority.epoch})
	if err != nil {
		return nil, err
	}
	if state.GetSessionEpoch() != authority.epoch || state.GetHostSequence() > math.MaxInt64 || state.GetPackageSequence() > math.MaxInt64 {
		return nil, errors.New("invalid server synchronization receipt")
	}
	if err := recordContact(status, state.GetServerTime()); err != nil {
		return nil, err
	}
	status.HostHighWater = max(status.GetHostHighWater(), state.GetHostSequence())
	status.PackageHighWater = max(status.GetPackageHighWater(), state.GetPackageSequence())
	return state, nil
}

func recordContact(status *agentv1.TransportStatus, serverTime *timestamppb.Timestamp) error {
	if serverTime == nil || !serverTime.IsValid() {
		return errors.New("server receipt has no valid contact time")
	}
	status.LastServerContactAt = serverTime
	return nil
}

func continueAfter(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, spool.ErrNeedsSync) {
		return false
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return false
	case connect.CodeFailedPrecondition:
		return rpcreason.Get(err) == "open_upload"
	case connect.CodeResourceExhausted:
		// Server-wide admission backpressure: stop this flush and retry on
		// the next cycle instead of offering more uploads to a saturated
		// server. Per-device deferrals still let other evidence proceed.
		return rpcreason.Get(err) != "admission_rejected"
	default:
		return true
	}
}
