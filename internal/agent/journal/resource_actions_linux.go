package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
)

const (
	maximumResourceActionBytes      = 1 << 20
	maximumResourceActions          = 65536
	maximumResourceActionTotalBytes = 256 << 20
)

var (
	ErrResourceActionNotFound = errors.New("resource action not found")
	ErrResourceActionRejected = errors.New("resource action transition rejected")
	ErrResourceActionBusy     = errors.New("resource has running work")
	ErrResourceActionCapacity = errors.New("resource action journal is at capacity")
)

// AcceptResourceAction atomically fences current enrollment/trust, advances the
// resource sequence and supersedes unstarted work. Resource floors and protected
// outcomes are never evicted; older read-only findings have bounded retention.
// Unfinished work reserves its entire bounded lifecycle before admission, so
// recording its native outcome does not compete with later work for capacity.
func (s *Store) AcceptResourceAction(ctx context.Context, authorityRevision, trustRevision int64, record *agentv1.ResourceExecutionRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	encoded, err := s.encodeResourceAction(record)
	if err != nil {
		return 0, err
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING &&
		record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED &&
		!readOnlyResourceTerminal(record) && record.GetAdmissionRefusal() == nil {
		return 0, ErrResourceActionRejected
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, resourceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	if err := s.resourceActionFences(ctx, q, authorityRevision, trustRevision, record, true); err != nil {
		return 0, err
	}
	intent := record.GetIntent()
	if err := rejectCanceledResourcePreparation(ctx, q, intent.GetActionId()); err != nil {
		return 0, err
	}
	if existing, err := q.ReadResourceAction(ctx, intent.GetActionId()); err == nil {
		if _, _, err := s.checkedResourceAction(ctx, q, existing); err != nil {
			return 0, err
		}
		return 0, ErrResourceActionRejected
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, stateReadError(ctx)
	}
	floor, err := q.ReadResourceFloor(ctx, resourceFloorKey(record))
	var previous journaldb.ResourceAction
	var superseded []byte
	if errors.Is(err, sql.ErrNoRows) {
		count, err := q.ResourceActionCount(ctx, journaldb.ResourceActionCountParams(resourceFloorKey(record)))
		if err != nil {
			return 0, stateReadError(ctx)
		}
		if count != 0 {
			return 0, ErrRecoveryHold
		}
	} else if err != nil {
		return 0, stateReadError(ctx)
	} else {
		previous, err = q.ReadResourceAction(ctx, floor.ActionID)
		if err != nil {
			return 0, stateReadError(ctx)
		}
		old, err := s.decodeResourceAction(previous)
		if err != nil {
			return 0, err
		}
		if !floorMatchesAction(floor, previous) {
			return 0, ErrRecoveryHold
		}
		if intent.GetResourceSequence() <= uint64(floor.ResourceSequence) {
			return 0, ErrResourceActionRejected
		}
		if old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
			return 0, ErrResourceActionBusy
		}
		// A pending stage must be stopped by its owner before another action
		// takes this floor. Never strand an independent native staging unit.
		if old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING ||
			(old.GetIntent().GetPreparation() != nil && (old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED || old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED)) {
			return 0, ErrResourceActionBusy
		}
		if old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED || old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
			if previous.Revision == math.MaxInt64 {
				return 0, ErrConflict
			}
			old.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED
			old.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED
			old.CompletedAt = record.GetAcceptedAt()
			superseded, err = s.encodeResourceAction(old)
			if err != nil {
				return 0, err
			}
		}
	}
	usage, err := q.ReadResourceActionUsage(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	delta := resourceActionCapacityBytes(record.GetState(), len(encoded))
	if superseded != nil {
		delta += int64(len(superseded)) - resourceActionCapacityBytes(agentv1.ResourceExecutionState(previous.State), len(previous.Record))
	}
	if superseded != nil {
		if err := replaceResourceAction(ctx, q, previous, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED, superseded, false); err != nil {
			return 0, err
		}
	}
	var readOnly int64
	if readOnlyResourceTerminal(record) {
		readOnly = 1
	}
	if err := q.InsertResourceAction(ctx, journaldb.InsertResourceActionParams{
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Kind: int64(intent.GetDesired().GetRef().GetKind()), CanonicalKey: intent.GetDesired().GetRef().GetCanonicalKey(),
		ResourceSequence: int64(intent.GetResourceSequence()), State: int64(record.GetState()), Record: encoded, ReadOnlyTerminal: readOnly,
	}); err != nil {
		return 0, resourceActionWriteError(ctx)
	}
	if record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		if err := s.reserveResourceOwnership(ctx, q, record); err != nil {
			return 0, err
		}
	}
	if err := q.RaiseResourceFloor(ctx, journaldb.RaiseResourceFloorParams{
		DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		Kind: int64(intent.GetDesired().GetRef().GetKind()), CanonicalKey: intent.GetDesired().GetRef().GetCanonicalKey(), ResourceSequence: int64(intent.GetResourceSequence()), ActionID: intent.GetActionId(),
	}); err != nil {
		return 0, resourceActionWriteError(ctx)
	}
	prunedCount, prunedBytes, err := s.pruneReadOnlyResourceActions(ctx, q)
	if err != nil {
		return 0, err
	}
	if err := changeResourceActionUsage(ctx, q, usage, 1-prunedCount, delta-prunedBytes); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, resourceActionWriteError(ctx)
	}
	return 1, nil
}

// Keep the newest 256 non-floor read-only records as well as every current
// resource floor. Admission order is SQLite's durable rowid, not device time.
// Pruning and its returned accounting deltas belong to the caller's transaction.
func (s *Store) pruneReadOnlyResourceActions(ctx context.Context, q *journaldb.Queries) (int64, int64, error) {
	var count, size int64
	for {
		row, err := q.OldReadOnlyResourceAction(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return count, size, nil
		}
		if err != nil {
			return 0, 0, stateReadError(ctx)
		}
		record, _, err := s.checkedResourceAction(ctx, q, row)
		if err != nil {
			return 0, 0, err
		}
		if !readOnlyResourceTerminal(record) {
			return 0, 0, ErrRecoveryHold
		}
		deleted, err := q.DeleteReadOnlyResourceAction(ctx, row.ActionID)
		if err != nil {
			return 0, 0, resourceActionWriteError(ctx)
		}
		if deleted != 1 {
			return 0, 0, ErrRecoveryHold
		}
		count++
		size += int64(len(row.Record))
	}
}

// LoadResourceAction returns an independently decoded record. Exact RPC retries
// are reads; they must not rewrite terminal evidence or renew an old challenge.
func (s *Store) LoadResourceAction(ctx context.Context, actionID string) (*agentv1.ResourceExecutionRecord, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	row, err := s.queries.ReadResourceAction(ctx, actionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrResourceActionNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	return s.checkedResourceAction(ctx, s.queries, row)
}

// NextUnfinishedResourceAction uses a single-row ordered cursor, never an
// unbounded allocation. Restart processing must not replay RUNNING work.
func (s *Store) NextUnfinishedResourceAction(ctx context.Context, afterActionID string) (*agentv1.ResourceExecutionRecord, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	row, err := s.queries.NextUnfinishedResourceAction(ctx, afterActionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrResourceActionNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	return s.checkedResourceAction(ctx, s.queries, row)
}

// UpdateResourceAction commits acceptance, effect consumption or outcome against
// three independent revisions. Revoked authority may record terminal evidence,
// but only currently trusted work may cross QUEUED or RUNNING admission fences.
func (s *Store) UpdateResourceAction(ctx context.Context, actionRevision, authorityRevision, trustRevision int64, next *agentv1.ResourceExecutionRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if actionRevision < 1 || actionRevision == math.MaxInt64 {
		return 0, ErrConflict
	}
	encoded, err := s.encodeResourceAction(next)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, resourceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	admitting := next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED || next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED || next.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING
	if err := s.resourceActionFences(ctx, q, authorityRevision, trustRevision, next, admitting); err != nil {
		return 0, err
	}
	row, err := q.ReadResourceAction(ctx, next.GetIntent().GetActionId())
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrResourceActionNotFound
	}
	if err != nil {
		return 0, stateReadError(ctx)
	}
	current, _, err := s.checkedResourceAction(ctx, q, row)
	if err != nil {
		return 0, err
	}
	if row.Revision != actionRevision {
		return 0, ErrConflict
	}
	if err := rejectResourceActionTransition(current, next); err != nil {
		return 0, err
	}
	usage, err := q.ReadResourceActionUsage(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	delta := resourceActionCapacityBytes(next.GetState(), len(encoded)) - resourceActionCapacityBytes(current.GetState(), len(row.Record))
	if err := changeResourceActionUsage(ctx, q, usage, 0, delta); err != nil {
		return 0, err
	}
	if err := replaceResourceAction(ctx, q, row, next.GetState(), encoded, readOnlyResourceTerminal(next)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, resourceActionWriteError(ctx)
	}
	return actionRevision + 1, nil
}

func replaceResourceAction(ctx context.Context, q *journaldb.Queries, current journaldb.ResourceAction, state agentv1.ResourceExecutionState, encoded []byte, readOnlyTerminal bool) error {
	var readOnly int64
	if readOnlyTerminal {
		readOnly = 1
	}
	changed, err := q.ReplaceResourceAction(ctx, journaldb.ReplaceResourceActionParams{ActionID: current.ActionID, Revision: current.Revision, State: int64(state), Record: encoded, ReadOnlyTerminal: readOnly})
	if err != nil {
		return resourceActionWriteError(ctx)
	}
	if changed != 1 {
		return ErrConflict
	}
	if state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING &&
		state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED &&
		state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED &&
		state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
		if _, err := q.DeleteResourceOwnershipReservation(ctx, current.ActionID); err != nil {
			return resourceActionWriteError(ctx)
		}
	}
	return nil
}

// Every unfinished action reserves its maximum bounded record size before it
// can be admitted. QUEUED/RUNNING growth consumes that reservation, never new
// capacity; terminal evidence releases the unused portion. Keep the aggregate
// ResourceActionTotals SQL in sync with this calculation.
func resourceActionCapacityBytes(state agentv1.ResourceExecutionState, encodedBytes int) int64 {
	switch state {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED,
		agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING:
		return maximumResourceActionBytes
	default:
		return int64(encodedBytes)
	}
}

func changeResourceActionUsage(ctx context.Context, q *journaldb.Queries, usage journaldb.ReadResourceActionUsageRow, countDelta, bytesDelta int64) error {
	if usage.RecordCount < 0 || usage.RecordCount > maximumResourceActions || usage.RecordBytes < 0 || usage.RecordBytes > maximumResourceActionTotalBytes {
		return ErrRecoveryHold
	}
	count, size := usage.RecordCount+countDelta, usage.RecordBytes+bytesDelta
	if count > maximumResourceActions || size > maximumResourceActionTotalBytes {
		return ErrResourceActionCapacity
	}
	if count < 0 || size < 0 {
		return ErrRecoveryHold
	}
	changed, err := q.ReplaceResourceActionUsage(ctx, journaldb.ReplaceResourceActionUsageParams{RecordCount: count, RecordBytes: size})
	if err != nil {
		return resourceActionWriteError(ctx)
	}
	if changed != 1 {
		return ErrRecoveryHold
	}
	return nil
}

func (s *Store) resourceActionFences(ctx context.Context, q *journaldb.Queries, authorityRevision, trustRevision int64, record *agentv1.ResourceExecutionRecord, admitting bool) error {
	row, err := q.ReadState(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	authority, err := s.decodeAuthority(row.Revision, row.State)
	if err != nil {
		return err
	}
	trust, currentTrustRevision, err := s.loadExecutionTrust(ctx, q)
	if err != nil {
		return err
	}
	if row.Revision != authorityRevision || currentTrustRevision != trustRevision {
		return ErrConflict
	}
	if !admitting {
		return nil
	}
	intent := record.GetIntent()
	if authority.GetInstallationId() != record.GetInstallationId() || authority.GetDeviceId() != intent.GetDeviceId() ||
		authority.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || len(authority.GetCertificatePem()) == 0 ||
		!executionTrustConfigured(trust) || !proto.Equal(trust.GetRoot(), record.GetAcceptedRoot()) ||
		!bytes.Equal(trust.GetDelegationEnvelope(), record.GetAcceptedDelegationEnvelope()) ||
		trust.GetRoot().GetDeploymentId() != intent.GetDeploymentId() || trust.GetRoot().GetVersion() != intent.GetRootVersion() ||
		trust.GetDelegationVersion() != intent.GetDelegationVersion() || trust.GetMinimumRecoveryEpoch() > intent.GetRecoveryEpoch() {
		return ErrResourceActionRejected
	}
	return nil
}

func resourceActionWriteError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("commit resource action failed")
}

func resourceFloorKey(record *agentv1.ResourceExecutionRecord) journaldb.ReadResourceFloorParams {
	intent := record.GetIntent()
	return journaldb.ReadResourceFloorParams{DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Kind: int64(intent.GetDesired().GetRef().GetKind()), CanonicalKey: intent.GetDesired().GetRef().GetCanonicalKey()}
}

func floorMatchesAction(floor journaldb.ResourceFloor, row journaldb.ResourceAction) bool {
	return floor.ActionID == row.ActionID && floor.ResourceSequence == row.ResourceSequence && floor.DeploymentID == row.DeploymentID &&
		floor.DeviceID == row.DeviceID && floor.EnrollmentGeneration == row.EnrollmentGeneration && floor.Kind == row.Kind && floor.CanonicalKey == row.CanonicalKey
}
