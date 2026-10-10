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
	maximumServiceActionBytes      = 128 << 10
	maximumServiceActions          = 65536
	maximumServiceActionTotalBytes = 256 << 20
)

var (
	ErrServiceActionNotFound = errors.New("service action not found")
	ErrServiceActionRejected = errors.New("service action transition rejected")
	ErrServiceActionBusy     = errors.New("service resource has running work")
	ErrServiceActionCapacity = errors.New("service action journal is at capacity")
)

// AcceptServiceAction atomically fences current enrollment/trust, advances the
// resource sequence and supersedes unstarted work. Resource floors and protected
// outcomes are never evicted; older read-only successes have bounded retention.
// Unfinished work reserves its entire bounded lifecycle before admission, so
// recording its native outcome does not compete with later work for capacity.
func (s *Store) AcceptServiceAction(ctx context.Context, authorityRevision, trustRevision int64, record *agentv1.ServiceExecutionRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	encoded, err := s.encodeServiceAction(record)
	if err != nil {
		return 0, err
	}
	if record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED &&
		(record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED || servicePlanDrifts(record)) {
		return 0, ErrServiceActionRejected
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, serviceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	if err := s.serviceActionFences(ctx, q, authorityRevision, trustRevision, record, true); err != nil {
		return 0, err
	}
	intent := record.GetIntent()
	if existing, err := q.ReadServiceAction(ctx, intent.GetActionId()); err == nil {
		if _, _, err := s.checkedServiceAction(ctx, q, existing); err != nil {
			return 0, err
		}
		return 0, ErrServiceActionRejected
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, stateReadError(ctx)
	}
	floor, err := q.ReadServiceResourceFloor(ctx, serviceFloorKey(record))
	var previous journaldb.ServiceAction
	var superseded []byte
	if errors.Is(err, sql.ErrNoRows) {
		count, err := q.ServiceResourceActionCount(ctx, journaldb.ServiceResourceActionCountParams(serviceFloorKey(record)))
		if err != nil {
			return 0, stateReadError(ctx)
		}
		if count != 0 {
			return 0, ErrRecoveryHold
		}
	} else if err != nil {
		return 0, stateReadError(ctx)
	} else {
		previous, err = q.ReadServiceAction(ctx, floor.ActionID)
		if err != nil {
			return 0, stateReadError(ctx)
		}
		old, err := s.decodeServiceAction(previous)
		if err != nil {
			return 0, err
		}
		if !floorMatchesAction(floor, previous) {
			return 0, ErrRecoveryHold
		}
		if intent.GetResourceSequence() <= uint64(floor.ResourceSequence) {
			return 0, ErrServiceActionRejected
		}
		if old.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING {
			return 0, ErrServiceActionBusy
		}
		if old.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED || old.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED {
			if previous.Revision == math.MaxInt64 {
				return 0, ErrConflict
			}
			old.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED
			old.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_SUPERSEDED
			old.CompletedAt = record.GetAcceptedAt()
			superseded, err = s.encodeServiceAction(old)
			if err != nil {
				return 0, err
			}
		}
	}
	usage, err := q.ReadServiceActionUsage(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	delta := serviceActionCapacityBytes(record.GetState(), len(encoded))
	if superseded != nil {
		delta += int64(len(superseded)) - serviceActionCapacityBytes(agentv1.ServiceExecutionState(previous.State), len(previous.Record))
	}
	if superseded != nil {
		if err := replaceServiceAction(ctx, q, previous, agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED, superseded); err != nil {
			return 0, err
		}
	}
	var readOnly int64
	if readOnlyServiceSuccess(record) {
		readOnly = 1
	}
	if err := q.InsertServiceAction(ctx, journaldb.InsertServiceActionParams{
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Unit: intent.GetDesired().GetUnit(),
		ResourceSequence: int64(intent.GetResourceSequence()), State: int64(record.GetState()), Record: encoded, ReadOnlySuccess: readOnly,
	}); err != nil {
		return 0, serviceActionWriteError(ctx)
	}
	if err := q.RaiseServiceResourceFloor(ctx, journaldb.RaiseServiceResourceFloorParams{
		DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		Unit: intent.GetDesired().GetUnit(), ResourceSequence: int64(intent.GetResourceSequence()), ActionID: intent.GetActionId(),
	}); err != nil {
		return 0, serviceActionWriteError(ctx)
	}
	prunedCount, prunedBytes, err := s.pruneReadOnlyServiceActions(ctx, q)
	if err != nil {
		return 0, err
	}
	if err := changeServiceActionUsage(ctx, q, usage, 1-prunedCount, delta-prunedBytes); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, serviceActionWriteError(ctx)
	}
	return 1, nil
}

// Keep the newest 256 non-floor read-only records as well as every current
// resource floor. Admission order is SQLite's durable rowid, not device time.
// Pruning and its returned accounting deltas belong to the caller's transaction.
func (s *Store) pruneReadOnlyServiceActions(ctx context.Context, q *journaldb.Queries) (int64, int64, error) {
	var count, size int64
	for {
		row, err := q.OldReadOnlyServiceAction(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return count, size, nil
		}
		if err != nil {
			return 0, 0, stateReadError(ctx)
		}
		record, _, err := s.checkedServiceAction(ctx, q, row)
		if err != nil {
			return 0, 0, err
		}
		if !readOnlyServiceSuccess(record) {
			return 0, 0, ErrRecoveryHold
		}
		deleted, err := q.DeleteReadOnlyServiceAction(ctx, row.ActionID)
		if err != nil {
			return 0, 0, serviceActionWriteError(ctx)
		}
		if deleted != 1 {
			return 0, 0, ErrRecoveryHold
		}
		count++
		size += int64(len(row.Record))
	}
}

// LoadServiceAction returns an independently decoded record. Exact RPC retries
// are reads; they must not rewrite terminal evidence or renew an old challenge.
func (s *Store) LoadServiceAction(ctx context.Context, actionID string) (*agentv1.ServiceExecutionRecord, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	row, err := s.queries.ReadServiceAction(ctx, actionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrServiceActionNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	return s.checkedServiceAction(ctx, s.queries, row)
}

// NextUnfinishedServiceAction uses a single-row ordered cursor, never an
// unbounded allocation. Restart processing must not replay RUNNING work.
func (s *Store) NextUnfinishedServiceAction(ctx context.Context, afterActionID string) (*agentv1.ServiceExecutionRecord, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	row, err := s.queries.NextUnfinishedServiceAction(ctx, afterActionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrServiceActionNotFound
	}
	if err != nil {
		return nil, 0, stateReadError(ctx)
	}
	return s.checkedServiceAction(ctx, s.queries, row)
}

// UpdateServiceAction commits acceptance, effect consumption or outcome against
// three independent revisions. Revoked authority may record terminal evidence,
// but only currently trusted work may cross QUEUED or RUNNING admission fences.
func (s *Store) UpdateServiceAction(ctx context.Context, actionRevision, authorityRevision, trustRevision int64, next *agentv1.ServiceExecutionRecord) (int64, error) {
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
	encoded, err := s.encodeServiceAction(next)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, serviceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	admitting := next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED || next.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING
	if err := s.serviceActionFences(ctx, q, authorityRevision, trustRevision, next, admitting); err != nil {
		return 0, err
	}
	row, err := q.ReadServiceAction(ctx, next.GetIntent().GetActionId())
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrServiceActionNotFound
	}
	if err != nil {
		return 0, stateReadError(ctx)
	}
	current, _, err := s.checkedServiceAction(ctx, q, row)
	if err != nil {
		return 0, err
	}
	if row.Revision != actionRevision {
		return 0, ErrConflict
	}
	if err := rejectServiceActionTransition(current, next); err != nil {
		return 0, err
	}
	usage, err := q.ReadServiceActionUsage(ctx)
	if err != nil {
		return 0, stateReadError(ctx)
	}
	delta := serviceActionCapacityBytes(next.GetState(), len(encoded)) - serviceActionCapacityBytes(current.GetState(), len(row.Record))
	if err := changeServiceActionUsage(ctx, q, usage, 0, delta); err != nil {
		return 0, err
	}
	if err := replaceServiceAction(ctx, q, row, next.GetState(), encoded); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, serviceActionWriteError(ctx)
	}
	return actionRevision + 1, nil
}

func replaceServiceAction(ctx context.Context, q *journaldb.Queries, current journaldb.ServiceAction, state agentv1.ServiceExecutionState, encoded []byte) error {
	changed, err := q.ReplaceServiceAction(ctx, journaldb.ReplaceServiceActionParams{ActionID: current.ActionID, Revision: current.Revision, State: int64(state), Record: encoded})
	if err != nil {
		return serviceActionWriteError(ctx)
	}
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

// Every unfinished action reserves its maximum bounded record size before it
// can be admitted. QUEUED/RUNNING growth consumes that reservation, never new
// capacity; terminal evidence releases the unused portion. Keep the aggregate
// ServiceActionTotals SQL in sync with this calculation.
func serviceActionCapacityBytes(state agentv1.ServiceExecutionState, encodedBytes int) int64 {
	switch state {
	case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED,
		agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING:
		return maximumServiceActionBytes
	default:
		return int64(encodedBytes)
	}
}

func changeServiceActionUsage(ctx context.Context, q *journaldb.Queries, usage journaldb.ReadServiceActionUsageRow, countDelta, bytesDelta int64) error {
	if usage.RecordCount < 0 || usage.RecordCount > maximumServiceActions || usage.RecordBytes < 0 || usage.RecordBytes > maximumServiceActionTotalBytes {
		return ErrRecoveryHold
	}
	count, size := usage.RecordCount+countDelta, usage.RecordBytes+bytesDelta
	if count > maximumServiceActions || size > maximumServiceActionTotalBytes {
		return ErrServiceActionCapacity
	}
	if count < 0 || size < 0 {
		return ErrRecoveryHold
	}
	changed, err := q.ReplaceServiceActionUsage(ctx, journaldb.ReplaceServiceActionUsageParams{RecordCount: count, RecordBytes: size})
	if err != nil {
		return serviceActionWriteError(ctx)
	}
	if changed != 1 {
		return ErrRecoveryHold
	}
	return nil
}

func (s *Store) serviceActionFences(ctx context.Context, q *journaldb.Queries, authorityRevision, trustRevision int64, record *agentv1.ServiceExecutionRecord, admitting bool) error {
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
		return ErrServiceActionRejected
	}
	return nil
}

func serviceActionWriteError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("commit service action failed")
}

func serviceFloorKey(record *agentv1.ServiceExecutionRecord) journaldb.ReadServiceResourceFloorParams {
	intent := record.GetIntent()
	return journaldb.ReadServiceResourceFloorParams{DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Unit: intent.GetDesired().GetUnit()}
}

func floorMatchesAction(floor journaldb.ServiceResourceFloor, row journaldb.ServiceAction) bool {
	return floor.ActionID == row.ActionID && floor.ResourceSequence == row.ResourceSequence && floor.DeploymentID == row.DeploymentID &&
		floor.DeviceID == row.DeviceID && floor.EnrollmentGeneration == row.EnrollmentGeneration && floor.Unit == row.Unit
}
