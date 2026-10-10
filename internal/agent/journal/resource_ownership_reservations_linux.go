package journal

import (
	"context"
	"database/sql"
	"errors"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal/journaldb"
)

// Called only inside action admission: no native staging may start unless both
// action and future ownership/undo lifecycle capacity commit together.
func (s *Store) reserveResourceOwnership(ctx context.Context, q *journaldb.Queries, record *agentv1.ResourceExecutionRecord) error {
	intent := record.GetIntent()
	ref := intent.GetDesired().GetRef()
	key := journaldb.ReadResourceOwnershipParams{DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), Kind: int64(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey()}
	ledger, err := s.loadResourceOwnership(ctx, q, key)
	if err == nil {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED && !sameResourceOwner(ledger.GetOwner(), intent.GetOwnership()) {
			return ErrResourceOwnershipConflict
		}
		return nil // Even released ledgers retain their complete capacity.
	}
	if !errors.Is(err, ErrResourceOwnershipNotFound) {
		return err
	}
	if err := s.rejectOtherGenerationOwnership(ctx, q, key); err != nil {
		return err
	}
	count, err := q.ReadResourceOwnershipUsage(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	reserved, err := q.CountResourceOwnershipReservations(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if count < 0 || reserved < 0 || count+reserved > 256 {
		return ErrRecoveryHold
	}
	if count+reserved == 256 {
		return ErrResourceOwnershipCapacity
	}
	if err := q.InsertResourceOwnershipReservation(ctx, journaldb.InsertResourceOwnershipReservationParams{ActionID: intent.GetActionId(), DeploymentID: key.DeploymentID, DeviceID: key.DeviceID, EnrollmentGeneration: key.EnrollmentGeneration, Kind: key.Kind, CanonicalKey: key.CanonicalKey}); err != nil {
		return resourceActionWriteError(ctx)
	}
	return nil
}

// A synchronous claim may not consume capacity reserved by other preparation.
// A staged claim must consume its own durable reservation, never a new slot.
func consumeResourceOwnershipReservation(ctx context.Context, q *journaldb.Queries, action *agentv1.ResourceExecutionRecord, count int64) error {
	reserved, err := q.CountResourceOwnershipReservations(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	_, err = q.ReadResourceOwnershipReservation(ctx, action.GetIntent().GetActionId())
	if errors.Is(err, sql.ErrNoRows) {
		if action.GetIntent().GetPreparation() != nil {
			return ErrRecoveryHold
		}
		if count+reserved >= 256 {
			return ErrResourceOwnershipCapacity
		}
		return nil
	}
	if err != nil {
		return stateReadError(ctx)
	}
	if count+reserved > 256 {
		return ErrRecoveryHold
	}
	changed, err := q.DeleteResourceOwnershipReservation(ctx, action.GetIntent().GetActionId())
	if err != nil {
		return resourceActionWriteError(ctx)
	}
	if changed != 1 {
		return ErrRecoveryHold
	}
	return nil
}

func (s *Store) validatePendingOwnershipReservations(ctx context.Context) error {
	for cursor := ""; ; {
		row, err := s.queries.NextResourceAction(ctx, cursor)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return stateReadError(ctx)
		}
		cursor = row.ActionID
		if row.State != 1 && row.State != 2 && row.State != 3 && row.State != 9 {
			continue
		}
		action, err := s.decodeResourceAction(row)
		if err != nil {
			return err
		}
		if action.GetIntent().GetPreparation() == nil {
			continue
		}
		key := journaldb.ReadResourceOwnershipParams{DeploymentID: row.DeploymentID, DeviceID: row.DeviceID, EnrollmentGeneration: row.EnrollmentGeneration, Kind: row.Kind, CanonicalKey: row.CanonicalKey}
		if _, err := s.queries.ReadResourceOwnership(ctx, key); err == nil {
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			return stateReadError(ctx)
		}
		if _, err := s.queries.ReadResourceOwnershipReservation(ctx, row.ActionID); err != nil {
			return stateReadError(ctx)
		}
	}
}
