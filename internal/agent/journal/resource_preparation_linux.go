package journal

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"lindm/internal/agent/journal/journaldb"
)

// CancelUnpreparedResourceAction records denial, not execution authority or an
// observation. The caller authenticates its enrolled local connection; no intent
// is admitted and no sequence floor is advanced. Late Prepare cannot bypass it.
func (s *Store) CancelUnpreparedResourceAction(ctx context.Context, authorityRevision int64, actionID string, intentDigest []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	if !canonicalResourceID(actionID) || len(intentDigest) != 32 {
		return ErrResourceActionRejected
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return resourceActionWriteError(ctx)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	row, err := q.ReadState(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	authority, err := s.decodeAuthority(row.Revision, row.State)
	if err != nil {
		return err
	}
	if row.Revision != authorityRevision {
		return ErrConflict
	}
	if !canonicalResourceID(authority.GetEnrollmentGeneration()) {
		return ErrResourceActionRejected
	}
	if _, err := q.ReadResourceAction(ctx, actionID); err == nil {
		return ErrResourceActionRejected
	} else if !errors.Is(err, sql.ErrNoRows) {
		return stateReadError(ctx)
	}
	if old, err := q.ReadResourcePreparationCancellation(ctx, actionID); err == nil {
		if old.EnrollmentGeneration != authority.GetEnrollmentGeneration() || !bytes.Equal(old.IntentSha256, intentDigest) {
			return ErrResourceActionRejected
		}
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return stateReadError(ctx)
	}
	count, err := q.CountResourcePreparationCancellations(ctx)
	if err != nil {
		return stateReadError(ctx)
	}
	if count >= maximumResourceActions {
		return ErrResourceActionCapacity
	}
	if err := q.InsertResourcePreparationCancellation(ctx, journaldb.InsertResourcePreparationCancellationParams{ActionID: actionID, EnrollmentGeneration: authority.GetEnrollmentGeneration(), IntentSha256: bytes.Clone(intentDigest)}); err != nil {
		return resourceActionWriteError(ctx)
	}
	if err := tx.Commit(); err != nil {
		return resourceActionWriteError(ctx)
	}
	return nil
}

func rejectCanceledResourcePreparation(ctx context.Context, q *journaldb.Queries, actionID string) error {
	if _, err := q.ReadResourcePreparationCancellation(ctx, actionID); err == nil {
		return ErrResourceActionRejected
	} else if !errors.Is(err, sql.ErrNoRows) {
		return stateReadError(ctx)
	}
	return nil
}
