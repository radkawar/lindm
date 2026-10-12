package targeting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/auditkind"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

const rolloutPromotionInterval = 10 * time.Second

// Promoter executes the retained human plan, never a service-account grant. Run
// belongs to the exclusive jobs supervisor. Transactions also fence the scanned
// revision, so an overlapping former leader cannot advance the same stage twice.
// A Promoter has one runner; its keyset cursor bounds each pass to 100 rollouts.
type Promoter struct {
	pool     *pgxpool.Pool
	identity *identity.Service
	store    *Store
	after    uuid.UUID
}

func NewPromoter(pool *pgxpool.Pool, auth *identity.Service, store *Store) (*Promoter, error) {
	if pool == nil || auth == nil || store == nil {
		return nil, errors.New("targeting: promoter requires pool, identity and store")
	}
	return &Promoter{pool: pool, identity: auth, store: store}, nil
}

func (p *Promoter) Run(ctx context.Context) error {
	ticker := time.NewTicker(rolloutPromotionInterval)
	defer ticker.Stop()
	for {
		if err := p.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("rollout promotion failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// RunOnce assesses one bounded page without requiring a console read. Health
// pauses commit before identity/network work. Only a ready automatic successor
// needs fresh creator authority; manual and final rings remain health-monitored.
func (p *Promoter) RunOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := targetingdb.New(p.pool).ListActiveRollouts(ctx, p.after)
	if err != nil {
		return err
	}
	var first error
	for _, row := range rows {
		if ctx.Err() != nil {
			return errors.Join(first, ctx.Err())
		}
		if err := p.evaluate(ctx, row); err != nil && first == nil {
			first = fmt.Errorf("evaluate rollout %s: %w", row.ID, err)
		}
		p.after = row.ID
	}
	if len(rows) < 100 {
		p.after = uuid.Nil
	}
	return first
}

func (p *Promoter) evaluate(ctx context.Context, candidate targetingdb.ListActiveRolloutsRow) error {
	ready, err := p.refresh(ctx, candidate)
	if err != nil || !ready {
		return ignoreRolloutContention(err)
	}
	authorization, err := p.identity.AuthorizeFresh(ctx, candidate.CreatorID, identity.PermissionAssignResources)
	if err == nil {
		unrestricted, _ := identity.DeviceScopes(authorization.Principal(), identity.PermissionAssignResources)
		if !unrestricted {
			err = identity.ErrAuthorizationDenied
		}
	}
	if err == nil {
		err = p.promote(ctx, candidate, authorization)
	}
	if rolloutAuthorityDenied(err) {
		return ignoreRolloutContention(p.pauseAuthority(ctx, candidate))
	}
	return ignoreRolloutContention(err)
}

func rolloutAuthorityDenied(err error) bool {
	return errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrAuthorizationExpired) || errors.Is(err, identity.ErrDirectoryUnavailable)
}

func ignoreRolloutContention(err error) error {
	var database *pgconn.PgError
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotReady) || errors.As(err, &database) && (database.Code == "40001" || database.Code == "40P01") {
		return nil
	}
	return err
}

func (p *Promoter) refresh(ctx context.Context, candidate targetingdb.ListActiveRolloutsRow) (bool, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := targetingdb.New(tx)
	if err := q.LockTargeting(ctx); err != nil {
		return false, err
	}
	row, err := q.GetRollout(ctx, candidate.ID)
	if err != nil {
		return false, err
	}
	if row.Paused || row.Revision != candidate.Revision {
		return false, nil
	}
	if _, err := p.store.RefreshRollout(ctx, tx, candidate.ID); err != nil {
		return false, err
	}
	state, err := p.store.rolloutState(ctx, q, candidate.ID)
	if err != nil {
		return false, err
	}
	return state.PromotionReady, tx.Commit(ctx)
}

func (p *Promoter) promote(ctx context.Context, candidate targetingdb.ListActiveRolloutsRow, authorization *identity.Authorization) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Principal-before-targeting order is shared with the manual RPC. No
	// authoritative directory I/O occurs under these locks.
	if err := p.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return err
	}
	q := targetingdb.New(tx)
	if err := q.LockTargeting(ctx); err != nil {
		return err
	}
	row, err := q.GetRollout(ctx, candidate.ID)
	if err != nil {
		return err
	}
	if row.Paused || row.Revision != candidate.Revision {
		return nil
	}
	if _, err := p.store.PromoteAutomatic(ctx, tx, authorization.Principal(), identity.PermissionAssignResources, row.ID); err != nil {
		return err
	}
	if err := p.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Promoter) pauseAuthority(ctx context.Context, candidate targetingdb.ListActiveRolloutsRow) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := targetingdb.New(tx)
	if err := q.LockTargeting(ctx); err != nil {
		return err
	}
	row, err := q.GetRollout(ctx, candidate.ID)
	if err != nil {
		return err
	}
	if row.Paused || row.Revision != candidate.Revision {
		return nil
	}
	if err := pauseRollout(ctx, q, row, "rollout_authorization_denied"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A safety pause only withdraws authority. It does not need a replacement actor
// when the creator is disabled, and never assigns ownership to the current leader.
func pauseRollout(ctx context.Context, q *targetingdb.Queries, row targetingdb.ResourceRollout, reason string) error {
	count, err := q.UpdateRollout(ctx, targetingdb.UpdateRolloutParams{ID: row.ID, RingIndex: row.RingIndex, Paused: true, PauseReason: reason, StageStartedAt: row.StageStartedAt, ExpectedRevision: row.Revision})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	if err := q.InsertRolloutEvent(ctx, targetingdb.InsertRolloutEventParams{ID: uuid.New(), RolloutID: row.ID, Revision: row.Revision + 1, Reason: reason}); err != nil {
		return err
	}
	return q.TargetingAudit(ctx, targetingdb.TargetingAuditParams{ID: uuid.New(), Action: auditkind.TargetingRolloutPause.String(), ResourceID: row.ID.String(), Context: reason})
}
