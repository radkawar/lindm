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
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity"
	"lindm/internal/targeting/targetingdb"
)

const rolloutPromotionInterval = 10 * time.Second

// Promoter executes the retained human plan, never a service-account grant. Run
// belongs to the exclusive jobs supervisor. Transactions also fence the scanned
// revision, so an overlapping former leader cannot advance the same stage twice.
// Each pass bounds its work: 100 rollouts promoted, 100 awaiting approvals
// checked and 50 planned devices activated.
type Promoter struct {
	pool     *pgxpool.Pool
	identity *identity.Service
	store    *Store
	hooks    RolloutHooks
	after    uuid.UUID
}

// RolloutHooks are the device-domain operations a started rollout needs: the
// canonical resolver, exact preview activation (the same head write as the
// ActivateTargetPreview RPC) and the approval scope check.
type RolloutHooks struct {
	Resolve       Resolver
	Activate      func(ctx context.Context, tx pgx.Tx, preview *policyv1.TargetPreview, actor uuid.UUID, authorizationVersion uint64, adoptionApprovalID, reason string) error
	ApprovalScope identity.ApprovalScope
}

func NewPromoter(pool *pgxpool.Pool, auth *identity.Service, store *Store, hooks RolloutHooks) (*Promoter, error) {
	if pool == nil || auth == nil || store == nil || hooks.Resolve == nil || hooks.Activate == nil || hooks.ApprovalScope == nil {
		return nil, errors.New("targeting: promoter requires pool, identity, store and rollout hooks")
	}
	return &Promoter{pool: pool, identity: auth, store: store, hooks: hooks}, nil
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

// RunOnce promotes, starts approved rollouts and activates admitted planned
// devices, each phase under its own deadline so one cannot starve the others.
func (p *Promoter) RunOnce(ctx context.Context) error {
	return errors.Join(p.promoteOnce(ctx), p.startApproved(ctx), p.activatePlanned(ctx))
}

// promoteOnce assesses one bounded page without requiring a console read. Health
// pauses commit before identity/network work. Only a ready automatic successor
// needs fresh creator authority; manual and final rings remain health-monitored.
func (p *Promoter) promoteOnce(ctx context.Context) error {
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

// creatorAuthority freshly authorizes a rollout creator's unrestricted
// resources.assign; a service identity never substitutes for the human.
func (p *Promoter) creatorAuthority(ctx context.Context, creator uuid.UUID) (*identity.Authorization, error) {
	authorization, err := p.identity.AuthorizeFresh(ctx, creator, identity.PermissionAssignResources)
	if err != nil {
		return nil, err
	}
	if unrestricted, _ := identity.DeviceScopes(authorization.Principal(), identity.PermissionAssignResources); !unrestricted {
		return nil, identity.ErrAuthorizationDenied
	}
	return authorization, nil
}

// startApproved decides rollouts awaiting their single approval: an approved
// request is consumed and started under the creator's fresh authority; a
// rejected, expired or never-requested approval ends the rollout.
func (p *Promoter) startApproved(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := targetingdb.New(p.pool).ListAwaitingRolloutPlans(ctx, uuid.Nil)
	if err != nil {
		return err
	}
	var first error
	for _, row := range rows {
		if ctx.Err() != nil {
			return errors.Join(first, ctx.Err())
		}
		if err := p.decide(ctx, row); err != nil && first == nil {
			first = fmt.Errorf("start rollout %s: %w", row.RolloutID, err)
		}
	}
	return first
}

func (p *Promoter) decide(ctx context.Context, row targetingdb.ListAwaitingRolloutPlansRow) error {
	request := new(adminv1.StartRolloutRequest)
	if err := proto.Unmarshal(row.Request, request); err != nil {
		return err
	}
	approval, state, err := p.identity.ApprovalForRequest(ctx, p.pool, row.CreatorID, request)
	if errors.Is(err, identity.ErrApprovalInvalid) {
		// A different payload under the same request ID never approves this plan.
		state, err = adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, nil
	}
	if err != nil {
		return err
	}
	switch state {
	case adminv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED:
		if time.Since(row.CreatedAt.Time) < ApprovalWindow {
			return nil
		}
		return p.end(ctx, row.RolloutID, planApprovalExpired, "approval_expired")
	case adminv1.ApprovalState_APPROVAL_STATE_PENDING:
		return nil
	case adminv1.ApprovalState_APPROVAL_STATE_EXPIRED:
		return p.end(ctx, row.RolloutID, planApprovalExpired, "approval_expired")
	case adminv1.ApprovalState_APPROVAL_STATE_REJECTED:
		return p.end(ctx, row.RolloutID, planRejected, "approval_rejected")
	case adminv1.ApprovalState_APPROVAL_STATE_WITHDRAWN:
		return p.end(ctx, row.RolloutID, planRejected, "approval_withdrawn")
	}
	authorization, err := p.creatorAuthority(ctx, row.CreatorID)
	if rolloutAuthorityDenied(err) {
		// The approval cannot be used by a creator who lost authority; it expires.
		return nil
	}
	if err != nil {
		return err
	}
	pair, err := p.identity.PrepareApprovalConsumption(ctx, row.CreatorID, approval, request)
	if errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrApprovalInvalid) {
		// Either principal changed after the decision; the approval is spent.
		return p.end(ctx, row.RolloutID, planApprovalExpired, "approval_invalidated")
	}
	if err != nil {
		return err
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.identity.LockAndConsumeApproval(ctx, tx, pair, func(ctx context.Context, tx pgx.Tx, principal identity.Principal, permission identity.Permission, target uuid.UUID) error {
		if err := p.store.Lock(ctx, tx); err != nil {
			return err
		}
		return p.hooks.ApprovalScope(ctx, tx, principal, permission, target)
	}); err != nil {
		return ignoreRolloutContention(err)
	}
	if err := p.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return err
	}
	if err := p.store.StartApproved(ctx, tx, authorization.Principal(), row.RolloutID, approval); err != nil {
		return ignoreRolloutContention(err)
	}
	if err := p.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Promoter) end(ctx context.Context, id uuid.UUID, status int16, reason string) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.store.endAwaiting(ctx, tx, id, status, reason); err != nil {
		return ignoreRolloutContention(err)
	}
	return tx.Commit(ctx)
}

// activatePlanned activates a bounded batch of admitted, still pending planned
// devices. Each device commits separately; one device never blocks the rest.
func (p *Promoter) activatePlanned(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := targetingdb.New(p.pool)
	rows, err := q.ListRolloutActivations(ctx)
	if err != nil {
		return err
	}
	authorities := make(map[uuid.UUID]*identity.Authorization)
	denied := make(map[uuid.UUID]bool)
	var first error
	for _, row := range rows {
		if ctx.Err() != nil {
			return errors.Join(first, ctx.Err())
		}
		if denied[row.RolloutID] {
			continue
		}
		authorization := authorities[row.CreatorID]
		if authorization == nil {
			authorization, err = p.creatorAuthority(ctx, row.CreatorID)
			if err == nil {
				authorities[row.CreatorID] = authorization
			}
		}
		if err == nil {
			err = p.activateOne(ctx, authorization, row)
		}
		if rolloutAuthorityDenied(err) {
			denied[row.RolloutID] = true
			err = p.pauseRolloutAuthority(ctx, row.RolloutID)
		}
		if err = ignoreRolloutContention(err); err != nil {
			if first == nil {
				first = fmt.Errorf("activate rollout %s device %s: %w", row.RolloutID, row.DeviceID, err)
			}
			// Move a failing device behind the rest of the queue.
			if touchErr := q.TouchRolloutDevicePlan(ctx, targetingdb.TouchRolloutDevicePlanParams{RolloutID: row.RolloutID, DeviceID: row.DeviceID}); touchErr != nil {
				return errors.Join(first, touchErr)
			}
		}
	}
	return first
}

func (p *Promoter) activateOne(ctx context.Context, authorization *identity.Authorization, row targetingdb.ListRolloutActivationsRow) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return err
	}
	if err := p.store.ActivatePlanned(ctx, tx, authorization.Principal(), row.RolloutID, row.DeviceID, p.hooks.Resolve, func(ctx context.Context, tx pgx.Tx, preview *policyv1.TargetPreview, approval, reason string) error {
		return p.hooks.Activate(ctx, tx, preview, authorization.ActorID(), authorization.Version(), approval, reason)
	}); err != nil {
		return err
	}
	if err := p.identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Promoter) pauseRolloutAuthority(ctx context.Context, id uuid.UUID) error {
	row, err := targetingdb.New(p.pool).GetRollout(ctx, id)
	if err != nil {
		return err
	}
	return p.pauseAuthority(ctx, targetingdb.ListActiveRolloutsRow{ID: row.ID, CreatorID: row.CreatorID, Revision: row.Revision})
}
