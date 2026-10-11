package directory

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/advisory"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// populateAdvisoryApproval exposes only the exact finding, under fresh action
// authority and target scope. A removed finding remains unavailable, not replaced.
func (s *Service) populateAdvisoryApproval(ctx context.Context, actor identity.Principal, approval *adminv1.Approval) error {
	request := approval.GetAcceptAdvisoryFinding()
	if request == nil || s.Advisories == nil {
		return nil
	}
	permission := identity.PermissionManageAdvisoryExceptions
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, permission)
	if err != nil {
		return core.ExecutionError(err)
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return core.ExecutionError(err)
	}
	id, err := uuid.Parse(request.GetDeviceId())
	if err != nil {
		return core.MapErr(core.ErrInternalState)
	}
	if _, err := core.LockDeviceScope(ctx, devicedb.New(tx), authorization.Principal(), permission, id); err != nil {
		return core.MapErr(err)
	}
	approval.AdvisoryFinding, err = s.Advisories.ApprovalFinding(ctx, tx, request)
	if err != nil && !errors.Is(err, advisory.ErrNotFound) {
		return core.MapErr(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return core.ExecutionError(err)
	}
	return core.MapErr(tx.Commit(ctx))
}
