package directory

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting"
)

// populateTargetApproval adds retained evidence only after the normal approval
// API authorizes the record, then rechecks current action authority and device
// scope under the same locks as other scoped product reads.
func (s *Service) populateTargetApproval(ctx context.Context, actor identity.Principal, approval *adminv1.Approval) error {
	request := approval.GetActivateTargetPreview()
	if request == nil || s.Targeting == nil {
		return nil
	}
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionAssignResources)
	if err != nil {
		return core.ExecutionError(err)
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return core.ExecutionError(err)
	}
	id, err := uuid.Parse(request.GetDeviceId())
	if err != nil {
		return core.MapErr(core.ErrInternalState)
	}
	if _, err := core.LockDeviceScope(ctx, devicedb.New(tx), authorization.Principal(), identity.PermissionAssignResources, id); err != nil {
		return core.MapErr(err)
	}
	approval.TargetPreview, err = s.Targeting.ApprovalPreview(ctx, tx, request)
	if errors.Is(err, targeting.ErrRejected) || errors.Is(err, targeting.ErrNotFound) {
		// Historical records may predate binding validation or retained evidence.
		// Never turn malformed optional evidence into a valid approval or an
		// unreadable inbox. Activation still performs its strict digest check.
		approval.TargetPreview = nil
	} else if err != nil {
		return targetApprovalError(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionAssignResources); err != nil {
		return core.ExecutionError(err)
	}
	return core.MapErr(tx.Commit(ctx))
}

func targetApprovalError(err error) error {
	if errors.Is(err, targeting.ErrRejected) {
		return core.Invalid("invalid_targeting_request")
	}
	if errors.Is(err, targeting.ErrNotFound) {
		return rpcreason.Error(connect.CodeNotFound, "targeting_not_found")
	}
	return core.MapErr(err)
}
