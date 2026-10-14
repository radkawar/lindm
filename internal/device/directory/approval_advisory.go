// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/advisory"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
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
	switch {
	case err == nil:
		approval.EvidenceState = adminv1.ApprovalEvidenceState_APPROVAL_EVIDENCE_STATE_CURRENT
	case errors.Is(err, advisory.ErrNotFound):
		approval.EvidenceState = adminv1.ApprovalEvidenceState_APPROVAL_EVIDENCE_STATE_UNAVAILABLE
	default:
		return core.MapErr(err)
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, permission); err != nil {
		return core.ExecutionError(err)
	}
	return core.MapErr(tx.Commit(ctx))
}

// admitApproval refuses to approve a request whose bound evidence the device's
// current evaluation no longer reports: an advisory acceptance whose exact
// finding is gone, whether resolved or superseded by newer inventory. The same
// rule projects APPROVAL_EVIDENCE_STATE_UNAVAILABLE on reads.
func (s *Service) admitApproval(ctx context.Context, tx pgx.Tx, approval *adminv1.Approval) error {
	request := approval.GetAcceptAdvisoryFinding()
	if request == nil {
		return nil
	}
	if s.Advisories == nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "advisory_unavailable")
	}
	_, err := s.Advisories.ApprovalFinding(ctx, tx, request)
	if errors.Is(err, advisory.ErrNotFound) {
		return rpcreason.Error(connect.CodeFailedPrecondition, "approval_evidence_unavailable")
	}
	return err
}
