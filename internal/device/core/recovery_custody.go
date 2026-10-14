// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"encoding/hex"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

func unknownRecoveryCustody() *adminv1.RecoveryKeyCustody {
	return &adminv1.RecoveryKeyCustody{State: adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_UNKNOWN}
}

// Providers return caller-owned public creation records. Only this domain's
// durable owner attestation can produce CONFIRMED; custody on disk cannot.
func (s *Service) currentRecoveryCustody() *adminv1.RecoveryKeyCustody {
	if s.RecoveryKeyCustody == nil {
		return unknownRecoveryCustody()
	}
	custody, err := s.RecoveryKeyCustody()
	if err != nil || custody == nil {
		return unknownRecoveryCustody()
	}
	custody.CanConfirm = false
	custody.ConfirmedAt = nil
	switch custody.State {
	case adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_EXTERNAL_RECIPIENTS:
		return custody
	case adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING:
		return custody
	default:
		return unknownRecoveryCustody()
	}
}

func (s *Service) recoveryCustodyStatus(ctx context.Context, q *devicedb.Queries, actor identity.Principal) (*adminv1.RecoveryKeyCustody, error) {
	custody := s.currentRecoveryCustody()
	if custody.State != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING {
		return custody, nil
	}
	confirmed, err := q.GetRecoveryCustodyConfirmation(ctx, devicedb.GetRecoveryCustodyConfirmationParams{DeploymentID: s.DeploymentID, ConfirmationDigest: custody.ConfirmationDigest})
	if err == nil {
		custody.State = adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_CONFIRMED
		custody.ConfirmedAt = timestamppb.New(confirmed.Time)
		return custody, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	owner, err := q.IsRecoveryCustodyOwner(ctx, actor.ID)
	if err != nil {
		return nil, err
	}
	custody.CanConfirm = owner && actor.Role == identity.RoleOwner && !actor.ServiceAccount && identity.Authorize(actor, identity.PermissionManageExecutionTrust) && RequireUnrestrictedPrincipal(actor, identity.PermissionManageExecutionTrust) == nil
	return custody, nil
}

// ConfirmRecoveryKeyCustody records an owner's assertion about off-server
// custody. It neither transfers keys nor verifies external storage/removal.
func (s *Service) ConfirmRecoveryKeyCustody(ctx context.Context, req *connect.Request[adminv1.ConfirmRecoveryKeyCustodyRequest]) (*connect.Response[adminv1.ConfirmRecoveryKeyCustodyResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageExecutionTrust)
	if err != nil {
		return nil, err
	}
	if actor.Role != identity.RoleOwner || actor.ServiceAccount {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, Invalid("invalid_request")
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionManageExecutionTrust)
	if err != nil {
		return nil, ExecutionError(err)
	}
	fresh := authorization.Principal()
	if fresh.Role != identity.RoleOwner || fresh.ServiceAccount {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	if err := RequireUnrestrictedPrincipal(fresh, identity.PermissionManageExecutionTrust); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(req.Msg.GetExpectedConfirmationDigest())
	if err != nil || len(digest) != 32 {
		return nil, Invalid("invalid_request")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageExecutionTrust); err != nil {
		return nil, ExecutionError(err)
	}
	q := devicedb.New(tx)
	owner, err := q.IsRecoveryCustodyOwner(ctx, actor.ID)
	if err != nil {
		return nil, MapErr(err)
	}
	if !owner {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	custody := s.currentRecoveryCustody()
	if custody.State != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_custody_unknown")
	}
	if custody.ConfirmationDigest != req.Msg.GetExpectedConfirmationDigest() {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_custody_changed")
	}
	if err := s.Identity.LockRecentStepUpForCustody(ctx, tx, digest); err != nil {
		return nil, custodyVerificationError(err)
	}
	count, err := q.RecordRecoveryCustodyConfirmation(ctx, devicedb.RecordRecoveryCustodyConfirmationParams{DeploymentID: s.DeploymentID, ConfirmationDigest: custody.ConfirmationDigest, OwnerPrincipalID: actor.ID})
	if err != nil {
		return nil, MapErr(err)
	}
	if count == 1 {
		if err := InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), ActorID: &actor.ID, Action: auditkind.RecoveryCustodyConfirmed.String(), ResourceID: "server/recovery-custody", Reason: "Owner attested off-server recovery custody; storage and removal not verified"}, AuditDetails("deployment_id", s.DeploymentID.String(), "confirmation_digest", custody.ConfirmationDigest)); err != nil {
			return nil, MapErr(err)
		}
	}
	current := s.currentRecoveryCustody()
	if current.State != adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_PENDING || current.ConfirmationDigest != custody.ConfirmationDigest {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "recovery_custody_changed")
	}
	if err := s.Identity.LockAuthorization(ctx, tx, authorization, identity.PermissionManageExecutionTrust); err != nil {
		return nil, ExecutionError(err)
	}
	if err := s.Identity.ConsumeRecoveryCustodyStepUp(ctx, tx, digest); err != nil {
		return nil, custodyVerificationError(err)
	}
	confirmed, err := q.GetRecoveryCustodyConfirmation(ctx, devicedb.GetRecoveryCustodyConfirmationParams{DeploymentID: s.DeploymentID, ConfirmationDigest: custody.ConfirmationDigest})
	if err != nil {
		return nil, MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, MapErr(err)
	}
	custody.State = adminv1.RecoveryKeyCustodyState_RECOVERY_KEY_CUSTODY_STATE_CONFIRMED
	custody.ConfirmedAt = timestamppb.New(confirmed.Time)
	custody.CanConfirm = false
	return NoStore(&adminv1.ConfirmRecoveryKeyCustodyResponse{Custody: custody}), nil
}

func custodyVerificationError(err error) error {
	if errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationExpired) {
		return rpcreason.Error(connect.CodePermissionDenied, "recent_step_up_required")
	}
	return MapErr(err)
}
