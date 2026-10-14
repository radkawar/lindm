// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

// CreateEnrollmentApproval records the inbox entry in the reservation transaction.
// The fresh authorization is obtained before opening that transaction; no directory
// I/O occurs while reservation locks are held. Only the typed enrollment action is
// accepted here, rather than exposing an unchecked generic approval insert.
func (s *Service) CreateEnrollmentApproval(ctx context.Context, tx pgx.Tx, authorization *Authorization, request *adminv1.ApprovePendingEnrollmentRequest, scope ApprovalScope) (uuid.UUID, error) {
	if s == nil || authorization == nil || request == nil || scope == nil || s.rules.Validate(request) != nil {
		return uuid.Nil, ErrApprovalInvalid
	}
	if authorization.Principal().ServiceAccount {
		return uuid.Nil, ErrAuthorizationDenied
	}
	binding, err := bindApproval(request)
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.LockAuthorization(ctx, tx, authorization, binding.permission); err != nil {
		return uuid.Nil, err
	}
	if err := scope(ctx, tx, authorization.Principal(), binding.permission, binding.target); err != nil {
		return uuid.Nil, err
	}
	actor := authorization.ActorID()
	q := identitydb.New(tx)
	row, err := q.InsertApproval(ctx, identitydb.InsertApprovalParams{ID: uuid.New(), RequesterID: actor, RequesterVersion: int64(authorization.Version()), Action: binding.action, Permission: string(binding.permission), DeviceID: &binding.target, MutationID: binding.mutation, Payload: binding.payload, PayloadSha256: binding.digest[:], LifetimeSeconds: 3600})
	if err != nil {
		return uuid.Nil, s.dbErr(err)
	}
	if err := s.insertSystemAudit(ctx, q, &actor, auditkind.ApprovalCreated, row.ID.String(), binding.action); err != nil {
		return uuid.Nil, err
	}
	return row.ID, nil
}
