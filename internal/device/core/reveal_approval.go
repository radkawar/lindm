package core

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
)

// RevealApprovalDecision decides, for this caller at request time, whether revealing
// custody material guarded by permission needs an independent approver. target
// is the device whose recovery key or local-admin password is revealed, or
// uuid.Nil for a deployment-global secret. In order: the escrow server setting
// and the authorization policy always require approval; otherwise approval is
// required exactly when another human could give it. Reveal handlers call this
// on every request and never trust a client's copy of the decision.
func (s *Service) RevealApprovalDecision(ctx context.Context, actor identity.Principal, permission identity.Permission, target uuid.UUID) (*adminv1.RevealApproval, error) {
	switch {
	case s.RevealApproval:
		return &adminv1.RevealApproval{Required: true, Rule: adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_SERVER_SETTING}, nil
	case actor.ApprovalRequired(permission):
		return &adminv1.RevealApproval{Required: true, Rule: adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_AUTHORIZATION_POLICY}, nil
	case s.Identity == nil:
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	other, err := s.Identity.OtherApproverAvailable(ctx, actor.ID, permission, target, approverVisible)
	if err != nil {
		return nil, ApprovalError(err)
	}
	if other {
		return &adminv1.RevealApproval{Required: true, Rule: adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ANOTHER_APPROVER}, nil
	}
	return &adminv1.RevealApproval{Rule: adminv1.RevealApprovalRule_REVEAL_APPROVAL_RULE_ONLY_APPROVER}, nil
}

// CallerRevealApproval is RevealApprovalDecision for a read projection: nil
// when the caller's own grant for permission does not reach target, so the
// console never offers a reveal the server would refuse anyway.
func (s *Service) CallerRevealApproval(ctx context.Context, q *devicedb.Queries, actor identity.Principal, permission identity.Permission, target uuid.UUID) (*adminv1.RevealApproval, error) {
	if target == uuid.Nil {
		if unrestricted, _ := identity.DeviceScopes(actor, permission); !unrestricted {
			return nil, nil
		}
	} else if !identity.Authorize(actor, permission) {
		return nil, nil
	} else if err := RequireDeviceScope(ctx, q, actor, permission, target); errors.Is(err, ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, MapErr(err)
	}
	return s.RevealApprovalDecision(ctx, actor, permission, target)
}

// RequireRevealApproval refuses a reveal without an approval ID when the
// request-time decision requires one. A supplied approval is always consumed.
func (s *Service) RequireRevealApproval(ctx context.Context, actor identity.Principal, permission identity.Permission, target uuid.UUID, approvalID string) error {
	if approvalID != "" {
		return nil
	}
	decision, err := s.RevealApprovalDecision(ctx, actor, permission, target)
	if err != nil {
		return err
	}
	if decision.GetRequired() {
		return ApprovalError(identity.ErrApprovalRequired)
	}
	return nil
}

// approverVisible mirrors ApprovalScope without locking the device row: a
// device target must be inside the grant's scope, a global one needs an
// unrestricted grant.
func approverVisible(ctx context.Context, tx pgx.Tx, principal identity.Principal, permission identity.Permission, target uuid.UUID) (bool, error) {
	if target == uuid.Nil {
		unrestricted, _ := identity.DeviceScopes(principal, permission)
		return unrestricted, nil
	}
	err := RequireDeviceScope(ctx, devicedb.New(tx), principal, permission, target)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
