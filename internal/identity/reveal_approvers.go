package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/identity/identitydb"
)

// ApproverVisibility reports, without taking locks, whether principal's grant
// for permission reaches target inside the caller-supplied read transaction.
// uuid.Nil names a deployment-global resource, which needs an unrestricted grant.
type ApproverVisibility func(ctx context.Context, tx pgx.Tx, principal Principal, permission Permission, target uuid.UUID) (bool, error)

// approverCandidatePage bounds each principal read; the scan stops at the
// first eligible approver.
const approverCandidatePage = 100

// OtherApproverAvailable reports whether a human other than requester holds
// standing authority to approve a request for permission on target: the same
// permission and approvals.manage, each reaching target, as DecideApproval
// would require.
//
// Standing authority is read from each principal's last committed state, not a
// fresh directory observation: an administrator who has not signed in recently
// still counts, while a disabled, deactivated or demoted one does not. Service
// accounts, the requester's own sessions (browser or CLI), local accounts that
// cannot sign in because they never enrolled a credential, and break-glass
// accounts never count. A break-glass account holds no standing authority
// outside an audited emergency session, so routine reveals never depend on
// unsealing one. The answer is advisory: it decides whether an approval is
// required, never who may approve; DecideApproval still fences the actual
// approver freshly.
func (s *Service) OtherApproverAvailable(ctx context.Context, requester uuid.UUID, permission Permission, target uuid.UUID, visible ApproverVisibility) (bool, error) {
	if s == nil || visible == nil || requester == uuid.Nil || !knownPermission(permission) {
		return false, ErrApprovalInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	issuers := []string{s.issuer}
	if s.localIssuer != "" && s.localIssuer != s.issuer {
		issuers = append(issuers, s.localIssuer)
	}
	after := uuid.Nil
	for {
		rows, err := q.ListApproverCandidates(ctx, identitydb.ListApproverCandidatesParams{After: after, Requester: requester, Issuers: issuers, LocalIssuer: s.localIssuer, PageSize: approverCandidatePage})
		if err != nil {
			return false, s.dbErr(err)
		}
		for _, row := range rows {
			eligible, err := s.standingApprover(ctx, tx, q, row, permission, target, visible)
			if err != nil || eligible {
				return eligible, err
			}
		}
		if len(rows) < approverCandidatePage {
			return false, nil
		}
		after = rows[len(rows)-1].ID
	}
}

// standingApprover is decideAccess without directory freshness, followed by the
// grant and scope checks lockApprovalPair applies to an approver.
func (s *Service) standingApprover(ctx context.Context, tx pgx.Tx, q *identitydb.Queries, row identitydb.Principal, permission Permission, target uuid.UUID, visible ApproverVisibility) (bool, error) {
	snapshot, err := s.readSnapshot(ctx, q, row)
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if snapshot.ServiceAccount || snapshot.BreakGlass || !snapshot.Qualified || !snapshot.Enabled || snapshot.Deactivated ||
		snapshot.Issuer == "" || snapshot.Issuer != s.accessIssuer(snapshot) || snapshot.Subject == "" {
		return false, nil
	}
	if snapshot.Local {
		account, err := q.GetLocalApproverAccount(ctx, row.ID)
		if err != nil {
			return false, s.dbErr(err)
		}
		if account.BreakGlass || !account.Enrolled {
			return false, nil
		}
	}
	principal := s.snapshotPrincipal(snapshot, snapshotRole(snapshot.policy, snapshot))
	grants := append([]Permission{permission, PermissionManageApprovals}, approvalPermissionRequirements[permission]...)
	for _, grant := range grants {
		if !Authorize(principal, grant) {
			return false, nil
		}
		reaches, err := visible(ctx, tx, principal, grant, target)
		if err != nil || !reaches {
			return false, err
		}
	}
	return true, nil
}
