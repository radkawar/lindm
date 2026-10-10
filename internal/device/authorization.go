package device

import (
	"context"
	"encoding/json"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

// deviceScopeFilter is the SQL representation of only the bindings granting perm.
// An empty array denies every device; unrestricted is an explicit separate grant.
func deviceScopeFilter(principal identity.Principal, perm identity.Permission) (bool, []byte, error) {
	unrestricted, scopes := identity.DeviceScopes(principal, perm)
	if unrestricted || len(scopes) == 0 {
		return unrestricted, []byte("[]"), nil
	}
	encoded, err := json.Marshal(scopes)
	if err != nil {
		return false, nil, err
	}
	return false, encoded, nil
}

func requireUnrestrictedPrincipal(principal identity.Principal, perm identity.Permission) error {
	unrestricted, _ := identity.DeviceScopes(principal, perm)
	if !unrestricted {
		return rpcError(connect.CodePermissionDenied, "permission_denied")
	}
	return nil
}

// requireUnrestricted protects global resources that cannot be partitioned by a
// device scope, including enrollment, profile catalogs and the global audit log.
func (s *Service) requireUnrestricted(ctx context.Context, perm identity.Permission) (identity.Principal, error) {
	principal, err := s.require(ctx, perm)
	if err != nil {
		return identity.Principal{}, err
	}
	if err := requireUnrestrictedPrincipal(principal, perm); err != nil {
		return identity.Principal{}, err
	}
	return principal, nil
}

// requireDeviceScope deliberately gives the same error for an absent target and
// a target outside the caller's authority. Read callers use their read snapshot;
// mutation callers must first lock the device and use Authorization.Principal.
func requireDeviceScope(ctx context.Context, q *devicedb.Queries, principal identity.Principal, perm identity.Permission, deviceID uuid.UUID) error {
	unrestricted, scopes, err := deviceScopeFilter(principal, perm)
	if err != nil {
		return err
	}
	visible, err := q.DeviceInScope(ctx, devicedb.DeviceInScopeParams{
		ID: deviceID, ScopeUnrestricted: unrestricted, Scopes: scopes,
	})
	if err != nil {
		return err
	}
	if !visible {
		return errNotFound
	}
	return nil
}

// lockDeviceScope follows the principal-before-device lock order. Metadata and
// membership writers must also lock the device row so scope cannot change between
// this check and the mutation's commit.
func lockDeviceScope(ctx context.Context, q *devicedb.Queries, principal identity.Principal, perm identity.Permission, deviceID uuid.UUID) (devicedb.GetDeviceForUpdateRow, error) {
	row, err := q.GetDeviceForUpdate(ctx, deviceID)
	if err != nil {
		return devicedb.GetDeviceForUpdateRow{}, notFoundIfMissing(err)
	}
	if err := requireDeviceScope(ctx, q, principal, perm, deviceID); err != nil {
		return devicedb.GetDeviceForUpdateRow{}, err
	}
	return row, nil
}

// withinUnrestrictedAuthorization refreshes before opening a transaction, then
// fences both entry and commit. No cached request principal authorizes a write.
func (s *Service) withinUnrestrictedAuthorization(ctx context.Context, actor identity.Principal, perm identity.Permission, fn func(context.Context, *devicedb.Queries) error) error {
	if s.identity == nil {
		return rpcError(connect.CodeFailedPrecondition, "authorization_unavailable")
	}
	authorization, err := s.identity.AuthorizeFresh(ctx, actor.ID, perm)
	if err != nil {
		return executionError(err)
	}
	if err := requireUnrestrictedPrincipal(authorization.Principal(), perm); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, authorization, perm); err != nil {
		return executionError(err)
	}
	if err := fn(ctx, devicedb.New(tx)); err != nil {
		return err
	}
	if err := s.identity.LockAuthorization(ctx, tx, authorization, perm); err != nil {
		return executionError(err)
	}
	return tx.Commit(ctx)
}

func (s *Service) approvalScope(ctx context.Context, tx pgx.Tx, principal identity.Principal, perm identity.Permission, target uuid.UUID) error {
	if target == uuid.Nil {
		return requireUnrestrictedPrincipal(principal, perm)
	}
	_, err := lockDeviceScope(ctx, devicedb.New(tx), principal, perm, target)
	if err != nil {
		return err
	}
	if perm == identity.PermissionManageEnrollment {
		receipt, err := devicedb.New(tx).GetProvisioningEnrollmentForDevice(ctx, target)
		if err == pgx.ErrNoRows {
			// Reservation creates its approval before inserting the receipt.
			return requireUnrestrictedPrincipal(principal, perm)
		}
		if err != nil {
			return err
		}
		token, err := devicedb.New(tx).GetProvisioningToken(ctx, receipt.TokenID)
		if err != nil {
			return err
		}
		if receipt.State != "ready" {
			if receipt.State != "pending_approval" || !s.now().Before(receipt.ExpiresAt.Time) {
				return approvalError(identity.ErrApprovalInvalid)
			}
			if err := provisioningTokenUsable(token, s.now()); err != nil {
				return err
			}
		}
		assignment, err := provisioningAssignment(token)
		if err != nil {
			return err
		}
		return provisioningAssignmentAuthority(principal, assignment)
	}
	return nil
}
