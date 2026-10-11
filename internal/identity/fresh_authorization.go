package identity

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

const dispatchAuthorizationWindow = 30 * time.Second

var (
	ErrAuthorizationDenied  = errors.New("identity: authorization denied")
	ErrAuthorizationExpired = errors.New("identity: authorization expired")
	ErrAuthorizationChanged = errors.New("identity: authorization changed")
)

// Authorization is an opaque process-local approval for one actor and permission.
// It is not a serializable credential or a substitute for transaction fencing.
// Only AuthorizeFresh constructs usable values; LockAuthorization rechecks them.
// A start signer must also clip its grant expiry to ExpiresAt, never extend the
// observation's thirty-second residual authority by issuing a new full window.
type Authorization struct {
	service           *Service
	actorID           uuid.UUID
	role              string
	permission        Permission
	version           int64
	observedAt        time.Time
	expiresAt         time.Time
	monotonicDeadline time.Time
	breakGlass        bool
	principal         Principal
	bindingsDigest    []byte
}

func (a *Authorization) ActorID() uuid.UUID {
	if a == nil {
		return uuid.Nil
	}
	return a.actorID
}

func (a *Authorization) Version() uint64 {
	if a == nil || a.version <= 0 {
		return 0
	}
	return uint64(a.version)
}

// ApprovalRequired reads the policy captured with this authority. LockAuthorization
// must still fence the snapshot inside the mutation transaction.
func (a *Authorization) ApprovalRequired(permission Permission) bool {
	return a != nil && a.principal.ApprovalRequired(permission)
}

// Principal returns a detached copy of the authority captured by AuthorizeFresh.
// Target scope checks must use this principal and the fenced permission.
func (a *Authorization) Principal() Principal {
	if a == nil {
		return Principal{}
	}
	return clonePrincipal(a.principal)
}

func clonePrincipal(p Principal) Principal {
	p.AllowedPermissions = append([]string(nil), p.AllowedPermissions...)
	if p.Bindings != nil {
		bindings := make([]*authv1.RoleBinding, len(p.Bindings))
		for i, binding := range p.Bindings {
			bindings[i] = proto.CloneOf(binding)
		}
		p.Bindings = bindings
	}
	return p
}

// ExpiresAt also clips to remaining process-monotonic lifetime. A wall-clock
// rollback cannot create a longer signed start window from an older approval.
func (a *Authorization) ExpiresAt() time.Time {
	if a == nil || a.service == nil || a.monotonicDeadline.IsZero() {
		return time.Time{}
	}
	limit := a.service.clock().Add(time.Until(a.monotonicDeadline))
	if limit.Before(a.expiresAt) {
		return limit
	}
	return a.expiresAt
}

// AuthorizeFresh observes the authoritative directory anew, without the browser
// cache or an earlier singleflight. No transaction is held during that request.
// A denial still commits the observed revocation, authorization version and audit.
// Newer concurrently committed evidence wins over a delayed directory response.
func (s *Service) AuthorizeFresh(ctx context.Context, actorID uuid.UUID, permission Permission) (*Authorization, error) {
	if s == nil || s.pool == nil {
		return nil, errUnavailable
	}
	if actorID == uuid.Nil || !knownPermission(permission) {
		return nil, ErrAuthorizationDenied
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	row, err := identitydb.New(s.pool).GetPrincipalByID(ctx, actorID)
	if err != nil {
		return nil, s.authorizationStoreError(err)
	}
	subject := row.Subject
	if subject == "" || (row.Issuer != s.issuer && row.Issuer != s.localIssuer) {
		return nil, ErrAuthorizationDenied
	}
	monotonicDeadline := time.Now().Add(dispatchAuthorizationWindow)
	observation, err := s.observePrincipal(ctx, row.Issuer, subject)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, errStore) {
			return nil, err
		}
		return nil, ErrDirectoryUnavailable
	}
	var authorization *Authorization
	var denied error
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		snapshot, err := s.writeObservation(ctx, q, actorID, observation)
		if errors.Is(err, errStaleObservation) {
			// writeObservation already acquired the principal lock. Read all
			// components under that lock rather than assemble a mixed snapshot.
			current, loadErr := q.GetPrincipalForUpdate(ctx, actorID)
			if loadErr != nil {
				return s.authorizationStoreError(loadErr)
			}
			snapshot, err = s.readSnapshot(ctx, q, current)
		}
		if err != nil {
			return err
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		decision := decideAccess(now, s.accessIssuer(snapshot), snapshot.policy, snapshot)
		principal := s.snapshotPrincipal(snapshot, decision.Role)
		if decision.Kind != accessOK || !Authorize(principal, permission) {
			denied = ErrAuthorizationDenied
			if snapshot.BreakGlass {
				return s.insertSystemAudit(ctx, q, &actorID, "identity.break_glass_denied", principalResource(actorID), "permission denied: "+string(permission))
			}
			return nil
		}
		if snapshot.AuthorizationVersion <= 0 || snapshot.AuthorizationRole != decision.Role {
			denied = ErrAuthorizationChanged
			return nil
		}
		expires := snapshot.ObservedAt.Add(dispatchAuthorizationWindow)
		if snapshot.BreakGlass {
			deadline, err := q.ActiveBreakGlassDeadline(ctx, actorID)
			if err != nil {
				denied = ErrAuthorizationDenied
				return s.insertSystemAudit(ctx, q, &actorID, "identity.break_glass_denied", principalResource(actorID), "active emergency session required")
			}
			if deadline.Time.Before(expires) {
				expires = deadline.Time
			}
		}
		if snapshot.ObservedAt.Before(observation.AcquiredAt) || now.Before(snapshot.ObservedAt) || !now.Before(expires) {
			denied = ErrAuthorizationExpired
			return nil
		}
		digest, err := bindingsDigest(principal.Bindings)
		if err != nil {
			return err
		}
		authorization = &Authorization{
			service: s, actorID: actorID, role: decision.Role, permission: permission,
			version: snapshot.AuthorizationVersion, observedAt: snapshot.ObservedAt, expiresAt: expires,
			monotonicDeadline: monotonicDeadline,
			breakGlass:        snapshot.BreakGlass,
			principal:         clonePrincipal(principal),
			bindingsDigest:    digest,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if denied != nil {
		return nil, denied
	}
	return authorization, nil
}

// LockAuthorization fences a privileged mutation inside its caller-owned
// transaction. Lock order is policy, principal, then device, then action. No external
// call belongs in that transaction; commit or roll back promptly. This checks
// actor authority only: device, desired-head, recovery and lease fences remain
// the domain caller's responsibility. The required operation permission must
// match the approval; a read approval cannot gate a write. The lock remains held
// on return.
func (s *Service) LockAuthorization(ctx context.Context, tx pgx.Tx, authorization *Authorization, permission Permission) (result error) {
	defer func() {
		if result != nil && s != nil && authorization != nil && authorization.service == s && authorization.breakGlass {
			result = errors.Join(result, s.emergencyAudit(ctx, authorization.actorID, "identity.break_glass_denied", "", "worker authorization fence denied: "+string(permission)))
		}
	}()
	if s == nil || tx == nil || authorization == nil || authorization.service != s || authorization.actorID == uuid.Nil || authorization.version <= 0 || authorization.role == "" || authorization.permission != permission || !Authorize(authorization.principal, permission) {
		return ErrAuthorizationDenied
	}
	q := identitydb.New(tx)
	if err := s.lockPolicy(ctx, q); err != nil {
		return err
	}
	if authorization.principal.policy == nil {
		return ErrAuthorizationDenied
	}
	current, err := q.ReadRuntimeAuthorization(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	if !bytes.Equal(current.Digest, authorization.principal.policy.digest) {
		return ErrAuthorizationChanged
	}
	row, err := q.GetPrincipalForUpdate(ctx, authorization.actorID)
	if err != nil {
		return s.authorizationStoreError(err)
	}
	if row.Issuer != s.issuer && row.Issuer != s.localIssuer {
		return ErrAuthorizationDenied
	}
	if row.AuthorizationVersion != authorization.version {
		return ErrAuthorizationChanged
	}
	snapshot, err := s.readSnapshot(ctx, q, row)
	if err != nil {
		return err
	}
	now, err := s.authorizationTime(ctx, q)
	if err != nil {
		return err
	}
	if authorization.monotonicDeadline.IsZero() || !time.Now().Before(authorization.monotonicDeadline) {
		return ErrAuthorizationExpired
	}
	if authorization.observedAt.IsZero() || now.Before(authorization.observedAt) || now.Before(snapshot.ObservedAt) || !now.Before(authorization.expiresAt) || authorization.expiresAt.After(authorization.observedAt.Add(dispatchAuthorizationWindow)) || !authorization.expiresAt.After(authorization.observedAt) {
		return ErrAuthorizationExpired
	}
	decision := decideAccess(now, s.accessIssuer(snapshot), snapshot.policy, snapshot)
	principal := s.snapshotPrincipal(snapshot, decision.Role)
	if decision.Kind != accessOK || !Authorize(principal, authorization.permission) {
		return ErrAuthorizationDenied
	}
	if snapshot.BreakGlass {
		deadline, err := q.ActiveBreakGlassDeadline(ctx, authorization.actorID)
		if err != nil || !now.Before(deadline.Time) {
			return ErrAuthorizationDenied
		}
	}
	if decision.Role != authorization.role || snapshot.AuthorizationRole != authorization.role || snapshot.ObservedAt.Before(authorization.observedAt) || principal.ServiceAccount != authorization.principal.ServiceAccount {
		return ErrAuthorizationChanged
	}
	digest, err := bindingsDigest(principal.Bindings)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, authorization.bindingsDigest) {
		return ErrAuthorizationChanged
	}
	return nil
}

func (s *Service) authorizationTime(ctx context.Context, q *identitydb.Queries) (time.Time, error) {
	stamp, err := q.ReadAuthorizationClock(ctx)
	if err != nil {
		return time.Time{}, s.dbErr(err)
	}
	now, ok := timeFrom(stamp)
	if !ok {
		return time.Time{}, errStore
	}
	return now, nil
}

func (s *Service) authorizationStoreError(err error) error {
	mapped := s.dbErr(err)
	if errors.Is(mapped, errNotFound) {
		return ErrAuthorizationDenied
	}
	return mapped
}
