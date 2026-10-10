package identity

import (
	"context"
	"time"

	"github.com/google/uuid"

	"lindm/internal/identity/identitydb"
)

type authenticatedSessionKey struct{}

type authenticatedSession struct {
	service *Service
	hash    []byte
	actor   uuid.UUID
}

func (s *Service) withAuthenticatedSession(ctx context.Context, token string, p Principal) context.Context {
	return context.WithValue(WithPrincipal(ctx, p), authenticatedSessionKey{}, authenticatedSession{service: s, hash: sessionHash(token), actor: p.ID})
}

// RequireRecentStepUp accepts only recent password + verified WebAuthn local
// browser authentication. OIDC login time and CLI token issuance do not establish
// that assurance. WithPrincipal cannot manufacture the private middleware proof.
// This does not replace permission, target-scope, or mutation transaction fences.
func (s *Service) RequireRecentStepUp(ctx context.Context, maxAge time.Duration) error {
	proof, ok := ctx.Value(authenticatedSessionKey{}).(authenticatedSession)
	principal, present := PrincipalFromContext(ctx)
	if s == nil || !ok || !present || proof.service != s || proof.actor != principal.ID || principal.ServiceAccount || maxAge <= 0 {
		return ErrAuthorizationDenied
	}
	if maxAge > 5*time.Minute {
		maxAge = 5 * time.Minute
	}
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		row, err := q.GetPrincipalForUpdate(ctx, proof.actor)
		if err != nil {
			return s.authorizationStoreError(err)
		}
		if row.Issuer != s.localIssuer || row.ServiceAccount {
			return ErrAuthorizationDenied
		}
		snapshot, err := s.readLocalSnapshot(ctx, q, row)
		if err != nil {
			return err
		}
		if !snapshot.Enabled || !snapshot.Qualified {
			return ErrAuthorizationDenied
		}
		session, err := q.GetSessionByTokenHash(ctx, proof.hash)
		if err != nil {
			return s.authorizationStoreError(err)
		}
		if session.PrincipalID != proof.actor || session.Kind != "browser" || session.RevokedAt.Valid || session.BreakGlass != snapshot.BreakGlass {
			return ErrAuthorizationDenied
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		created, valid := timeFrom(session.CreatedAt)
		idle, idleValid := timeFrom(session.IdleExpiresAt)
		absolute, absoluteValid := timeFrom(session.AbsoluteExpiresAt)
		if !valid || !idleValid || !absoluteValid || now.Before(created) || now.Sub(created) > maxAge || !now.Before(idle) || !now.Before(absolute) {
			return ErrAuthorizationExpired
		}
		return nil
	})
}
