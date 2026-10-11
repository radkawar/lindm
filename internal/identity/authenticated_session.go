package identity

import (
	"context"

	"github.com/google/uuid"

	"lindm/internal/identity/identitydb"
)

// checkAuthenticatedSession runs after the caller locks the actor principal.
// Logout, account revocation and runtime-policy revocation use that same lock
// order, so a session cannot disappear between this check and commit.
func (s *Service) checkAuthenticatedSession(ctx context.Context, q *identitydb.Queries, actor uuid.UUID, browserOnly bool) error {
	proof, ok := ctx.Value(authenticatedSessionKey{}).(authenticatedSession)
	if !ok || proof.service != s || proof.actor != actor {
		return ErrAuthorizationDenied
	}
	session, err := q.GetSessionByTokenHash(ctx, proof.hash)
	if err != nil {
		return s.authorizationStoreError(err)
	}
	if session.PrincipalID != actor || session.RevokedAt.Valid || (browserOnly && session.Kind != "browser") || (session.Kind != "browser" && session.Kind != "cli") {
		return ErrAuthorizationDenied
	}
	now, err := s.authorizationTime(ctx, q)
	if err != nil {
		return err
	}
	created, createdOK := timeFrom(session.CreatedAt)
	idle, idleOK := timeFrom(session.IdleExpiresAt)
	absolute, absoluteOK := timeFrom(session.AbsoluteExpiresAt)
	if !createdOK || !idleOK || !absoluteOK || now.Before(created) || !now.Before(idle) || !now.Before(absolute) {
		return ErrAuthorizationExpired
	}
	return nil
}
