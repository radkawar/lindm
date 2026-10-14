// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
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
// browser authentication: the session's sign-in or its in-page step-up. OIDC login time and CLI token issuance do not establish
// that assurance. WithPrincipal cannot manufacture the private middleware proof.
// This does not replace permission, target-scope, or mutation transaction fences.
func (s *Service) RequireRecentStepUp(ctx context.Context, maxAge time.Duration) error {
	proof, err := s.stepUpProof(ctx)
	if err != nil || maxAge <= 0 {
		return ErrAuthorizationDenied
	}
	return s.withTx(ctx, func(q *identitydb.Queries) error {
		return s.requireRecentStepUp(ctx, q, proof, maxAge, nil)
	})
}

// LockRecentStepUpForCustody requires a new password + UV ceremony for this exact
// encrypted bundle. Call after LockAuthorization; principal/session locks remain
// held through the caller's attestation/audit commit. Sign-in cannot qualify.
func (s *Service) LockRecentStepUpForCustody(ctx context.Context, tx pgx.Tx, digest []byte) error {
	proof, err := s.stepUpProof(ctx)
	if err != nil || len(digest) != 32 {
		return ErrAuthorizationDenied
	}
	return s.requireRecentStepUp(ctx, identitydb.New(tx), proof, 5*time.Minute, digest)
}

func (s *Service) requireRecentStepUp(ctx context.Context, q *identitydb.Queries, proof authenticatedSession, maxAge time.Duration, custodyDigest []byte) error {
	if maxAge > 5*time.Minute {
		maxAge = 5 * time.Minute
	}
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
	session, err := q.GetSessionForUpdate(ctx, proof.hash)
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
	verified := created
	if stepped, ok := timeFrom(session.SteppedUpAt); ok && stepped.After(verified) {
		verified = stepped
	}
	if !valid || !idleValid || !absoluteValid || now.Before(created) || now.Before(verified) || now.Sub(verified) > maxAge || !now.Before(idle) || !now.Before(absolute) {
		return ErrAuthorizationExpired
	}
	if len(custodyDigest) != 0 {
		scopedAt, scopedValid := timeFrom(session.RecoveryCustodyStepUpAt)
		if !bytes.Equal(session.RecoveryCustodyStepUpDigest, custodyDigest) || !scopedValid {
			return ErrAuthorizationDenied
		}
		if scopedAt.Before(created) || now.Before(scopedAt) || now.Sub(scopedAt) > maxAge {
			return ErrAuthorizationExpired
		}
	}
	return nil
}

// ConsumeRecoveryCustodyStepUp clears only this session's matching scoped grant,
// in the same transaction that records the owner attestation.
func (s *Service) ConsumeRecoveryCustodyStepUp(ctx context.Context, tx pgx.Tx, digest []byte) error {
	proof, err := s.stepUpProof(ctx)
	if err != nil || len(digest) != 32 {
		return ErrAuthorizationDenied
	}
	count, err := identitydb.New(tx).ConsumeRecoveryCustodyStepUp(ctx, identitydb.ConsumeRecoveryCustodyStepUpParams{TokenHash: proof.hash, PrincipalID: proof.actor, CustodyDigest: digest})
	if err != nil {
		return s.dbErr(err)
	}
	if count != 1 {
		return ErrAuthorizationDenied
	}
	return nil
}

// stepUpProof returns the private middleware proof of the caller's own local
// browser session, which only RequireSession can attach.
func (s *Service) stepUpProof(ctx context.Context) (authenticatedSession, error) {
	proof, ok := ctx.Value(authenticatedSessionKey{}).(authenticatedSession)
	principal, present := PrincipalFromContext(ctx)
	if s == nil || !ok || !present || proof.service != s || proof.actor != principal.ID || principal.ServiceAccount {
		return authenticatedSession{}, ErrAuthorizationDenied
	}
	return proof, nil
}

// beginLocalStepUp re-checks the signed-in local account's password, then
// starts a passkey assertion bound to this exact session. A wrong password,
// lockout or disabled account is errUnauthenticated (and counts toward
// lockout like sign-in); a session that cannot step up is ErrAuthorizationDenied.
func (s *Service) beginLocalStepUp(ctx context.Context, request *authv1.LocalStepUpRequest, remote string) (*authv1.WebAuthnChallenge, error) {
	proof, err := s.stepUpProof(ctx)
	if err != nil {
		return nil, err
	}
	custodyDigest, err := hex.DecodeString(request.GetRecoveryCustodyConfirmationDigest())
	if err != nil || (len(custodyDigest) != 0 && len(custodyDigest) != 32) {
		return nil, ErrAuthorizationDenied
	}
	initial, err := identitydb.New(s.pool).GetLocalAccount(ctx, proof.actor)
	if err != nil {
		if errors.Is(s.dbErr(err), errNotFound) {
			return nil, ErrAuthorizationDenied
		}
		return nil, s.dbErr(err)
	}
	encoded := initial.PasswordHash
	if encoded == "" {
		encoded = s.dummyHash
	}
	passwordOK, err := s.verifyLocalPassword(ctx, encoded, request.GetPassword())
	if err != nil {
		return nil, err
	}
	var challenge *authv1.WebAuthnChallenge
	denied := false
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		principal, err := q.GetPrincipalForUpdate(ctx, proof.actor)
		if err != nil {
			return s.authorizationStoreError(err)
		}
		if principal.Issuer != s.localIssuer || principal.ServiceAccount {
			return ErrAuthorizationDenied
		}
		session, err := q.GetSessionByTokenHash(ctx, proof.hash)
		if err != nil {
			return s.authorizationStoreError(err)
		}
		if session.PrincipalID != proof.actor || session.Kind != "browser" || session.RevokedAt.Valid {
			return ErrAuthorizationDenied
		}
		account, err := q.GetLocalAccount(ctx, proof.actor)
		if err != nil {
			return s.dbErr(err)
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		locked := account.LockedUntil.Valid && now.Before(account.LockedUntil.Time)
		eligible := s.localLoginAllowed(account, session.IncidentReason, remote) &&
			initial.PasswordHash != "" && account.PasswordHash == initial.PasswordHash
		if !passwordOK || !eligible || locked {
			denied = true
			if eligible && !locked && !passwordOK {
				if err = q.RecordLocalFailure(ctx, account.ID); err != nil {
					return s.dbErr(err)
				}
			}
			return s.insertSystemAudit(ctx, q, &account.ID, auditkind.IdentityStepUpDenied, principalResource(account.ID), "password verification denied")
		}
		user, err := s.localUser(ctx, q, account)
		if err != nil {
			return err
		}
		options, ceremony, err := s.webauthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return errUnauthenticated
		}
		challenge, err = s.persistCeremony(ctx, q, principal, "step_up", ceremony, options.Response, "", session.IncidentReason, nil, proof.hash, false, custodyDigest)
		return err
	})
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, errUnauthenticated
	}
	return challenge, nil
}

// finishLocalStepUp verifies the passkey assertion for the session that began
// the step-up and records the verification time on that session.
func (s *Service) finishLocalStepUp(ctx context.Context, request *authv1.WebAuthnFinishRequest, remote string) error {
	proof, err := s.stepUpProof(ctx)
	if err != nil {
		return err
	}
	_, err = s.finishCeremony(ctx, request, "step_up", remote, proof)
	return err
}

// completeStepUp stores the verified credential's updated state, clears
// failures and marks the still-live session as recently verified.
func (s *Service) completeStepUp(ctx context.Context, q *identitydb.Queries, proof authenticatedSession, accountID uuid.UUID, credentialID, credentialJSON, custodyDigest []byte) error {
	if err := q.UpdateLocalCredential(ctx, identitydb.UpdateLocalCredentialParams{CredentialID: credentialID, AccountID: accountID, CredentialJson: credentialJSON}); err != nil {
		return s.dbErr(err)
	}
	if err := q.ClearLocalFailures(ctx, accountID); err != nil {
		return s.dbErr(err)
	}
	marked, err := q.MarkSessionSteppedUp(ctx, identitydb.MarkSessionSteppedUpParams{TokenHash: proof.hash, PrincipalID: accountID, CustodyDigest: custodyDigest})
	if err != nil {
		return s.dbErr(err)
	}
	if marked != 1 {
		return errUnauthenticated
	}
	return s.insertAudit(ctx, q, &accountID, auditkind.IdentityStepUp, principalResource(accountID), "")
}
