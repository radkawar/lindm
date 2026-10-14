// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"net"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

var errSetupRateLimited = errors.New("identity: setup_rate_limited")

// IssueSetupCode rotates the hash-only first-run capability before initialization.
// It needs only the migration database connection, never runtime signing keys.
// A pending identity/password survives rotation, including expiry recovery.
func IssueSetupCode(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	if pool == nil {
		return "", errInvalidConfig
	}
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	deployment, err := q.LockDeploymentIdentity(ctx)
	if err != nil {
		return "", err
	}
	if deployment.InitializedAt.Valid || deployment.OwnerPrincipalID != nil {
		return "", ErrOwnerInitialized
	}
	if err = q.IssueSetupCode(ctx, setupHash(code)); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return code, nil
}

func setupHash(code string) []byte {
	return domainHash("lindm.first_run.code.v1", code)
}

// Admission happens before password work and persists across restarts/replicas.
// Only RemoteAddr is used: forwarding headers cannot mint new client buckets.
func (s *Service) admitSetup(ctx context.Context, remote string) error {
	q := identitydb.New(s.pool)
	if err := q.PurgeSetupAttempts(ctx); err != nil {
		return s.dbErr(err)
	}
	if _, err := q.AdmitSetupAttempt(ctx, identitydb.AdmitSetupAttemptParams{
		BucketHash: domainHash("lindm.first_run.rate.v1", "global"), MaxAttempts: 60,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errSetupRateLimited
		}
		return s.dbErr(err)
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return errUnauthenticated
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errUnauthenticated
	}
	if _, err = q.AdmitSetupAttempt(ctx, identitydb.AdmitSetupAttemptParams{
		BucketHash: domainHash("lindm.first_run.rate.v1", "client:"+ip.String()), MaxAttempts: 10,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errSetupRateLimited
		}
		return s.dbErr(err)
	}
	return nil
}

// beginSetup reserves exactly one identity with the installer capability. Once
// reserved, even possession of that capability cannot change username/password.
// Completion consumes it atomically with UV registration and owner initialization.
func (s *Service) beginSetup(ctx context.Context, request *authv1.FirstRunSetupRequest) (*authv1.WebAuthnChallenge, error) {
	if !s.localPrimary {
		return nil, errUnauthenticated
	}
	digest := setupHash(request.GetCode())
	initial, err := identitydb.New(s.pool).FindSetupCode(ctx, digest)
	if err != nil {
		return nil, errUnauthenticated
	}
	var password string
	if initial == nil {
		password, err = s.hashLocalPassword(ctx, request.GetPassword())
	} else {
		account, readErr := identitydb.New(s.pool).GetLocalAccount(ctx, *initial)
		if readErr != nil {
			return nil, s.dbErr(readErr)
		}
		ok, verifyErr := s.verifyLocalPassword(ctx, account.PasswordHash, request.GetPassword())
		if verifyErr != nil {
			return nil, verifyErr
		}
		if !ok || account.Username != request.GetUsername() {
			return nil, errUnauthenticated
		}
		password = account.PasswordHash
	}
	if err != nil {
		return nil, err
	}
	var challenge *authv1.WebAuthnChallenge
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		deployment, err := q.LockDeploymentIdentity(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if deployment.InitializedAt.Valid || deployment.OwnerPrincipalID != nil {
			return errUnauthenticated
		}
		bound, err := q.FindSetupCode(ctx, digest)
		if err != nil {
			return errUnauthenticated
		}
		if bound == nil {
			id, err := s.createLocalIdentity(ctx, q, &authv1.CreateAccountRequest{Username: request.GetUsername(), Role: RoleOwner})
			if err != nil {
				return err
			}
			if err = q.SetLocalPassword(ctx, identitydb.SetLocalPasswordParams{ID: id, PasswordHash: password}); err != nil {
				return s.dbErr(err)
			}
			changed, err := q.BindSetupAccount(ctx, identitydb.BindSetupAccountParams{AccountID: &id, CodeHash: digest})
			if err != nil {
				return s.dbErr(err)
			}
			if changed != 1 {
				return errUnauthenticated
			}
			bound = &id
		} else if initial == nil || *bound != *initial {
			// Another first submission won while this request hashed its password.
			// Restart with the reserved credentials; never rebind on a race.
			return errUnauthenticated
		}
		principal, err := q.GetPrincipalForUpdate(ctx, *bound)
		if err != nil {
			return s.dbErr(err)
		}
		account, err := q.GetLocalAccount(ctx, *bound)
		if err != nil {
			return s.dbErr(err)
		}
		if !account.Enabled || account.Username != request.GetUsername() || account.PasswordHash != password {
			return errUnauthenticated
		}
		user, err := s.localUser(ctx, q, account)
		if err != nil {
			return err
		}
		options, session, err := s.webauthn.BeginRegistration(user, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}))
		if err != nil {
			return errUnauthenticated
		}
		challenge, err = s.persistCeremony(ctx, q, principal, "enroll", session, options.Response, password, "", digest, nil, true, nil)
		return err
	})
	return challenge, err
}
