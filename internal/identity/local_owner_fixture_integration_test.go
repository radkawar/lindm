// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"context"
	"testing"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

// bootstrapLocalOwner completes the real protected first-run ceremony. Tests of
// invitation/reset behavior then use the ordinary credential reset domain to
// arrange an invitation for that already initialized owner. It never binds an
// owner without user-verifying registration or preserves the removed CLI bypass.
func bootstrapLocalOwner(t *testing.T, s *Service, ctx context.Context, username string) (Enrollment, error) {
	t.Helper()
	code, err := IssueSetupCode(ctx, s.pool)
	if err != nil {
		return Enrollment{}, err
	}
	challenge, err := s.beginSetup(ctx, &authv1.FirstRunSetupRequest{Code: code, Username: username, Password: localTestPassword})
	if err != nil {
		return Enrollment{}, err
	}
	auth := localAuthenticator(t)
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
	cookie, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "enroll", "127.0.0.1:3456")
	if err != nil {
		return Enrollment{}, err
	}
	principal, decision, err := s.resolve(ctx, cookie)
	if err != nil {
		return Enrollment{}, err
	}
	if decision.Kind != accessOK || principal.Role != RoleOwner {
		return Enrollment{}, errUnauthenticated
	}
	var enrollment Enrollment
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		if _, err := q.GetPrincipalForUpdate(ctx, principal.ID); err != nil {
			return s.dbErr(err)
		}
		var err error
		enrollment, err = s.resetLocalCredentials(ctx, q, principal.ID)
		return err
	})
	return enrollment, err
}
