//go:build integration

package identity

import (
	"errors"
	"testing"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func TestLocalEnrollmentCanRestartAfterAbandonedPrompt(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	first, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: "abandoned password 123!"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword})
	if err != nil {
		t.Fatalf("abandoned prompt burned secret: %v", err)
	}
	account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.PasswordHash != "" {
		t.Fatal("begin durably set account password")
	}
	credentials, err := identitydb.New(pool).ListLocalCredentials(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 0 {
		t.Fatal("begin stored an authenticator")
	}
	if first.Token == second.Token || localChallenge(t, first) == localChallenge(t, second) {
		t.Fatal("restart reused unfinished ceremony")
	}
	oldBody, _ := auth.response(t, localChallenge(t, first), localTestOrigin, true, true, 0)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: first.Token, CredentialJson: string(oldBody)}, "enroll", "127.0.0.1:3456"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("replaced ceremony succeeded: %v", err)
	}
	body, _ := auth.response(t, localChallenge(t, second), localTestOrigin, true, true, 0)
	finish := &authv1.WebAuthnFinishRequest{Token: second.Token, CredentialJson: string(body)}
	if cookie, err := s.finishLocalCeremony(ctx, finish, "enroll", "127.0.0.1:3456"); err != nil || cookie != "" {
		t.Fatalf("restarted registration: %v", err)
	}
	account, err = identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(account.PasswordHash, localTestPassword) || verifyPassword(account.PasswordHash, "abandoned password 123!") {
		t.Fatal("registration did not commit only the successful password")
	}
	if _, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword}); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("successful registration did not consume secret: %v", err)
	}
	if _, err := s.finishLocalCeremony(ctx, finish, "enroll", "127.0.0.1:3456"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("successful finish replay accepted: %v", err)
	}
	_ = loginLocal(t, s, ctx, "owner", "", auth)
}

func TestLocalEnrollmentFailedVerificationPreservesSecret(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	challenge, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, false, 0)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "enroll", "127.0.0.1:3456"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("missing UV registration accepted: %v", err)
	}
	account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.PasswordHash != "" {
		t.Fatal("failed registration stored password")
	}
	enrollLocal(t, s, ctx, enrollment, auth)
}

func TestLocalEnrollmentSecretExpiryRecheckedAtFinish(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	challenge, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE local_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE account_id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "enroll", "127.0.0.1:3456"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("expired secret accepted at finish: %v", err)
	}
	account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := identitydb.New(pool).ListLocalCredentials(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.PasswordHash != "" || len(credentials) != 0 {
		t.Fatal("expired secret committed enrollment material")
	}
}
