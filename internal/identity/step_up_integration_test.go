//go:build integration

package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func TestRecentStepUpRequiresVerifiedLocalBrowserSession(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	owner, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, owner, auth)
	cookie := loginLocal(t, s, ctx, "owner", "", auth)
	if err := s.RequireRecentStepUp(WithPrincipal(ctx, Principal{ID: owner.AccountID, Role: RoleOwner}), 5*time.Minute); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("WithPrincipal forged assurance: %v", err)
	}
	var proof context.Context
	request := httptest.NewRequest(http.MethodGet, localTestOrigin+"/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	response := httptest.NewRecorder()
	s.RequireSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { proof = r.Context() })).ServeHTTP(response, request)
	if proof == nil {
		t.Fatalf("middleware did not authenticate local session: %d", response.Code)
	}
	if err := s.RequireRecentStepUp(proof, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecentStepUp(proof, 0); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatal("nonpositive freshness window accepted")
	}
	if _, err := pool.Exec(ctx, "UPDATE sessions SET created_at=created_at-interval '6 minutes',last_seen_at=last_seen_at-interval '6 minutes',idle_expires_at=idle_expires_at-interval '6 minutes',absolute_expires_at=absolute_expires_at-interval '6 minutes' WHERE token_hash=$1", sessionHash(cookie)); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecentStepUp(proof, time.Hour); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("caller extended five-minute limit: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE sessions SET kind='cli' WHERE token_hash=$1", sessionHash(cookie)); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecentStepUp(proof, 5*time.Minute); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("CLI issuance became step-up: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE sessions SET kind='browser',revoked_at=clock_timestamp() WHERE token_hash=$1", sessionHash(cookie)); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecentStepUp(proof, 5*time.Minute); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("revoked session proof accepted: %v", err)
	}
}

func TestRecentStepUpRejectsDirectoryAndServiceActors(t *testing.T) {
	svc, ctx, _ := integrationService(t)
	actor := insertObservedPrincipal(t, ctx, svc, uuid.New())
	cookie := insertLiveSession(t, ctx, svc, actor.ID)
	proof := svc.withAuthenticatedSession(ctx, cookie, Principal{ID: actor.ID, Role: RoleOwner})
	if err := svc.RequireRecentStepUp(proof, 5*time.Minute); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("OIDC session issuance accepted as WebAuthn: %v", err)
	}
	s, ctx, pool := localIntegrationService(t)
	owner, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, owner, auth)
	cookie = loginLocal(t, s, ctx, "owner", "", auth)
	proof = s.withAuthenticatedSession(ctx, cookie, Principal{ID: owner.AccountID, Role: RoleOwner})
	if _, err := pool.Exec(ctx, "UPDATE principals SET service_account=true WHERE id=$1", owner.AccountID); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecentStepUp(proof, 5*time.Minute); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("persisted service actor accepted: %v", err)
	}
	row, err := identitydb.New(pool).GetPrincipalByID(ctx, owner.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.readLocalSnapshot(ctx, identitydb.New(pool), row)
	if err != nil {
		t.Fatal(err)
	}
	if !s.snapshotPrincipal(snapshot, RoleOwner).ServiceAccount {
		t.Fatal("local refresh erased durable service-account classification")
	}
}

// An aged session regains recent verification through the in-page step-up
// (password, then passkey) without a new session; the ceremony only completes
// on the session that began it, and a wrong password counts toward lockout.
func TestInPageStepUpRenewsTheSameSession(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	owner, err := s.BootstrapLocalOwner(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, owner, auth)
	cookie := loginLocal(t, s, ctx, "owner", "", auth)
	if _, err := pool.Exec(ctx, "UPDATE sessions SET created_at=created_at-interval '6 minutes',last_seen_at=last_seen_at-interval '6 minutes',idle_expires_at=idle_expires_at-interval '6 minutes',absolute_expires_at=absolute_expires_at-interval '6 minutes' WHERE token_hash=$1", sessionHash(cookie)); err != nil {
		t.Fatal(err)
	}
	var proof context.Context
	request := httptest.NewRequest(http.MethodGet, localTestOrigin+"/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	s.RequireSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { proof = r.Context() })).ServeHTTP(httptest.NewRecorder(), request)
	if proof == nil {
		t.Fatal("middleware did not authenticate the local session")
	}
	if err := s.RequireRecentStepUp(proof, 5*time.Minute); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("aged session still counts as recent: %v", err)
	}
	if _, err := s.beginLocalStepUp(proof, &authv1.LocalStepUpRequest{Password: "incorrect password 123"}, "127.0.0.1:1"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("wrong step-up password: %v", err)
	}
	account, err := identitydb.New(pool).GetLocalAccount(ctx, owner.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.FailedAttempts != 1 {
		t.Fatalf("wrong step-up password did not count toward lockout: %d", account.FailedAttempts)
	}
	finish := func(proof context.Context, challenge *authv1.WebAuthnChallenge, counter uint32) error {
		body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, false, true, counter)
		return s.finishLocalStepUp(proof, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "127.0.0.1:1")
	}
	challenge, err := s.beginLocalStepUp(proof, &authv1.LocalStepUpRequest{Password: localTestPassword}, "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := PrincipalFromContext(proof)
	other := s.withAuthenticatedSession(ctx, "another browser session token", principal)
	if err := finish(other, challenge, 2); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("step-up finished on another session: %v", err)
	}
	challenge, err = s.beginLocalStepUp(proof, &authv1.LocalStepUpRequest{Password: localTestPassword}, "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := finish(proof, challenge, 3); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRecentStepUp(proof, 5*time.Minute); err != nil {
		t.Fatalf("step-up did not renew recent verification: %v", err)
	}
	if err := finish(proof, challenge, 4); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("step-up assertion replayed: %v", err)
	}
	var sessions, failures int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM sessions WHERE revoked_at IS NULL),(SELECT failed_attempts FROM local_accounts WHERE id=$1)", owner.AccountID).Scan(&sessions, &failures); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || failures != 0 {
		t.Fatalf("step-up changed sessions (%d live) or kept failures (%d)", sessions, failures)
	}
}
