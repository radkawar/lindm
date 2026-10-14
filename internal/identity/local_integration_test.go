// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
	"lindm/internal/rpcreason"
	"lindm/internal/testdb"
)

const localTestPassword = "correct local password 123!"
const localTestOrigin = "https://console.example.com:18444"

type rejectIdentityTransport struct{ t *testing.T }

func (r rejectIdentityTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("local-only startup contacted an IdP")
	return nil, errors.New("unexpected network")
}

func localIntegrationService(t *testing.T) (*Service, context.Context, *pgxpool.Pool) {
	t.Helper()
	pool, _ := testdb.Open(t)
	// The fixture lives for the test, not one shared login-operation deadline.
	// Policy cases each perform real password hashing before the next flow.
	ctx := t.Context()
	s, err := New(ctx, pool, Config{Local: true, PublicURL: localTestOrigin, HTTPClient: &http.Client{Transport: rejectIdentityTransport{t}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, ctx, pool
}
func localChallenge(t *testing.T, challenge *authv1.WebAuthnChallenge) string {
	t.Helper()
	var options struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(challenge.OptionsJson), &options); err != nil {
		t.Fatal(err)
	}
	if options.Challenge == "" {
		t.Fatal("missing challenge")
	}
	return options.Challenge
}
func enrollLocal(t *testing.T, s *Service, ctx context.Context, enrollment Enrollment, auth localSoftwareAuthenticator) {
	t.Helper()
	challenge, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
	request := &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}
	if cookie, err := s.finishLocalCeremony(ctx, request, "enroll", "127.0.0.1:3456"); err != nil || cookie != "" {
		t.Fatalf("enroll cookie=%t err=%v", cookie != "", err)
	}
	if _, err := s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword}); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("reused enrollment secret: %v", err)
	}
	if _, err := s.finishLocalCeremony(ctx, request, "enroll", "127.0.0.1:3456"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("registration replay: %v", err)
	}
}
func loginLocal(t *testing.T, s *Service, ctx context.Context, user, reason string, auth localSoftwareAuthenticator) string {
	t.Helper()
	var before int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE revoked_at IS NULL").Scan(&before); err != nil {
		t.Fatal(err)
	}
	challenge, err := s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: user, Password: localTestPassword, IncidentReason: reason}, "127.0.0.1:3456")
	if err != nil {
		t.Fatal(err)
	}
	var sessions int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE revoked_at IS NULL").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != before {
		t.Fatal("password-only step issued a session")
	}
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, false, true, 1)
	request := &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}
	cookie, err := s.finishLocalCeremony(ctx, request, "login", "127.0.0.1:3456")
	if err != nil || cookie == "" {
		t.Fatalf("login: %v", err)
	}
	if _, err := s.finishLocalCeremony(ctx, request, "login", "127.0.0.1:3456"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("assertion replay: %v", err)
	}
	return cookie
}
func TestLocalAuthenticationLifecycle(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapLocalOwner(t, s, ctx, "owner"); !errors.Is(err, ErrOwnerInitialized) {
		t.Fatalf("second bootstrap: %v", err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	cookie := loginLocal(t, s, ctx, "owner", "", auth)
	principal, decision, err := s.resolve(ctx, cookie)
	if err != nil || decision.Kind != accessOK || principal.Role != RoleOwner {
		t.Fatalf("resolve: %v %v", decision, err)
	}
	if principal.Issuer != s.localIssuer || principal.Subject != enrollment.AccountID.String() {
		t.Fatal("local principal namespace binding lost")
	}
	authorization, err := s.AuthorizeFresh(ctx, principal.ID, PermissionManageAccounts)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.LockAuthorization(ctx, tx, authorization, PermissionManageAccounts); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		if _, err := q.GetPrincipalForUpdate(ctx, principal.ID); err != nil {
			return err
		}
		if err := q.UpdateLocalAccount(ctx, identitydb.UpdateLocalAccountParams{ID: principal.ID, Role: RoleOwner, Enabled: false, ScopeBinding: []byte("{}")}); err != nil {
			return err
		}
		return s.invalidateLocalAccount(ctx, q, principal.ID, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, decision, err = s.resolve(ctx, cookie); err != nil || decision.Kind != accessUnauthenticated {
		t.Fatalf("disabled session: %v %v", decision, err)
	}
	if _, err = s.AuthorizeFresh(ctx, principal.ID, PermissionReadFleet); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("disabled fresh approval: %v", err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = s.LockAuthorization(ctx, tx, authorization, PermissionManageAccounts); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("disabled old approval: %v", err)
	}
}

// A wrong password and an unknown username are refused identically, with one
// stable reason the console turns into "Username or password is incorrect."
func TestLocalLoginRefusalReasonIsUniform(t *testing.T) {
	s, ctx, _ := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	enrollLocal(t, s, ctx, enrollment, localAuthenticator(t))
	type refusal struct {
		status int
		reason string
		body   string
	}
	begin := func(username, password string) refusal {
		t.Helper()
		body, err := protojson.Marshal(&authv1.LocalLoginRequest{Username: username, Password: password})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequestWithContext(ctx, http.MethodPost, localTestOrigin+"/auth/local/login/begin", bytes.NewReader(body))
		request.Header.Set("Origin", localTestOrigin)
		recorder := httptest.NewRecorder()
		s.handleLocalLoginBegin(recorder, request)
		return refusal{recorder.Code, recorder.Header().Get(rpcreason.Header), recorder.Body.String()}
	}
	wrong := begin("owner", "incorrect password 123")
	unknown := begin("nobody", localTestPassword)
	if wrong.status != http.StatusUnauthorized || wrong.reason != "invalid_credentials" {
		t.Fatalf("wrong password: %+v", wrong)
	}
	if unknown != wrong {
		t.Fatalf("unknown user %+v differs from wrong password %+v", unknown, wrong)
	}
}
func TestLocalEnrollmentExpiryAndLockout(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE local_enrollments SET expires_at = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.beginLocalEnrollment(ctx, &authv1.LocalEnrollmentRequest{Secret: enrollment.Secret, Password: localTestPassword}); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("expired enrollment: %v", err)
	}
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		var err error
		enrollment, err = s.resetLocalCredentials(ctx, q, enrollment.AccountID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	for range 5 {
		if _, err = s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "owner", Password: "incorrect password 123"}, "127.0.0.1:1"); !errors.Is(err, errUnauthenticated) {
			t.Fatal(err)
		}
	}
	if _, err = s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "owner", Password: localTestPassword}, "127.0.0.1:1"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("locked password accepted: %v", err)
	}
	account, err := identitydb.New(pool).GetLocalAccount(ctx, enrollment.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if !account.LockedUntil.Valid || account.FailedAttempts != 5 {
		t.Fatal("lockout not durable")
	}
	if _, err = s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "unknown", Password: localTestPassword}, "127.0.0.1:1"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("unknown account: %v", err)
	}
	if _, err = pool.Exec(ctx, "UPDATE local_accounts SET locked_until=now()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	challenge, err := s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "owner", Password: localTestPassword}, "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE local_ceremonies SET expires_at=now()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, false, true, 1)
	if _, err = s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "login", "127.0.0.1:1"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("expired challenge: %v", err)
	}
}
func TestBreakGlassAuthorityAndAudit(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "emergency")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	s.localPrimary = false
	s.issuer = "https://unavailable.example/realms/lindm"
	s.breakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionReadFleet)}, ConsoleOnly: true, MaxSessionLifetime: durationpb.New(5 * time.Minute), RequireIncidentReason: true}
	if _, err = pool.Exec(ctx, "UPDATE local_accounts SET break_glass=true WHERE id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ reason, remote string }{{"", "127.0.0.1:1"}, {"incident 123", "192.0.2.1:1"}} {
		if _, err = s.beginLocalLogin(ctx, &authv1.LocalLoginRequest{Username: "emergency", Password: localTestPassword, IncidentReason: test.reason}, test.remote); !errors.Is(err, errUnauthenticated) {
			t.Fatalf("boundary accepted: %v", err)
		}
	}
	cookie := loginLocal(t, s, ctx, "emergency", "incident 123", auth)
	principal, decision, err := s.resolve(ctx, cookie)
	if err != nil || decision.Kind != accessOK || !principal.BreakGlass || principal.IncidentReason != "incident 123" {
		t.Fatalf("emergency principal: %v %v", decision, err)
	}
	if Authorize(principal, PermissionManageAccounts) || !Authorize(principal, PermissionReadFleet) {
		t.Fatal("emergency allowlist not enforced")
	}
	session, err := s.getSession(ctx, sessionHash(cookie))
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(session.Absolute) > 5*time.Minute {
		t.Fatal("emergency lifetime exceeded")
	}
	if _, err = s.AuthorizeFresh(ctx, principal.ID, PermissionManageAccounts); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("worker bypassed allowlist: %v", err)
	}
	authorization, err := s.AuthorizeFresh(ctx, principal.ID, PermissionReadFleet)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.LockAuthorization(ctx, tx, authorization, PermissionReadFleet); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://console.example.com/protected", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	s.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("protected denial status %d", response.Code)
	}
	if err = s.logout(ctx, cookie, principal.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizeFresh(ctx, principal.ID, PermissionReadFleet); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("terminated emergency has worker authority: %v", err)
	}
	for _, action := range []string{"identity.break_glass_activated", "identity.break_glass_used", "identity.break_glass_denied", "identity.break_glass_terminated"} {
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action=$1", action).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Errorf("missing durable audit %s", action)
		}
	}
}

// An emergency operator's approval inbox takes one break-glass observation and
// denial audit per inbox permission, each inside its own observation timeout.
// A slow store whose total exceeds the shared round wait must not fail it.
func TestBreakGlassInboxObservationsEachGetTheirOwnTimeout(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "emergency")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	s.localPrimary = false
	s.issuer = "https://unavailable.example/realms/lindm"
	s.breakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionRevokeDevice)}, ConsoleOnly: true, MaxSessionLifetime: durationpb.New(5 * time.Minute), RequireIncidentReason: true}
	if _, err = pool.Exec(ctx, "UPDATE local_accounts SET break_glass=true WHERE id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	principal, _, err := s.resolve(ctx, loginLocal(t, s, ctx, "emergency", "incident 123", auth))
	if err != nil || !principal.BreakGlass {
		t.Fatalf("emergency principal: %+v %v", principal, err)
	}
	// Every denied inbox permission commits its own break-glass denial audit.
	// Slow each audit write so their sum exceeds the round's shared wait while
	// each observation stays well inside its own timeout.
	denied := len(approvalInboxPermissions) - 1
	delay := 2*directoryFetchTimeout/time.Duration(denied) + 250*time.Millisecond
	if delay > directoryFetchTimeout/4 {
		t.Fatalf("audit delay %v leaves no headroom within the %v observation timeout", delay, directoryFetchTimeout)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION lindm_test_slow_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(%f); RETURN NEW; END $$`, delay.Seconds())); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER lindm_test_slow_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION lindm_test_slow_audit()`); err != nil {
		t.Fatal(err)
	}
	deniedAudits := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action=$1", "identity.break_glass_denied").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	before := deniedAudits()
	started := time.Now()
	if _, _, err := s.CountOpenApprovals(t.Context(), principal.ID); err != nil {
		t.Fatalf("emergency inbox count failed after %v: %v", time.Since(started), err)
	}
	if elapsed := time.Since(started); elapsed <= 2*directoryFetchTimeout {
		t.Fatalf("emergency inbox count took %v, within one shared round wait; the regression would prove nothing", elapsed)
	}
	if audits := deniedAudits() - before; audits != denied {
		t.Fatalf("break-glass denial audits = %d, want one per denied inbox permission (%d)", audits, denied)
	}
}

func TestLocalSessionCannotBecomeBreakGlass(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	enrollment, err := bootstrapLocalOwner(t, s, ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, auth)
	cookie := loginLocal(t, s, ctx, "owner", "", auth)
	if _, err := pool.Exec(ctx, "UPDATE local_accounts SET break_glass = true WHERE id = $1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	s.localPrimary = false
	s.issuer = "https://external.example/realms/lindm"
	s.breakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionReadFleet)}, MaxSessionLifetime: durationpb.New(time.Hour), RequireIncidentReason: true}
	if _, decision, err := s.resolve(ctx, cookie); err != nil || decision.Kind != accessUnauthenticated {
		t.Fatalf("normal session inherited emergency authority: %v %v", decision, err)
	}
	if _, err := s.AuthorizeFresh(ctx, enrollment.AccountID, PermissionReadFleet); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("normal session inherited emergency worker authority: %v", err)
	}
}
