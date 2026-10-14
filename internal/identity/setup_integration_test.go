// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

func setupRequest(code, username string) *authv1.FirstRunSetupRequest {
	return &authv1.FirstRunSetupRequest{Code: code, Username: username, Password: localTestPassword}
}

// Login-mode projection is pure, but /auth/options also reports durable setup
// state. Keep all advertised modes on the real database-backed HTTP boundary.
func TestAuthenticationOptionsAdvertiseConfiguredLocalLogin(t *testing.T) {
	for _, test := range authenticationModeTests {
		t.Run(test.name, func(t *testing.T) {
			s, ctx, pool := localIntegrationService(t)
			s.localPrimary = test.local
			if test.policy {
				s.breakGlass = &configv1.BreakGlassPolicy{}
			}
			assertOptions := func(setupAvailable bool) {
				t.Helper()
				recorder := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodGet, localTestOrigin+"/auth/options", nil).WithContext(ctx)
				s.Handler().ServeHTTP(recorder, request)
				options := &authv1.AuthenticationOptions{}
				if err := protojson.Unmarshal(recorder.Body.Bytes(), options); err != nil {
					t.Fatal(err)
				}
				if recorder.Code != http.StatusOK || options.ExternalLogin != test.external || options.LocalLogin != test.localLogin || options.BreakGlass != test.emergency || options.SetupAvailable != setupAvailable {
					t.Fatalf("incorrect configured login modes: status=%d external=%t local=%t emergency=%t setup=%t want_setup=%t", recorder.Code, options.ExternalLogin, options.LocalLogin, options.BreakGlass, options.SetupAvailable, setupAvailable)
				}
			}
			assertOptions(false)
			if _, err := IssueSetupCode(ctx, pool); err != nil {
				t.Fatal(err)
			}
			assertOptions(test.local)
			if _, err := pool.Exec(ctx, "UPDATE first_run_setup SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
				t.Fatal(err)
			}
			assertOptions(false)
			if test.local {
				code, err := IssueSetupCode(ctx, pool)
				if err != nil {
					t.Fatal(err)
				}
				assertOptions(true)
				challenge, err := s.beginSetup(ctx, setupRequest(code, "browser-owner"))
				if err != nil {
					t.Fatal(err)
				}
				auth := localAuthenticator(t)
				credential, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
				if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(credential)}, "enroll", "127.0.0.1:3456"); err != nil {
					t.Fatal(err)
				}
				assertOptions(false)
			}
		})
	}
}

func assertSetupUninitialized(t *testing.T, s *Service, ctx context.Context) {
	t.Helper()
	var initialized bool
	var credentials, sessions int
	if err := s.pool.QueryRow(ctx, "SELECT initialized_at IS NOT NULL FROM deployment_identity").Scan(&initialized); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM local_credentials").Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if initialized || credentials != 0 || sessions != 0 {
		t.Fatalf("setup leaked authority: initialized=%t credentials=%d sessions=%d", initialized, credentials, sessions)
	}
}

func TestSetupConcurrentReservationResumesOnlyBoundIdentity(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	q := identitydb.New(pool)
	if available, err := q.SetupAvailable(ctx); err != nil || available {
		t.Fatalf("setup without issued code: available=%t err=%v", available, err)
	}
	code, err := IssueSetupCode(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := pool.QueryRow(ctx, "SELECT code_hash FROM first_run_setup").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(code) != 43 || len(stored) != 32 || bytes.Contains(stored, []byte(code)) {
		t.Fatal("setup code entropy/hash storage contract failed")
	}
	if _, err := s.beginSetup(ctx, setupRequest(strings.Repeat("A", 43), "attacker")); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("unauthorized reservation: %v", err)
	}
	var wg sync.WaitGroup
	errorsByRequest := make([]error, 2)
	challenges := make([]*authv1.WebAuthnChallenge, 2)
	for i, name := range []string{"first-owner", "other-owner"} {
		wg.Add(1)
		go func(index int, username string) {
			defer wg.Done()
			challenges[index], errorsByRequest[index] = s.beginSetup(ctx, setupRequest(code, username))
		}(i, name)
	}
	wg.Wait()
	winner := -1
	for i, err := range errorsByRequest {
		if err == nil {
			if winner != -1 {
				t.Fatal("two identities reserved the same setup code")
			}
			winner = i
		} else if !errors.Is(err, errUnauthenticated) {
			t.Fatalf("concurrent setup refusal: %v", err)
		}
	}
	if winner == -1 {
		t.Fatal("neither authorized setup reserved its identity")
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM local_accounts").Scan(&count); err != nil || count != 1 {
		t.Fatalf("reserved account count=%d err=%v", count, err)
	}
	assertSetupUninitialized(t, s, ctx)
	names := []string{"first-owner", "other-owner"}
	if _, err := s.beginSetup(ctx, setupRequest(code, names[1-winner])); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("pending identity takeover: %v", err)
	}
	wrongPassword := setupRequest(code, names[winner])
	wrongPassword.Password = "different sufficiently long password"
	if _, err := s.beginSetup(ctx, wrongPassword); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("pending password takeover: %v", err)
	}
	if _, err := s.beginSetup(ctx, setupRequest(code, names[winner])); err != nil {
		t.Fatalf("same identity did not resume: %v", err)
	}
	request := &authv1.WebAuthnFinishRequest{Token: challenges[winner].Token, CredentialJson: "{}"}
	if _, err := s.finishLocalCeremony(ctx, request, "enroll", "127.0.0.1:10000"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("superseded ceremony replay: %v", err)
	}
	assertSetupUninitialized(t, s, ctx)
}

func TestSetupRequiresUVAndAtomicallyFinishesOnce(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	code, err := IssueSetupCode(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := s.beginSetup(ctx, setupRequest(code, "chosen-owner"))
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	body, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, false, 0)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "enroll", "127.0.0.1:10000"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("registration without user verification: %v", err)
	}
	assertSetupUninitialized(t, s, ctx)
	challenge, err = s.beginSetup(ctx, setupRequest(code, "chosen-owner"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
	finish := &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}
	var wg sync.WaitGroup
	cookies := make([]string, 2)
	results := make([]error, 2)
	for i := range cookies {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			cookies[index], results[index] = s.finishLocalCeremony(ctx, finish, "enroll", "127.0.0.1:10000")
		}(i)
	}
	wg.Wait()
	accepted := 0
	for i, err := range results {
		if err != nil {
			if !errors.Is(err, errUnauthenticated) {
				t.Fatalf("finish refusal: %v", err)
			}
			continue
		}
		accepted++
		principal, decision, err := s.resolve(ctx, cookies[i])
		if err != nil || decision.Kind != accessOK || principal.DisplayName != "chosen-owner" || principal.Role != RoleOwner {
			t.Fatalf("completed setup session: %v %v", decision, err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent completion requests", accepted)
	}
	if available, err := identitydb.New(pool).SetupAvailable(ctx); err != nil || available {
		t.Fatalf("setup remains available: available=%t err=%v", available, err)
	}
	if _, err := IssueSetupCode(ctx, pool); !errors.Is(err, ErrOwnerInitialized) {
		t.Fatalf("issuance after owner initialization: %v", err)
	}
	if _, err := s.beginSetup(ctx, setupRequest(code, "chosen-owner")); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("consumed setup code replay: %v", err)
	}
	var pinned bool
	if err := pool.QueryRow(ctx, "SELECT pinned_role='owner' FROM principals").Scan(&pinned); err != nil || !pinned {
		t.Fatalf("owner identity not pinned: pinned=%t err=%v", pinned, err)
	}
	restarted, err := newService(ctx, pool, Config{
		Local: true, PublicURL: localTestOrigin,
		InitialOwnerExecution: func(context.Context, pgx.Tx, uuid.UUID) error {
			return errors.New("completed deployment must never arm initial execution admission")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	if restarted.initialOwnerExecution != nil {
		t.Fatal("restart retained first-owner execution admission after initialization")
	}
}

func TestSetupExpiryRotationAndExecutionAdmissionRollback(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	code, err := IssueSetupCode(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.beginSetup(ctx, setupRequest(code, "reserved-owner"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE first_run_setup SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.beginSetup(ctx, setupRequest(code, "reserved-owner")); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("expired code: %v", err)
	}
	replacement, err := IssueSetupCode(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	body, _ := auth.response(t, localChallenge(t, original), localTestOrigin, true, true, 0)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: original.Token, CredentialJson: string(body)}, "enroll", "127.0.0.1:10000"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("old ceremony survived code rotation: %v", err)
	}
	if _, err := s.beginSetup(ctx, setupRequest(replacement, "replacement-owner")); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("rotation changed reserved identity: %v", err)
	}
	challenge, err := s.beginSetup(ctx, setupRequest(replacement, "reserved-owner"))
	if err != nil {
		t.Fatal(err)
	}
	admissionFailure := errors.New("signed execution delegation rejected")
	s.initialOwnerExecution = func(_ context.Context, _ pgx.Tx, actor uuid.UUID) error {
		if actor == uuid.Nil {
			t.Error("initial delegation had no bound owner")
		}
		return admissionFailure
	}
	body, _ = auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
	if _, err := s.finishLocalCeremony(ctx, &authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(body)}, "enroll", "127.0.0.1:10000"); !errors.Is(err, admissionFailure) {
		t.Fatalf("initial delegation rejection: %v", err)
	}
	assertSetupUninitialized(t, s, ctx)
	if available, err := identitydb.New(pool).SetupAvailable(ctx); err != nil || !available {
		t.Fatalf("admission rollback consumed setup: available=%t err=%v", available, err)
	}
	s.initialOwnerExecution = nil
	if _, err := s.beginSetup(ctx, setupRequest(replacement, "reserved-owner")); err != nil {
		t.Fatalf("admission failure prevented safe resume: %v", err)
	}
}

func TestSetupHTTPRejectsCSRFBoundsAndDurableRateAbuse(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	code, err := IssueSetupCode(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	body, err := protojson.Marshal(setupRequest(code, "http-owner"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, origin, header, contentType string }{
		{"cross origin", "https://attacker.example", "1", "application/json"},
		{"absent origin", "", "1", "application/json"},
		{"simple request", localTestOrigin, "", "application/json"},
		{"form request", localTestOrigin, "1", "application/x-www-form-urlencoded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/auth/setup/begin", bytes.NewReader(body))
			request.Header.Set("Origin", test.origin)
			request.Header.Set("X-Lindm-Setup", test.header)
			request.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()
			s.handleSetupBegin(recorder, request)
			if recorder.Code != http.StatusForbidden || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("CSRF/caching refusal: HTTP %d cache=%s", recorder.Code, recorder.Header().Get("Cache-Control"))
			}
		})
	}
	for attempt := range 11 {
		request := httptest.NewRequest(http.MethodPost, "/auth/setup/begin", strings.NewReader(strings.Repeat("x", 8193)))
		request.Header.Set("Origin", localTestOrigin)
		request.Header.Set("X-Lindm-Setup", "1")
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		s.handleSetupBegin(recorder, request)
		expected := http.StatusBadRequest
		if attempt == 10 {
			expected = http.StatusTooManyRequests
		}
		if recorder.Code != expected {
			t.Fatalf("bounded setup attempt %d: HTTP %d", attempt, recorder.Code)
		}
	}
	assertSetupUninitialized(t, s, ctx)
	var encoded string
	if err := pool.QueryRow(ctx, "SELECT row_to_json(s)::text FROM first_run_setup s").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal([]byte(encoded), &state); err != nil {
		t.Fatal(err)
	}
	if state["account_id"] != nil || strings.Contains(encoded, code) || strings.Contains(encoded, localTestPassword) {
		t.Fatal("denied requests changed pending identity or persisted plaintext secrets")
	}
}

func TestSetupAdmissionSharesDurableWindowAcrossReplicas(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	replica, err := New(ctx, pool, Config{Local: true, PublicURL: localTestOrigin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := replica.Close(); err != nil {
			t.Error(err)
		}
	})
	for range 10 {
		if err := s.admitSetup(ctx, "192.0.2.1:1000"); err != nil {
			t.Fatal(err)
		}
	}
	if err := replica.admitSetup(ctx, "192.0.2.1:2000"); !errors.Is(err, errSetupRateLimited) {
		t.Fatalf("replica escaped client rate window: %v", err)
	}
	for range 49 {
		if err := replica.admitSetup(ctx, "192.0.2.2:2000"); err != nil && !errors.Is(err, errSetupRateLimited) {
			t.Fatal(err)
		}
	}
	if err := s.admitSetup(ctx, "192.0.2.3:3000"); !errors.Is(err, errSetupRateLimited) {
		t.Fatalf("new client escaped global rate window: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE first_run_attempts SET window_at=clock_timestamp()-interval '2 minutes'"); err != nil {
		t.Fatal(err)
	}
	if err := replica.admitSetup(ctx, "192.0.2.1:2000"); err != nil {
		t.Fatalf("elapsed window did not recover: %v", err)
	}
}

func TestSetupHTTPCompletionIssuesOnlySecureSessionCookie(t *testing.T) {
	s, ctx, pool := localIntegrationService(t)
	code, err := IssueSetupCode(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := s.beginSetup(ctx, setupRequest(code, "browser-owner"))
	if err != nil {
		t.Fatal(err)
	}
	auth := localAuthenticator(t)
	credential, _ := auth.response(t, localChallenge(t, challenge), localTestOrigin, true, true, 0)
	body, err := protojson.Marshal(&authv1.WebAuthnFinishRequest{Token: challenge.Token, CredentialJson: string(credential)})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/local/enroll/finish", bytes.NewReader(body))
	request.Header.Set("Origin", localTestOrigin)
	recorder := httptest.NewRecorder()
	s.handleLocalEnrollFinish(recorder, request)
	response := recorder.Result()
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	cookies := response.Cookies()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store" || len(cookies) != 1 {
		t.Fatalf("setup completion response: HTTP %d cookies=%d", response.StatusCode, len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("setup session cookie weakened browser custody")
	}
	if recorder.Body.Len() != 0 || strings.Contains(recorder.Body.String(), code) {
		t.Fatal("setup completion echoed authentication material")
	}
	principal, decision, err := s.resolve(ctx, cookie.Value)
	if err != nil || decision.Kind != accessOK || principal.DisplayName != "browser-owner" {
		t.Fatalf("HTTP setup did not authenticate its owner: %v %v", decision, err)
	}
}
