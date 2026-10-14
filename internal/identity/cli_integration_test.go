// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func cliBrowserFixture(t *testing.T) (*Service, context.Context, string) {
	t.Helper()
	s, ctx, _ := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "cli-owner")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, authenticator)
	return s, ctx, loginLocal(t, s, ctx, "cli-owner", "", authenticator)
}

func cliCodeFixture(t *testing.T, s *Service, ctx context.Context, cookie string) *authv1.CLIExchangeRequest {
	t.Helper()
	verifier, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	state, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(verifier))
	redirect := "http://127.0.0.1:34567/callback"
	binding, err := s.beginCLI(ctx, &authv1.CLIAuthorizationRequest{RedirectUri: redirect, State: state, CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	principal, decision, err := s.resolve(ctx, cookie)
	if err != nil || decision.Kind != accessOK {
		t.Fatalf("browser resolve: %v %v", decision, err)
	}
	location, err := s.approveCLI(ctx, cookie, binding, principal)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != state || len(u.Query()) != 2 {
		t.Fatal("callback lost state or included excess fields")
	}
	return &authv1.CLIExchangeRequest{Code: u.Query().Get("code"), CodeVerifier: verifier, RedirectUri: redirect}
}

func cliHTTP(t *testing.T, s *Service, method, path, token string, bearer bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, localTestOrigin+path, nil)
	if bearer {
		request.Header.Set("Authorization", "Bearer "+token)
	} else {
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	return response
}

func TestCLICodePKCEBindingSingleUseAndRevocation(t *testing.T) {
	s, ctx, cookie := cliBrowserFixture(t)
	request := cliCodeFixture(t, s, ctx, cookie)
	wrong := &authv1.CLIExchangeRequest{Code: request.Code, CodeVerifier: strings.Repeat("a", 43), RedirectUri: request.RedirectUri}
	if _, err := s.exchangeCLI(ctx, wrong); err == nil {
		t.Fatal("wrong PKCE verifier accepted")
	}
	wrong.CodeVerifier = request.CodeVerifier
	wrong.RedirectUri = "http://127.0.0.1:34568/callback"
	if _, err := s.exchangeCLI(ctx, wrong); err == nil {
		t.Fatal("wrong redirect accepted")
	}
	var wg sync.WaitGroup
	results := make(chan *authv1.CLIExchangeResponse, 2)
	for range 2 {
		wg.Go(func() {
			result, err := s.exchangeCLI(ctx, request)
			if err == nil {
				results <- result
			}
		})
	}
	wg.Wait()
	close(results)
	var session *authv1.CLIExchangeResponse
	for result := range results {
		if session != nil {
			t.Fatal("authorization code replay issued two sessions")
		}
		session = result
	}
	if session == nil {
		t.Fatal("no exchange succeeded")
	}
	if _, err := s.exchangeCLI(ctx, request); err == nil {
		t.Fatal("code replay accepted")
	}
	var stored int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE kind='cli' AND token_hash=$1", sessionHash(session.Token)).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("hashed CLI session: count=%d err=%v", stored, err)
	}
	response := cliHTTP(t, s, http.MethodGet, "/auth/session", session.Token, true)
	principal := &authv1.SessionPrincipal{}
	if response.Code != http.StatusOK || protojson.Unmarshal(response.Body.Bytes(), principal) != nil || principal.GetCsrfToken() != "" || principal.GetId() == "" {
		t.Fatalf("CLI session response status=%d", response.Code)
	}
	if response := cliHTTP(t, s, http.MethodGet, "/auth/session", cookie, true); response.Code != http.StatusUnauthorized {
		t.Fatal("browser cookie accepted as bearer")
	}
	if response := cliHTTP(t, s, http.MethodGet, "/auth/session", session.Token, false); response.Code != http.StatusUnauthorized {
		t.Fatal("CLI token accepted as cookie")
	}
	if response := cliHTTP(t, s, http.MethodGet, "/auth/accounts", session.Token, true); response.Code != http.StatusUnauthorized {
		t.Fatal("bearer accepted by browser account endpoint")
	}
	if response := cliHTTP(t, s, http.MethodPost, "/auth/logout", session.Token, true); response.Code != http.StatusNoContent {
		t.Fatalf("bearer logout without CSRF: %d", response.Code)
	}
	if response := cliHTTP(t, s, http.MethodGet, "/auth/session", session.Token, true); response.Code != http.StatusUnauthorized {
		t.Fatal("revoked CLI session survived")
	}
	if response := cliHTTP(t, s, http.MethodGet, "/auth/session", cookie, false); response.Code != http.StatusOK {
		t.Fatal("CLI logout revoked ordinary browser session")
	}
}

func TestCLIExpiryAndAuthorityFences(t *testing.T) {
	for _, scenario := range []string{"code_expiry", "browser_revoked", "version_changed", "account_disabled", "cli_idle", "cli_absolute"} {
		t.Run(scenario, func(t *testing.T) {
			s, ctx, cookie := cliBrowserFixture(t)
			request := cliCodeFixture(t, s, ctx, cookie)
			principal, _, err := s.resolve(ctx, cookie)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "code_expiry":
				_, err = s.pool.Exec(ctx, "UPDATE cli_auth_codes SET expires_at=now()-interval '1 second'")
			case "browser_revoked":
				err = s.logout(ctx, cookie, principal.ID)
			case "version_changed":
				_, err = s.pool.Exec(ctx, "UPDATE principals SET authorization_version=authorization_version+1 WHERE id=$1", principal.ID)
			case "account_disabled":
				_, err = s.pool.Exec(ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", principal.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.exchangeCLI(ctx, request)
			if scenario != "cli_idle" && scenario != "cli_absolute" {
				if err == nil {
					t.Fatal("invalid code authority exchanged")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var idle, absolute time.Time
			if err := s.pool.QueryRow(ctx, "SELECT idle_expires_at,absolute_expires_at FROM sessions WHERE token_hash=$1", sessionHash(result.Token)).Scan(&idle, &absolute); err != nil {
				t.Fatal(err)
			}
			if time.Until(idle) > 15*time.Minute || time.Until(absolute) > 8*time.Hour {
				t.Fatal("CLI-specific expiry limits not applied")
			}
			if scenario == "cli_idle" {
				_, err = s.pool.Exec(ctx, "UPDATE sessions SET created_at=now()-interval '1 hour',last_seen_at=now()-interval '16 minutes',idle_expires_at=now()-interval '1 minute' WHERE token_hash=$1", sessionHash(result.Token))
			} else {
				_, err = s.pool.Exec(ctx, "UPDATE sessions SET created_at=now()-interval '9 hours',last_seen_at=now()-interval '1 hour',idle_expires_at=now()-interval '1 hour',absolute_expires_at=now()-interval '1 hour' WHERE token_hash=$1", sessionHash(result.Token))
			}
			if err != nil {
				t.Fatal(err)
			}
			if response := cliHTTP(t, s, http.MethodGet, "/auth/session", result.Token, true); response.Code != http.StatusUnauthorized {
				t.Fatal("expired CLI session survived")
			}
		})
	}
}

func TestCLIBreakGlassRestrictionAndRevocation(t *testing.T) {
	s, ctx, _ := localIntegrationService(t)
	enrollment, err := s.BootstrapLocalOwner(ctx, "emergency-cli")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := localAuthenticator(t)
	enrollLocal(t, s, ctx, enrollment, authenticator)
	s.localPrimary = false
	s.issuer = "https://unavailable.example/realms/lindm"
	s.breakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionReadFleet)}, MaxSessionLifetime: durationpb.New(5 * time.Minute), RequireIncidentReason: true}
	if _, err := s.pool.Exec(ctx, "UPDATE local_accounts SET break_glass=true WHERE id=$1", enrollment.AccountID); err != nil {
		t.Fatal(err)
	}
	cookie := loginLocal(t, s, ctx, "emergency-cli", "incident CLI test", authenticator)
	request := cliCodeFixture(t, s, ctx, cookie)
	session, err := s.exchangeCLI(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	principal, decision, err := s.resolveKind(ctx, session.Token, "cli")
	if err != nil || decision.Kind != accessOK || !principal.BreakGlass || principal.IncidentReason != "incident CLI test" {
		t.Fatalf("emergency CLI principal: %v %v", decision, err)
	}
	if !Authorize(principal, PermissionReadFleet) || Authorize(principal, PermissionRevokeDevice) {
		t.Fatal("CLI did not preserve emergency allowlist")
	}
	if time.Until(session.ExpiresAt.AsTime()) > 5*time.Minute {
		t.Fatal("CLI extended emergency expiry")
	}
	authorization, err := s.AuthorizeFresh(ctx, principal.ID, PermissionReadFleet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeFresh(ctx, principal.ID, PermissionRevokeDevice); err == nil {
		t.Fatal("worker authority widened emergency CLI permissions")
	}
	pending := cliCodeFixture(t, s, ctx, cookie)
	s.breakGlass.ConsoleOnly = true
	if response := cliHTTP(t, s, http.MethodGet, "/auth/session", session.Token, true); response.Code != http.StatusUnauthorized {
		t.Fatal("console-only emergency accepted CLI bearer")
	}
	if _, err := s.exchangeCLI(ctx, pending); err == nil {
		t.Fatal("console-only emergency issued CLI session")
	}
	s.breakGlass.ConsoleOnly = false
	if response := cliHTTP(t, s, http.MethodPost, "/auth/logout", session.Token, true); response.Code != http.StatusNoContent {
		t.Fatal("emergency CLI logout failed")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockAuthorization(ctx, tx, authorization, PermissionReadFleet); err == nil {
		t.Fatal("emergency CLI logout retained old worker authority")
	}
}

func TestCLIApprovalOriginCSRFBrowserBinding(t *testing.T) {
	s, ctx, cookie := cliBrowserFixture(t)
	state, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.beginCLI(ctx, &authv1.CLIAuthorizationRequest{RedirectUri: "http://127.0.0.1:34567/callback", State: state, CodeChallenge: state})
	if err != nil {
		t.Fatal(err)
	}
	for _, signedIn := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodGet, localTestOrigin+"/auth/cli/approve", nil)
		request.AddCookie(&http.Cookie{Name: cliFlowCookie, Value: binding})
		if signedIn {
			request.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		}
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("CLI approval page status = %d", response.Code)
		}
		body := response.Body.String()
		if signedIn {
			for _, text := range []string{
				"Approve only if you started lindmctl on this device.",
				"lindm sends the session to http://127.0.0.1:34567/callback.",
				`action="/auth/cli/approve"`,
				`value="` + csrfToken(cookie+binding) + `"`,
			} {
				if !strings.Contains(body, text) {
					t.Fatalf("CLI approval page omitted %q", text)
				}
			}
		} else if !strings.Contains(body, `href="/" target="_blank" rel="noopener"`) || !strings.Contains(body, "Return to this tab after you sign in.") {
			t.Fatal("CLI sign-in page lost its return instruction or safe console link")
		}
	}
	for _, scenario := range []string{"missing_origin", "wrong_csrf", "wrong_binding", "valid"} {
		form := url.Values{"csrf_token": {csrfToken(cookie + binding)}}
		if scenario == "wrong_csrf" {
			form.Set("csrf_token", csrfToken(cookie))
		}
		request := httptest.NewRequest(http.MethodPost, localTestOrigin+"/auth/cli/approve", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if scenario != "missing_origin" {
			request.Header.Set("Origin", localTestOrigin)
		}
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		flow := binding
		if scenario == "wrong_binding" {
			flow = state
		}
		request.AddCookie(&http.Cookie{Name: cliFlowCookie, Value: flow})
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		want := http.StatusForbidden
		if scenario == "valid" {
			want = http.StatusSeeOther
		}
		if response.Code != want {
			t.Fatalf("%s approval: %d, want %d", scenario, response.Code, want)
		}
	}
}
