// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

func mcpFixture(t *testing.T) (*Service, context.Context, string, uuid.UUID) {
	t.Helper()
	s, ctx, _ := localIntegrationService(t)
	owner, err := bootstrapLocalOwner(t, s, ctx, "mcp-owner")
	if err != nil {
		t.Fatal(err)
	}
	return s, ctx, insertLiveSession(t, ctx, s, owner.AccountID), owner.AccountID
}

func mcpSettingsHTTP(t *testing.T, s *Service, cookie, method, path string, message proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if message != nil {
		var err error
		body, err = protojson.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, localTestOrigin+path, bytes.NewReader(body))
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		r.Header.Set(csrfHeader, csrfToken(cookie))
	}
	r.Header.Set("Origin", localTestOrigin)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func mcpIssueHTTP(t *testing.T, s *Service, cookie, label string, proposals bool) *authv1.IssueMCPTokenResponse {
	t.Helper()
	w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/tokens", &authv1.IssueMCPTokenRequest{Label: label, ProposalsAllowed: proposals, LifetimeSeconds: 3600})
	result := &authv1.IssueMCPTokenResponse{}
	if w.Code != http.StatusOK || protojson.Unmarshal(w.Body.Bytes(), result) != nil || !validOpaqueToken(result.GetBearerToken()) {
		t.Fatalf("issue token status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("shown-once credential response can be cached")
	}
	return result
}

func mcpRequest(s *Service, token string, browser bool, next http.Handler) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, localTestOrigin+"/mcp", nil)
	if browser {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		r.Header.Set("Origin", localTestOrigin)
		r.Header.Set(csrfHeader, csrfToken(token))
	} else if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.RequireMCP(next).ServeHTTP(w, r)
	return w
}

func mcpEnableHTTP(t *testing.T, s *Service, cookie string, enabled bool) {
	t.Helper()
	w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/settings", &authv1.UpdateMCPSettingsRequest{Enabled: enabled})
	if w.Code != http.StatusOK {
		t.Fatalf("set enabled=%t status=%d", enabled, w.Code)
	}
}

func TestMCPSettingsOwnCredentialsAndDurableAudit(t *testing.T) {
	s, ctx, cookie, actor := mcpFixture(t)
	if w := mcpSettingsHTTP(t, s, "", http.MethodGet, "/auth/mcp/settings", nil); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous settings access accepted")
	}
	settings := &authv1.MCPSettings{}
	w := mcpSettingsHTTP(t, s, cookie, http.MethodGet, "/auth/mcp/settings", nil)
	if w.Code != http.StatusOK || protojson.Unmarshal(w.Body.Bytes(), settings) != nil || settings.Enabled || len(settings.Tokens) != 0 {
		t.Fatal("MCP is not disabled with an empty own-token list by default")
	}
	for _, request := range []*authv1.IssueMCPTokenRequest{
		{Label: "", LifetimeSeconds: 3600},
		{Label: "\nunsafe", LifetimeSeconds: 3600},
		{Label: "assistant", LifetimeSeconds: 2592001},
		{Label: "assistant", LifetimeSeconds: 0},
	} {
		if w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/tokens", request); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid issuance status=%d", w.Code)
		}
	}
	issued := mcpIssueHTTP(t, s, cookie, "Local assistant", false)
	stored, err := identitydb.New(s.pool).GetMCPTokenByHash(ctx, domainHash(mcpTokenDomain, issued.BearerToken))
	if err != nil || stored.PrincipalID != actor || bytes.Equal(stored.TokenHash, []byte(issued.BearerToken)) || stored.ProposalsAllowed || len(stored.TokenHash) != 32 {
		t.Fatalf("dedicated hashed credential storage: %v", err)
	}
	if lifetime := stored.ExpiresAt.Time.Sub(stored.CreatedAt.Time); lifetime != time.Hour {
		t.Fatalf("stored token lifetime=%v", lifetime)
	}
	w = mcpSettingsHTTP(t, s, cookie, http.MethodGet, "/auth/mcp/settings", nil)
	if protojson.Unmarshal(w.Body.Bytes(), settings) != nil || len(settings.Tokens) != 1 || settings.Tokens[0].Id != issued.Token.Id || strings.Contains(w.Body.String(), issued.BearerToken) {
		t.Fatal("list leaked credential or omitted own token")
	}
	var peer Enrollment
	if err := s.withTx(ctx, func(q *identitydb.Queries) error {
		var err error
		peer, err = s.createLocalAccount(ctx, q, &authv1.CreateAccountRequest{Username: "mcp-peer", Role: RoleAdmin})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	peerCookie := insertLiveSession(t, ctx, s, peer.AccountID)
	peerToken := mcpIssueHTTP(t, s, peerCookie, "Other assistant", true)
	w = mcpSettingsHTTP(t, s, peerCookie, http.MethodGet, "/auth/mcp/settings", nil)
	if w.Code != http.StatusOK || protojson.Unmarshal(w.Body.Bytes(), settings) != nil || len(settings.Tokens) != 1 || settings.Tokens[0].Id != peerToken.Token.Id {
		t.Fatal("token list crossed principal ownership")
	}
	if w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/tokens/revoke", &authv1.RevokeMCPTokenRequest{TokenId: peerToken.Token.Id}); w.Code != http.StatusForbidden {
		t.Fatal("owner revoked another principal's token")
	}
	mcpEnableHTTP(t, s, cookie, true)
	if w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/tokens/revoke", &authv1.RevokeMCPTokenRequest{TokenId: issued.Token.Id}); w.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", w.Code)
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_id=$1 AND reason='' AND action IN ('identity.mcp_token_issued','identity.mcp_token_revoked','identity.mcp_settings_changed') AND position($2 in details::text)=0`, actor, issued.BearerToken).Scan(&count); err != nil || count != 3 {
		t.Fatalf("durable management audit count=%d err=%v", count, err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE local_accounts SET role='operator' WHERE id=$1`, peer.AccountID); err != nil {
		t.Fatal(err)
	}
	if w := mcpSettingsHTTP(t, s, peerCookie, http.MethodGet, "/auth/mcp/settings", nil); w.Code != http.StatusForbidden {
		t.Fatal("principal without integrations.manage read settings")
	}
	if _, err := s.pool.Exec(ctx, `UPDATE local_accounts SET role='admin', scope_binding='{"scopes":[{"labels":["east"]}]}' WHERE id=$1`, peer.AccountID); err != nil {
		t.Fatal(err)
	}
	if w := mcpSettingsHTTP(t, s, peerCookie, http.MethodGet, "/auth/mcp/settings", nil); w.Code != http.StatusForbidden {
		t.Fatal("device-scoped integrations.manage accessed deployment settings")
	}
}

func TestRequireMCPAuthenticationAndCapabilityCeilings(t *testing.T) {
	s, ctx, cookie, actor := mcpFixture(t)
	read := mcpIssueHTTP(t, s, cookie, "Reader", false)
	propose := mcpIssueHTTP(t, s, cookie, "Proposer", true)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, browser := range []bool{false, true} {
		token := read.BearerToken
		if browser {
			token = cookie
		}
		if w := mcpRequest(s, token, browser, next); w.Code != http.StatusForbidden {
			t.Fatal("disabled MCP accepted authenticated access")
		}
	}
	mcpEnableHTTP(t, s, cookie, true)
	for _, test := range []struct {
		token    string
		browser  bool
		proposal bool
		tag      string
	}{
		{read.BearerToken, false, false, "Reader"},
		{propose.BearerToken, false, true, "Proposer"},
		{cookie, true, true, "browser"},
	} {
		called := false
		w := mcpRequest(s, test.token, test.browser, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			principal, ok := PrincipalFromContext(r.Context())
			if !ok || principal.ID != actor || MCPProposalsAllowed(r.Context()) != test.proposal || MCPClientTag(r.Context()) != test.tag {
				t.Error("MCP lost principal binding or capability ceiling")
			}
			if !test.browser && !errors.Is(s.RequireRecentStepUp(r.Context(), time.Minute), ErrAuthorizationDenied) {
				t.Error("dedicated token supplied browser step-up")
			}
			if !test.browser {
				err := s.withTx(r.Context(), func(q *identitydb.Queries) error {
					if _, err := q.GetPrincipalForUpdate(r.Context(), actor); err != nil {
						return err
					}
					if err := s.checkAuthenticatedSession(r.Context(), q, actor, false); err != nil {
						return err
					}
					if !errors.Is(s.checkAuthenticatedSession(r.Context(), q, actor, true), ErrAuthorizationDenied) {
						t.Error("dedicated token passed browser-only session fence")
					}
					return nil
				})
				if err != nil {
					t.Errorf("token-bound authenticated-session fence: %v", err)
				}
			}
			if err := s.AuditMCP(r.Context(), "tools/list", ""); err != nil {
				t.Error(err)
			}
			if err := s.AuditMCPResult(r.Context(), "tools/list", "", "success"); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		if w.Code != http.StatusNoContent || !called {
			t.Fatalf("authenticated request status=%d", w.Code)
		}
	}
	for _, test := range []struct {
		name   string
		token  string
		cookie bool
		origin string
		csrf   string
		path   string
		status int
	}{
		{"anonymous", "", false, "", "", "/mcp", http.StatusUnauthorized},
		{"browser_no_csrf", cookie, true, localTestOrigin, "", "/mcp", http.StatusForbidden},
		{"browser_no_origin", cookie, true, "", csrfToken(cookie), "/mcp", http.StatusForbidden},
		{"bearer_origin", read.BearerToken, false, "https://unexpected.example", "", "/mcp", http.StatusForbidden},
		{"browser_as_bearer", cookie, false, "", "", "/mcp", http.StatusUnauthorized},
		{"token_as_cookie", read.BearerToken, true, localTestOrigin, csrfToken(read.BearerToken), "/mcp", http.StatusUnauthorized},
		{"token_other_path", read.BearerToken, false, "", "", "/elsewhere", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, localTestOrigin+test.path, nil)
			if test.cookie {
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: test.token})
			} else if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			r.Header.Set(csrfHeader, test.csrf)
			w := httptest.NewRecorder()
			s.RequireMCP(next).ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d want=%d", w.Code, test.status)
			}
		})
	}
	connect := httptest.NewRequest(http.MethodPost, localTestOrigin+"/lindm.admin.v1.AdminService/GetFleetSummary", nil)
	connect.Header.Set("Authorization", "Bearer "+read.BearerToken)
	w := httptest.NewRecorder()
	s.RequireSession(next).ServeHTTP(w, connect)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("dedicated token authenticated ordinary Connect")
	}
	if MCPProposalsAllowed(WithPrincipal(ctx, Principal{ID: actor})) || MCPClientTag(ctx) != "" || s.AuditMCP(WithPrincipal(ctx, Principal{ID: actor}), "http", "") == nil {
		t.Fatal("principal-only context manufactured private MCP authentication")
	}
	var attempts, successes int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE details->>'outcome'='attempt'),count(*) FILTER (WHERE details->>'outcome'='success') FROM audit_events WHERE actor_id=$1 AND action='mcp.attempt' AND details->>'tool'=''`, actor).Scan(&attempts, &successes); err != nil || attempts != 3 || successes != 3 {
		t.Fatalf("discovery audit attempts=%d successes=%d err=%v", attempts, successes, err)
	}
}

func TestMCPTokenCurrentAuthorityAndTransactionFences(t *testing.T) {
	for _, scenario := range []string{"revoke", "disable_mcp", "expire", "disable_account", "role_and_scope", "logout_browser"} {
		t.Run(scenario, func(t *testing.T) {
			s, ctx, cookie, actor := mcpFixture(t)
			issued := mcpIssueHTTP(t, s, cookie, "Scoped assistant", true)
			mcpEnableHTTP(t, s, cookie, true)
			var requestCtx context.Context
			if w := mcpRequest(s, issued.BearerToken, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCtx = r.Context()
				w.WriteHeader(http.StatusNoContent)
			})); w.Code != http.StatusNoContent {
				t.Fatal("token did not authenticate")
			}
			authorization, err := s.AuthorizeFresh(requestCtx, actor, PermissionReadFleet)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "revoke":
				w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/tokens/revoke", &authv1.RevokeMCPTokenRequest{TokenId: issued.Token.Id})
				if w.Code != http.StatusOK {
					t.Fatal("revoke failed")
				}
			case "disable_mcp":
				mcpEnableHTTP(t, s, cookie, false)
			case "expire":
				_, err = s.pool.Exec(ctx, `UPDATE mcp_tokens SET created_at=clock_timestamp()-interval '2 hours', expires_at=clock_timestamp()-interval '1 hour' WHERE principal_id=$1`, actor)
			case "disable_account":
				_, err = s.pool.Exec(ctx, `UPDATE local_accounts SET enabled=false WHERE id=$1`, actor)
			case "role_and_scope":
				_, err = s.pool.Exec(ctx, `UPDATE local_accounts SET role='auditor', scope_binding='{"scopes":[{"labels":["east"]}]}' WHERE id=$1`, actor)
			case "logout_browser":
				err = s.logout(ctx, cookie, actor)
			}
			if err != nil {
				t.Fatal(err)
			}
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fenced := s.LockAuthorization(requestCtx, tx, authorization, PermissionReadFleet)
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if scenario == "logout_browser" {
				if fenced != nil {
					t.Fatalf("dedicated credential unexpectedly tied to browser logout: %v", fenced)
				}
			} else if fenced == nil {
				t.Fatal("changed token authority passed transaction fence")
			}
			called := false
			w := mcpRequest(s, issued.BearerToken, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				principal, _ := PrincipalFromContext(r.Context())
				if scenario == "role_and_scope" {
					unrestricted, scopes := DeviceScopes(principal, PermissionReadFleet)
					if principal.Role != RoleAuditor || Authorize(principal, PermissionManageIntegrations) || unrestricted || len(scopes) != 1 || scopes[0].GetLabels()[0] != "east" {
						t.Error("token retained stale role, permission or scope")
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			if scenario == "role_and_scope" || scenario == "logout_browser" {
				if w.Code != http.StatusNoContent || !called {
					t.Fatalf("current credential request status=%d", w.Code)
				}
			} else if called || w.Code < http.StatusBadRequest {
				t.Fatal("denied credential reached handler")
			}
		})
	}
}

func TestMCPAuditsFailClosedAndManagementRollsBack(t *testing.T) {
	s, ctx, cookie, _ := mcpFixture(t)
	issued := mcpIssueHTTP(t, s, cookie, "Audited assistant", false)
	mcpEnableHTTP(t, s, cookie, true)
	if _, err := s.pool.Exec(ctx, `CREATE FUNCTION lindm_test_fail_mcp_audit() RETURNS trigger AS $$ BEGIN IF NEW.action LIKE '%mcp%' THEN RAISE EXCEPTION 'forced MCP audit failure'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `CREATE TRIGGER lindm_test_fail_mcp_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE PROCEDURE lindm_test_fail_mcp_audit()`); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		path string
		body proto.Message
	}{
		{"/auth/mcp/settings", &authv1.UpdateMCPSettingsRequest{Enabled: false}},
		{"/auth/mcp/tokens", &authv1.IssueMCPTokenRequest{Label: "Must not persist", LifetimeSeconds: 3600}},
		{"/auth/mcp/tokens/revoke", &authv1.RevokeMCPTokenRequest{TokenId: issued.Token.Id}},
	} {
		if w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, mutation.path, mutation.body); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("audit-failed management status=%d", w.Code)
		}
	}
	var enabled bool
	var active int
	if err := s.pool.QueryRow(ctx, `SELECT enabled FROM mcp_settings`).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("failed audit changed enabled switch: %v", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM mcp_tokens WHERE revoked_at IS NULL`).Scan(&active); err != nil || active != 1 {
		t.Fatalf("failed audit changed active tokens count=%d err=%v", active, err)
	}
	dispatched := false
	w := mcpRequest(s, issued.BearerToken, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.AuditMCP(r.Context(), "tools/call", "fleet_summary"); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		dispatched = true
	}))
	if w.Code != http.StatusServiceUnavailable || dispatched {
		t.Fatal("failed MCP attempt audit permitted dispatch")
	}
}

func TestMCPBreakGlassTokenIssuanceAndUseDenied(t *testing.T) {
	s, ctx, cookie, actor := mcpFixture(t)
	issued := mcpIssueHTTP(t, s, cookie, "Before emergency mode", true)
	mcpEnableHTTP(t, s, cookie, true)
	s.localPrimary = false
	s.issuer = "https://unavailable.example/realms/lindm"
	s.breakGlass = &configv1.BreakGlassPolicy{AllowedPermissions: []string{string(PermissionManageIntegrations), string(PermissionReadFleet)}, MaxSessionLifetime: durationpb.New(30 * time.Minute), RequireIncidentReason: true}
	if _, err := s.pool.Exec(ctx, `UPDATE local_accounts SET break_glass=true WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE sessions SET break_glass=true, incident_reason='MCP security test', absolute_expires_at=created_at+interval '30 minutes', idle_expires_at=created_at+interval '20 minutes' WHERE principal_id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	if w := mcpSettingsHTTP(t, s, cookie, http.MethodPost, "/auth/mcp/tokens", &authv1.IssueMCPTokenRequest{Label: "Emergency assistant", LifetimeSeconds: 3600}); w.Code != http.StatusForbidden {
		t.Fatalf("emergency issuance status=%d", w.Code)
	}
	called := false
	w := mcpRequest(s, issued.BearerToken, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	if called || w.Code < http.StatusBadRequest {
		t.Fatal("break-glass identity used a dedicated token")
	}
}
