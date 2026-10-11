package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

const cliFlowCookie = "__Host-lindm_cli"

func sessionCredential(r *http.Request) (token, kind string, ok bool) {
	if values := r.Header.Values("Authorization"); len(values) != 0 {
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			return "", "", false
		}
		if _, err := r.Cookie(sessionCookie); err == nil {
			return "", "", false
		}
		token = strings.TrimPrefix(values[0], "Bearer ")
		return token, "cli", validOpaqueToken(token)
	}
	token, ok = readOpaqueCookie(r, sessionCookie)
	return token, "browser", ok
}

func cliBearerPath(path string) bool {
	return path == "/auth/session" || path == "/auth/logout" || strings.HasPrefix(path, "/"+adminv1connect.AdminServiceName+"/")
}

func (s *Service) registerCLIHTTP(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/cli/authorize", s.handleCLIAuthorize)
	mux.HandleFunc("GET /auth/cli/approve", s.handleCLIApprovalPage)
	mux.HandleFunc("POST /auth/cli/approve", s.handleCLIApprove)
	mux.HandleFunc("POST /auth/cli/exchange", s.handleCLIExchange)
}

func (s *Service) beginCLI(ctx context.Context, request *authv1.CLIAuthorizationRequest) (string, error) {
	if err := s.rules.Validate(request); err != nil {
		return "", errUnauthenticated
	}
	redirect, err := url.Parse(request.GetRedirectUri())
	if err != nil {
		return "", errUnauthenticated
	}
	port, err := strconv.ParseUint(redirect.Port(), 10, 16)
	if err != nil || port == 0 {
		return "", errUnauthenticated
	}
	binding, err := randomToken()
	if err != nil {
		return "", err
	}
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		if err := q.LockCLIAdmission(ctx); err != nil {
			return s.dbErr(err)
		}
		if err := q.DeleteStaleCLIRequests(ctx); err != nil {
			return s.dbErr(err)
		}
		count, err := q.CountCLIRequests(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if count >= 512 {
			return errStore
		}
		return s.dbErr(q.InsertCLIRequest(ctx, identitydb.InsertCLIRequestParams{BindingHash: bindingHash(binding), RedirectUri: request.GetRedirectUri(), CodeChallenge: request.GetCodeChallenge(), State: request.GetState()}))
	})
	return binding, err
}

func (s *Service) handleCLIAuthorize(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 1024 {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	query := r.URL.Query()
	if len(query) != 3 || len(query["redirect_uri"]) != 1 || len(query["code_challenge"]) != 1 || len(query["state"]) != 1 {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	request := &authv1.CLIAuthorizationRequest{RedirectUri: query.Get("redirect_uri"), CodeChallenge: query.Get("code_challenge"), State: query.Get("state")}
	if err := s.rules.Validate(request); err != nil {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	binding, err := s.beginCLI(r.Context(), request)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	setHostCookie(w, cliFlowCookie, binding, 300)
	http.Redirect(w, r, s.publicOrigin+"/auth/cli/approve", http.StatusSeeOther)
}

func (s *Service) handleCLIApprovalPage(w http.ResponseWriter, r *http.Request) {
	binding, ok := readOpaqueCookie(r, cliFlowCookie)
	if !ok {
		writeStatus(w, http.StatusUnauthorized)
		return
	}
	request, err := identitydb.New(s.pool).GetCLIRequest(r.Context(), bindingHash(binding))
	if err != nil {
		writeStatus(w, statusFor(s.dbErr(err)))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	cookie, ok := readOpaqueCookie(r, sessionCookie)
	if !ok {
		_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign in to lindmctl</title><h1>Sign in to lindmctl</h1><p><a href="/" target="_blank" rel="noopener">Sign in to Lindm in another tab</a> using your normal local authenticator or SSO. Then return here.</p><a href="/auth/cli/approve">Continue after signing in</a></html>`)
		return
	}
	principal, decision, err := s.resolve(r.Context(), cookie)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	if decision.Kind != accessOK {
		clearHostCookie(w, sessionCookie)
		http.Redirect(w, r, s.publicOrigin+"/auth/cli/approve", http.StatusSeeOther)
		return
	}
	if principal.BreakGlass && s.breakGlass.GetConsoleOnly() {
		if err := s.emergencyAudit(r.Context(), principal.ID, "identity.break_glass_denied", "", "CLI forbidden by console-only policy"); err != nil {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
		writeStatus(w, http.StatusForbidden)
		return
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Approve lindmctl</title><h1>Approve lindmctl sign-in</h1><p>Signed in as %s. Only approve if you started lindmctl on this computer. A session will be delivered to %s.</p><p>%s</p><form method="post" action="/auth/cli/approve"><input type="hidden" name="csrf_token" value="%s"><button type="submit">Approve CLI session</button></form></html>`, html.EscapeString(principal.DisplayName), html.EscapeString(request.RedirectUri), html.EscapeString(principal.IncidentReason), csrfToken(cookie+binding))
}

func (s *Service) handleCLIApprove(w http.ResponseWriter, r *http.Request) {
	cookie, ok := readOpaqueCookie(r, sessionCookie)
	binding, bound := readOpaqueCookie(r, cliFlowCookie)
	if !ok || !bound || r.Header.Get("Authorization") != "" || !originMatches(s.publicOrigin, r.Header.Get("Origin")) {
		writeStatus(w, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil || len(r.PostForm["csrf_token"]) != 1 || !csrfMatch(cookie+binding, r.PostForm.Get("csrf_token")) {
		writeStatus(w, http.StatusForbidden)
		return
	}
	principal, decision, err := s.resolve(r.Context(), cookie)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	if decision.Kind != accessOK {
		writeStatus(w, statusForDecision(decision))
		return
	}
	if principal.BreakGlass && s.breakGlass.GetConsoleOnly() {
		if err := s.emergencyAudit(r.Context(), principal.ID, "identity.break_glass_denied", "", "CLI forbidden by console-only policy"); err != nil {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
		writeStatus(w, http.StatusForbidden)
		return
	}
	location, err := s.approveCLI(r.Context(), cookie, binding, principal)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	clearHostCookie(w, cliFlowCookie)
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func (s *Service) approveCLI(ctx context.Context, cookie, binding string, actor Principal) (string, error) {
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	var location string
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		// Principal precedes session/code locks, just like logout and source revocation.
		row, err := q.GetPrincipalForUpdate(ctx, actor.ID)
		if err != nil {
			return s.dbErr(err)
		}
		snap, err := s.readSnapshot(ctx, q, row)
		if err != nil {
			return err
		}
		if decideAccess(s.clock(), s.accessIssuer(snap), snap.policy, snap).Kind != accessOK {
			return errUnauthenticated
		}
		session, err := q.GetSessionByTokenHash(ctx, sessionHash(cookie))
		if err != nil {
			return s.dbErr(err)
		}
		now, err := q.ReadAuthorizationClock(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if session.PrincipalID != actor.ID || session.Kind != "browser" || session.RevokedAt.Valid || !now.Time.Before(session.IdleExpiresAt.Time) || !now.Time.Before(session.AbsoluteExpiresAt.Time) || (session.BreakGlass && s.breakGlass.GetConsoleOnly()) {
			return errUnauthenticated
		}
		if err := q.LockCLIAdmission(ctx); err != nil {
			return s.dbErr(err)
		}
		if err := q.DeleteStaleCLICodes(ctx); err != nil {
			return s.dbErr(err)
		}
		count, err := q.CountCLICodes(ctx)
		if err != nil {
			return s.dbErr(err)
		}
		if count >= 512 {
			return errStore
		}
		request, err := q.ConsumeCLIRequest(ctx, bindingHash(binding))
		if err != nil {
			return s.dbErr(err)
		}
		if err := q.InsertCLICode(ctx, identitydb.InsertCLICodeParams{CodeHash: domainHash("lindm.cli-code.v1", code), BrowserSessionHash: sessionHash(cookie), AuthorizationVersion: row.AuthorizationVersion, RedirectUri: request.RedirectUri, CodeChallenge: request.CodeChallenge}); err != nil {
			return s.dbErr(err)
		}
		location = request.RedirectUri + "?" + url.Values{"code": {code}, "state": {request.State}}.Encode()
		return s.insertAudit(ctx, q, &actor.ID, "identity.cli_approved", principalResource(actor.ID), session.IncidentReason)
	})
	return location, err
}

func (s *Service) exchangeCLI(ctx context.Context, request *authv1.CLIExchangeRequest) (*authv1.CLIExchangeResponse, error) {
	if err := s.rules.Validate(request); err != nil {
		return nil, errUnauthenticated
	}
	hash := domainHash("lindm.cli-code.v1", request.GetCode())
	q := identitydb.New(s.pool)
	code, err := q.GetCLICode(ctx, hash)
	if err != nil {
		return nil, s.dbErr(err)
	}
	session, err := q.GetSessionByTokenHash(ctx, code.BrowserSessionHash)
	if err != nil {
		return nil, s.dbErr(err)
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(request.GetCodeVerifier()))
	result := &authv1.CLIExchangeResponse{Token: token}
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		row, err := q.GetPrincipalForUpdate(ctx, session.PrincipalID)
		if err != nil {
			return s.dbErr(err)
		}
		snap, err := s.readSnapshot(ctx, q, row)
		if err != nil {
			return err
		}
		if decideAccess(s.clock(), s.accessIssuer(snap), snap.policy, snap).Kind != accessOK || row.AuthorizationVersion != code.AuthorizationVersion || (session.BreakGlass && s.breakGlass.GetConsoleOnly()) {
			return errUnauthenticated
		}
		if _, err := q.ConsumeCLICode(ctx, identitydb.ConsumeCLICodeParams{CodeHash: hash, CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), RedirectUri: request.GetRedirectUri()}); err != nil {
			return s.dbErr(err)
		}
		expiry, err := q.InsertCLISession(ctx, identitydb.InsertCLISessionParams{TokenHash: sessionHash(token), BrowserSessionHash: code.BrowserSessionHash})
		if err != nil {
			return s.dbErr(err)
		}
		result.ExpiresAt = timestamppb.New(expiry.Time)
		return s.insertAudit(ctx, q, &row.ID, "identity.cli_login", principalResource(row.ID), session.IncidentReason)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) handleCLIExchange(w http.ResponseWriter, r *http.Request) {
	// This is a native-client endpoint: cookies and browser-origin requests cannot
	// exchange a code. The code and its independent S256 proof authorize the POST.
	if len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Authorization")) != 0 {
		writeStatus(w, http.StatusForbidden)
		return
	}
	request := &authv1.CLIExchangeRequest{}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil || protojson.Unmarshal(body, request) != nil || s.rules.Validate(request) != nil {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	result, err := s.exchangeCLI(r.Context(), request)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	writeProto(w, result)
}
