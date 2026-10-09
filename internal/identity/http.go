package identity

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
)

type errorBody struct {
	Error string `json:"error"`
}

// Handler serves /auth/login, /auth/callback, /auth/logout, and /auth/session.
// Mount it without stripping the /auth prefix.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.Handle("POST /auth/logout", s.RequireSession(http.HandlerFunc(s.handleLogout)))
	mux.Handle("GET /auth/session", s.RequireSession(http.HandlerFunc(s.handleSession)))
	s.registerLocalHTTP(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prepare(w)
		mux.ServeHTTP(w, r)
	})
}

// RequireSession authenticates the opaque session, refreshes directory state,
// and requires an exact Origin plus CSRF token on unsafe methods.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prepare(w)
		cookie, ok := readOpaqueCookie(r, sessionCookie)
		if !ok {
			writeStatus(w, http.StatusUnauthorized)
			return
		}
		principal, dec, err := s.resolve(r.Context(), cookie)
		if err != nil {
			writeStatus(w, statusFor(err))
			return
		}
		if dec.Kind != accessOK {
			if dec.Kind == accessUnauthenticated {
				clearHostCookie(w, sessionCookie)
			}
			writeStatus(w, statusForDecision(dec))
			return
		}
		if principal.BreakGlass {
			if err := s.emergencyAudit(r.Context(), principal.ID, "identity.break_glass_used", principal.IncidentReason); err != nil {
				writeStatus(w, http.StatusServiceUnavailable)
				return
			}
			response := &emergencyResponse{ResponseWriter: w}
			w = response
			defer func() {
				if response.status >= http.StatusBadRequest {
					if err := s.emergencyAudit(r.Context(), principal.ID, "identity.break_glass_denied", "protected request denied"); err != nil {
						slog.Error("identity emergency denial audit failed")
					}
				}
			}()
		}
		if unsafeMethod(r.Method) && (!originMatches(s.publicOrigin, r.Header.Get("Origin")) || !csrfMatch(cookie, r.Header.Get(csrfHeader))) {
			writeStatus(w, http.StatusForbidden)
			return
		}
		if err := s.touch(r.Context(), cookie); err != nil {
			writeStatus(w, statusFor(err))
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	prepare(w)
	if s.oauth == nil {
		writeStatus(w, http.StatusNotFound)
		return
	}
	state, err := randomToken()
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	verifier, err := randomToken()
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	binding, err := randomToken()
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	if err := s.beginFlow(r.Context(), state, nonce, verifier, binding); err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	authURL := s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	if !strings.HasPrefix(authURL, "https://") || strings.Contains(authURL, verifier) {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	setHostCookie(w, flowCookie, binding, flowCookieMaxAge)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	prepare(w)
	if s.oauth == nil {
		writeStatus(w, http.StatusNotFound)
		return
	}
	if len(r.URL.RawQuery) > 4096 || r.URL.Query().Get("error") != "" {
		s.failCallback(w, http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	binding, ok := readOpaqueCookie(r, flowCookie)
	if !ok || !validOpaqueToken(state) || !validCode(code) {
		s.failCallback(w, http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	nonceHash, verifier, err := s.consumeFlow(ctx, state, binding)
	if err != nil {
		s.failCallback(w, http.StatusUnauthorized)
		return
	}
	subject, err := s.exchangeAndVerify(ctx, code, verifier, nonceHash)
	if err != nil {
		s.failCallback(w, http.StatusUnauthorized)
		return
	}
	obs, err := s.observeDirectory(ctx, subject)
	if err != nil {
		s.failCallback(w, http.StatusServiceUnavailable)
		return
	}
	if !obs.Found {
		if err := s.denyAbsent(ctx, subject, obs); err != nil {
			s.failCallback(w, statusFor(err))
			return
		}
		s.failCallback(w, http.StatusUnauthorized)
		return
	}
	cookie, denied, err := s.completeLogin(ctx, subject, obs)
	if err != nil {
		s.failCallback(w, statusFor(err))
		return
	}
	if denied || cookie == "" {
		s.failCallback(w, http.StatusUnauthorized)
		return
	}
	clearHostCookie(w, flowCookie)
	setHostCookie(w, sessionCookie, cookie, sessionCookieMaxAge)
	http.Redirect(w, r, s.publicOrigin+"/", http.StatusSeeOther)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, ok := readOpaqueCookie(r, sessionCookie)
	principal, authenticated := PrincipalFromContext(r.Context())
	if !ok || !authenticated {
		writeStatus(w, http.StatusUnauthorized)
		return
	}
	if err := s.logout(r.Context(), cookie, principal.ID); err != nil && !errors.Is(err, errNotFound) {
		writeStatus(w, statusFor(err))
		return
	}
	clearHostCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleSession(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeStatus(w, http.StatusUnauthorized)
		return
	}
	writeSession(w, principal)
}

func (s *Service) exchangeAndVerify(ctx context.Context, code, verifier string, wantNonce []byte) (uuid.UUID, error) {
	ctx = oidc.ClientContext(ctx, s.httpClient)
	tok, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) && retrieve.Response != nil {
			slog.Warn("identity token exchange failed", "status", retrieve.Response.StatusCode)
		} else {
			slog.Warn("identity token exchange failed")
		}
		return uuid.Nil, errUnauthenticated
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" || tok.AccessToken == "" {
		return uuid.Nil, errUnauthenticated
	}
	idToken, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		slog.Warn("identity id token rejected")
		return uuid.Nil, errUnauthenticated
	}
	var claims struct {
		AZP string `json:"azp"`
		TID string `json:"tid"`
		OID string `json:"oid"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return uuid.Nil, errUnauthenticated
	}
	if idToken.Subject == "" || idToken.Issuer != s.issuer || !idTokenAccepted(s.clientID, idToken.Audience, claims.AZP, idToken.Nonce, wantNonce, idToken.IssuedAt, s.clock()) {
		return uuid.Nil, errUnauthenticated
	}
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(tok.AccessToken); err != nil {
			return uuid.Nil, errUnauthenticated
		}
	}
	if s.entraTenant != uuid.Nil {
		tenant, err := uuid.Parse(claims.TID)
		if err != nil || tenant != s.entraTenant {
			return uuid.Nil, errUnauthenticated
		}
		object, err := uuid.Parse(claims.OID)
		if err != nil || object == uuid.Nil {
			return uuid.Nil, errUnauthenticated
		}
		return object, nil
	}
	subject, err := uuid.Parse(idToken.Subject)
	if err != nil || subject == uuid.Nil {
		return uuid.Nil, errUnauthenticated
	}
	return subject, nil
}

func (s *Service) failCallback(w http.ResponseWriter, status int) {
	clearHostCookie(w, flowCookie)
	writeStatus(w, status)
}

func writeSession(w http.ResponseWriter, principal Principal) {
	body, err := (protojson.MarshalOptions{EmitDefaultValues: true}).Marshal(&authv1.SessionPrincipal{
		Id:             principal.ID.String(),
		Issuer:         principal.Issuer,
		Subject:        principal.Subject,
		DisplayName:    principal.DisplayName,
		Role:           principal.Role,
		CsrfToken:      principal.CSRFToken,
		BreakGlass:     principal.BreakGlass,
		IncidentReason: principal.IncidentReason,
	})
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	prepare(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func prepare(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
}

func writeStatus(w http.ResponseWriter, status int) {
	code := "unavailable"
	switch status {
	case http.StatusUnauthorized:
		code = "unauthenticated"
	case http.StatusForbidden:
		code = "forbidden"
	case http.StatusBadRequest:
		code = "invalid_request"
	}
	writeJSON(w, status, errorBody{Error: code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	prepare(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, errNotFound), errors.Is(err, errUnauthenticated), errors.Is(err, errStaleObservation):
		return http.StatusUnauthorized
	default:
		return http.StatusServiceUnavailable
	}
}

func statusForDecision(dec accessDecision) int {
	if dec.Kind == accessForbidden {
		return http.StatusForbidden
	}
	return http.StatusUnauthorized
}

func validCode(code string) bool {
	if code == "" || len(code) > 2048 {
		return false
	}
	for _, r := range code {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
