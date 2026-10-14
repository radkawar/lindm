// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
	"lindm/internal/rpcreason"
)

func (s *Service) registerLocalHTTP(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/options", func(w http.ResponseWriter, r *http.Request) {
		available := false
		if s.localPrimary {
			var err error
			available, err = identitydb.New(s.pool).SetupAvailable(r.Context())
			if err != nil {
				writeStatus(w, http.StatusServiceUnavailable)
				return
			}
		}
		writeProto(w, s.authenticationOptions(available))
	})
	mux.HandleFunc("POST /auth/local/login/begin", s.handleLocalLoginBegin)
	mux.HandleFunc("POST /auth/setup/begin", s.handleSetupBegin)
	mux.HandleFunc("POST /auth/local/login/finish", s.handleLocalLoginFinish)
	mux.Handle("POST /auth/local/step-up/begin", s.RequireSession(http.HandlerFunc(s.handleLocalStepUpBegin)))
	mux.Handle("POST /auth/local/step-up/finish", s.RequireSession(http.HandlerFunc(s.handleLocalStepUpFinish)))
	mux.HandleFunc("POST /auth/local/enroll/begin", s.handleLocalEnrollBegin)
	mux.HandleFunc("POST /auth/local/enroll/finish", s.handleLocalEnrollFinish)
	mux.Handle("GET /auth/accounts", s.RequireSession(http.HandlerFunc(s.handleAccounts)))
	mux.Handle("POST /auth/accounts/create", s.RequireSession(http.HandlerFunc(s.handleCreateAccount)))
	mux.Handle("POST /auth/accounts/update", s.RequireSession(http.HandlerFunc(s.handleUpdateAccount)))
	mux.Handle("POST /auth/accounts/reset", s.RequireSession(http.HandlerFunc(s.handleResetAccount)))
}

// authenticationOptions projects configured login modes and the already queried
// setup availability; it does not decide whether setup may admit an owner.
func (s *Service) authenticationOptions(setupAvailable bool) *authv1.AuthenticationOptions {
	return &authv1.AuthenticationOptions{
		ExternalLogin:  !s.localPrimary,
		LocalLogin:     s.localPrimary || s.breakGlass != nil,
		BreakGlass:     !s.localPrimary && s.breakGlass != nil,
		SetupAvailable: setupAvailable,
	}
}

func (s *Service) readAuthRequest(w http.ResponseWriter, r *http.Request, message proto.Message) bool {
	if !originMatches(s.publicOrigin, r.Header.Get("Origin")) {
		writeStatus(w, http.StatusForbidden)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
	if err != nil || protojson.Unmarshal(body, message) != nil || s.rules.Validate(message) != nil {
		writeStatus(w, http.StatusBadRequest)
		return false
	}
	return true
}

func writeProto(w http.ResponseWriter, message proto.Message) {
	body, err := (protojson.MarshalOptions{EmitDefaultValues: true}).Marshal(message)
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	prepare(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Service) handleLocalLoginBegin(w http.ResponseWriter, r *http.Request) {
	request := &authv1.LocalLoginRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	result, err := s.beginLocalLogin(r.Context(), request, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, errUnauthenticated) {
			// One reason for unknown, wrong, disabled and locked: never an
			// account-existence oracle, but the console can say what to fix.
			w.Header().Set(rpcreason.Header, "invalid_credentials")
		}
		writeStatus(w, statusFor(err))
		return
	}
	writeProto(w, result)
}

// Step-up refusals carry a reason the console can act on: a wrong password
// (same reason as sign-in), a failed passkey check, or a session that can
// never step up (organization sign-in, service account).
func writeStepUpRefusal(w http.ResponseWriter, err error, credentialReason string) {
	switch {
	case errors.Is(err, errUnauthenticated):
		w.Header().Set(rpcreason.Header, credentialReason)
		writeStatus(w, http.StatusUnauthorized)
	case errors.Is(err, ErrAuthorizationDenied):
		w.Header().Set(rpcreason.Header, "step_up_unavailable")
		writeStatus(w, http.StatusForbidden)
	default:
		writeStatus(w, statusFor(err))
	}
}

func (s *Service) handleLocalStepUpBegin(w http.ResponseWriter, r *http.Request) {
	request := &authv1.LocalStepUpRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	result, err := s.beginLocalStepUp(r.Context(), request, r.RemoteAddr)
	if err != nil {
		writeStepUpRefusal(w, err, "invalid_credentials")
		return
	}
	writeProto(w, result)
}

func (s *Service) handleLocalStepUpFinish(w http.ResponseWriter, r *http.Request) {
	request := &authv1.WebAuthnFinishRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	if err := s.finishLocalStepUp(r.Context(), request, r.RemoteAddr); err != nil {
		writeStepUpRefusal(w, err, "step_up_failed")
		return
	}
	prepare(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleLocalEnrollBegin(w http.ResponseWriter, r *http.Request) {
	request := &authv1.LocalEnrollmentRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	result, err := s.beginLocalEnrollment(r.Context(), request)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	writeProto(w, result)
}
func (s *Service) handleLocalEnrollFinish(w http.ResponseWriter, r *http.Request) {
	request := &authv1.WebAuthnFinishRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	cookie, err := s.finishLocalCeremony(r.Context(), request, "enroll", r.RemoteAddr)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
	if cookie != "" {
		setHostCookie(w, sessionCookie, cookie, sessionCookieMaxAge)
	}
	prepare(w)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Service) handleLocalLoginFinish(w http.ResponseWriter, r *http.Request) {
	request := &authv1.WebAuthnFinishRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	cookie, err := s.finishLocalCeremony(r.Context(), request, "login", r.RemoteAddr)
	if err != nil {
		writeStatus(w, statusFor(err))
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
	lifetime := sessionCookieMaxAge
	if principal.BreakGlass {
		lifetime = int(s.breakGlass.GetMaxSessionLifetime().AsDuration().Seconds())
	}
	setHostCookie(w, sessionCookie, cookie, lifetime)
	writeSession(w, principal)
}

func (s *Service) accountTransaction(ctx context.Context, fn func(*identitydb.Queries, Principal) error) error {
	actor, ok := PrincipalFromContext(ctx)
	unrestricted, _ := DeviceScopes(actor, PermissionManageAccounts)
	if !ok || !unrestricted {
		return ErrAuthorizationDenied
	}
	authorization, err := s.AuthorizeFresh(ctx, actor.ID, PermissionManageAccounts)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = s.LockAuthorization(ctx, tx, authorization, PermissionManageAccounts); err != nil {
		return err
	}
	if unrestricted, _ := DeviceScopes(authorization.Principal(), PermissionManageAccounts); !unrestricted {
		return ErrAuthorizationDenied
	}
	if err = fn(identitydb.New(tx), actor); err != nil {
		return err
	}
	return s.dbErr(tx.Commit(ctx))
}
func accountStatus(err error) int {
	if err == ErrAuthorizationDenied || err == ErrAuthorizationChanged || err == ErrAuthorizationExpired {
		return http.StatusForbidden
	}
	return statusFor(err)
}
func (s *Service) handleAccounts(w http.ResponseWriter, r *http.Request) {
	response, err := s.BrowserAccounts().ListAccounts(r.Context())
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, response)
}
func enrollmentProto(enrollment Enrollment) *authv1.AccountEnrollment {
	return &authv1.AccountEnrollment{AccountId: enrollment.AccountID.String(), Secret: enrollment.Secret, ExpiresAt: timestamppb.New(enrollment.ExpiresAt)}
}
func (s *Service) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	request := &authv1.CreateAccountRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	enrollment, err := s.BrowserAccounts().CreateAccount(r.Context(), request)
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, enrollment)
}
func (s *Service) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	request := &authv1.UpdateAccountRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	err := s.BrowserAccounts().UpdateAccount(r.Context(), request)
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Service) handleResetAccount(w http.ResponseWriter, r *http.Request) {
	request := &authv1.ResetAccountRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	id, err := uuid.Parse(request.GetAccountId())
	if err != nil {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	var enrollment Enrollment
	err = s.accountTransaction(r.Context(), func(q *identitydb.Queries, actor Principal) error {
		if _, err := q.GetPrincipalForUpdate(r.Context(), id); err != nil {
			return s.dbErr(err)
		}
		var err error
		enrollment, err = s.resetLocalCredentials(r.Context(), q, id)
		if err != nil {
			return err
		}
		return s.insertSystemAudit(r.Context(), q, &actor.ID, auditkind.IdentityLocalCredentialsReset, principalResource(id), "credentials, sessions and pending authority revoked")
	})
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, enrollmentProto(enrollment))
}
