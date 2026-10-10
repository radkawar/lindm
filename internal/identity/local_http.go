package identity

import (
	"context"
	"io"
	"net/http"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func (s *Service) registerLocalHTTP(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/options", func(w http.ResponseWriter, r *http.Request) {
		writeProto(w, &authv1.AuthenticationOptions{ExternalLogin: !s.localPrimary, LocalLogin: s.localPrimary || s.breakGlass != nil, BreakGlass: !s.localPrimary && s.breakGlass != nil})
	})
	mux.HandleFunc("POST /auth/local/login/begin", s.handleLocalLoginBegin)
	mux.HandleFunc("POST /auth/local/login/finish", s.handleLocalLoginFinish)
	mux.HandleFunc("POST /auth/local/enroll/begin", s.handleLocalEnrollBegin)
	mux.HandleFunc("POST /auth/local/enroll/finish", s.handleLocalEnrollFinish)
	mux.Handle("GET /auth/accounts", s.RequireSession(http.HandlerFunc(s.handleAccounts)))
	mux.Handle("POST /auth/accounts/create", s.RequireSession(http.HandlerFunc(s.handleCreateAccount)))
	mux.Handle("POST /auth/accounts/update", s.RequireSession(http.HandlerFunc(s.handleUpdateAccount)))
	mux.Handle("POST /auth/accounts/reset", s.RequireSession(http.HandlerFunc(s.handleResetAccount)))
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
		writeStatus(w, statusFor(err))
		return
	}
	writeProto(w, result)
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
	_, err := s.finishLocalCeremony(r.Context(), request, "enroll", r.RemoteAddr)
	if err != nil {
		writeStatus(w, statusFor(err))
		return
	}
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
	response := &authv1.ListAccountsResponse{Roles: append([]string(nil), s.policy.names...)}
	err := s.accountTransaction(r.Context(), func(q *identitydb.Queries, _ Principal) error {
		rows, err := q.ListLocalAccounts(r.Context())
		if err != nil {
			return s.dbErr(err)
		}
		for _, row := range rows {
			binding := &authv1.RoleBinding{}
			if err := protojson.Unmarshal(row.ScopeBinding, binding); err != nil {
				return errStore
			}
			response.Accounts = append(response.Accounts, &authv1.LocalAccount{Id: row.ID.String(), Username: row.Username, Role: row.Role, Enabled: row.Enabled, BreakGlass: row.BreakGlass, Enrolled: row.Enrolled, Scopes: binding.GetScopes()})
		}
		return nil
	})
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
	var enrollment Enrollment
	err := s.accountTransaction(r.Context(), func(q *identitydb.Queries, actor Principal) error {
		var err error
		enrollment, err = s.createLocalAccount(r.Context(), q, request)
		if err != nil {
			return err
		}
		return s.insertAudit(r.Context(), q, &actor.ID, "identity.local_account_created", principalResource(enrollment.AccountID), "")
	})
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, enrollmentProto(enrollment))
}
func (s *Service) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	request := &authv1.UpdateAccountRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	if s.policy.role(request.GetRole()) == nil {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(request.GetAccountId())
	if err != nil {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	err = s.accountTransaction(r.Context(), func(q *identitydb.Queries, actor Principal) error {
		if _, err := q.GetPrincipalForUpdate(r.Context(), id); err != nil {
			return s.dbErr(err)
		}
		account, err := q.GetLocalAccount(r.Context(), id)
		if err != nil {
			return s.dbErr(err)
		}
		previous := &authv1.RoleBinding{}
		if err := protojson.Unmarshal(account.ScopeBinding, previous); err != nil {
			return errStore
		}
		binding := &authv1.RoleBinding{Scopes: request.GetScopes()}
		encoded, err := protojson.Marshal(binding)
		if err != nil {
			return err
		}
		if account.Enabled == request.GetEnabled() && account.Role == request.GetRole() && account.BreakGlass == request.GetBreakGlass() && proto.Equal(previous, binding) {
			return nil
		}
		if err := q.UpdateLocalAccount(r.Context(), identitydb.UpdateLocalAccountParams{ID: id, Enabled: request.GetEnabled(), Role: request.GetRole(), BreakGlass: request.GetBreakGlass(), ScopeBinding: encoded}); err != nil {
			return s.dbErr(err)
		}
		role := request.GetRole()
		if !request.GetEnabled() {
			role = ""
		}
		if err := s.invalidateLocalAccount(r.Context(), q, id, role); err != nil {
			return err
		}
		return s.insertAudit(r.Context(), q, &actor.ID, "identity.local_account_updated", principalResource(id), "sessions and pending authority revoked")
	})
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
		return s.insertAudit(r.Context(), q, &actor.ID, "identity.local_credentials_reset", principalResource(id), "credentials, sessions and pending authority revoked")
	})
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, enrollmentProto(enrollment))
}
