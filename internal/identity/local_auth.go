package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/identity/identitydb"
)

func (s *Service) localLoginAllowed(account identitydb.LocalAccount, reason, remote string) bool {
	if !account.Enabled {
		return false
	}
	if s.localPrimary {
		return true
	}
	if !account.BreakGlass || account.Role != RoleOwner || s.breakGlass == nil || reason == "" {
		return false
	}
	if s.breakGlass.GetConsoleOnly() {
		host, _, err := net.SplitHostPort(remote)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return false
		}
	}
	return true
}

func (s *Service) localUser(ctx context.Context, q *identitydb.Queries, account identitydb.LocalAccount) (*localWebAuthnUser, error) {
	rows, err := q.ListLocalCredentials(ctx, account.ID)
	if err != nil {
		return nil, s.dbErr(err)
	}
	user := &localWebAuthnUser{ID: account.ID, Username: account.Username, Credentials: make([]webauthn.Credential, 0, len(rows))}
	for _, row := range rows {
		var credential webauthn.Credential
		if err = json.Unmarshal(row.CredentialJson, &credential); err != nil {
			return nil, errStore
		}
		user.Credentials = append(user.Credentials, credential)
	}
	return user, nil
}

func (s *Service) beginLocalLogin(ctx context.Context, request *authv1.LocalLoginRequest, remote string) (*authv1.WebAuthnChallenge, error) {
	initial, err := identitydb.New(s.pool).GetLocalAccountByUsername(ctx, request.GetUsername())
	if err != nil && !errors.Is(s.dbErr(err), errNotFound) {
		return nil, s.dbErr(err)
	}
	encoded := initial.PasswordHash
	if encoded == "" {
		encoded = s.dummyHash
	}
	passwordOK, err := s.verifyLocalPassword(ctx, encoded, request.GetPassword())
	if err != nil {
		return nil, err
	}
	if initial.ID == uuid.Nil {
		return nil, errUnauthenticated
	}
	var challenge *authv1.WebAuthnChallenge
	denied := false
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		principal, err := q.GetPrincipalForUpdate(ctx, initial.ID)
		if err != nil {
			return s.dbErr(err)
		}
		account, err := q.GetLocalAccount(ctx, initial.ID)
		if err != nil {
			return s.dbErr(err)
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		locked := account.LockedUntil.Valid && now.Before(account.LockedUntil.Time)
		eligible := s.localLoginAllowed(account, request.GetIncidentReason(), remote) &&
			initial.PasswordHash != "" && account.PasswordHash == initial.PasswordHash
		if !passwordOK || !eligible || locked {
			denied = true
			if eligible && !locked && !passwordOK {
				if err = q.RecordLocalFailure(ctx, account.ID); err != nil {
					return s.dbErr(err)
				}
			}
			action := "identity.local_login_denied"
			if !s.localPrimary {
				action = "identity.break_glass_denied"
			}
			return s.insertAudit(ctx, q, &account.ID, action, principalResource(account.ID), "local authentication denied")
		}
		user, err := s.localUser(ctx, q, account)
		if err != nil {
			return err
		}
		options, session, err := s.webauthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return errUnauthenticated
		}
		challenge, err = s.persistCeremony(ctx, q, principal, "login", session, options.Response, "", request.GetIncidentReason(), nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, errUnauthenticated
	}
	return challenge, nil
}

func (s *Service) beginLocalEnrollment(ctx context.Context, request *authv1.LocalEnrollmentRequest) (*authv1.WebAuthnChallenge, error) {
	digest := domainHash("lindm.local.enrollment.v1", request.GetSecret())
	id, err := identitydb.New(s.pool).FindLocalEnrollment(ctx, digest)
	if err != nil {
		return nil, errUnauthenticated
	}
	password, err := s.hashLocalPassword(ctx, request.GetPassword())
	if err != nil {
		return nil, err
	}
	var challenge *authv1.WebAuthnChallenge
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		principal, err := q.GetPrincipalForUpdate(ctx, id)
		if err != nil {
			return s.dbErr(err)
		}
		account, err := q.GetLocalAccount(ctx, id)
		if err != nil {
			return s.dbErr(err)
		}
		if !account.Enabled {
			return errUnauthenticated
		}
		current, err := q.FindLocalEnrollment(ctx, digest)
		if err != nil || current != id {
			return errUnauthenticated
		}
		user, err := s.localUser(ctx, q, account)
		if err != nil {
			return err
		}
		options, session, err := s.webauthn.BeginRegistration(user)
		if err != nil {
			return errUnauthenticated
		}
		challenge, err = s.persistCeremony(ctx, q, principal, "enroll", session, options.Response, password, "", digest)
		return err
	})
	return challenge, err
}

// localCeremonySession binds enrollment to its hash-only secret without retaining
// the secret itself. Registration may be restarted until a credential commits.
type localCeremonySession struct {
	webauthn.SessionData
	EnrollmentSecretHash []byte `json:"enrollment_secret_hash,omitempty"`
}

func (s *Service) persistCeremony(ctx context.Context, q *identitydb.Queries, principal identitydb.Principal, kind string, session *webauthn.SessionData, options any, password, reason string, enrollmentHash []byte) (*authv1.WebAuthnChallenge, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	redacted, digest := redactWebAuthnSession(*session)
	data, err := json.Marshal(localCeremonySession{SessionData: redacted, EnrollmentSecretHash: enrollmentHash})
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	if err = q.PurgeLocalCeremonies(ctx); err != nil {
		return nil, s.dbErr(err)
	}
	if err = q.DeleteLocalCeremonies(ctx, principal.ID); err != nil {
		return nil, s.dbErr(err)
	}
	err = q.InsertLocalCeremony(ctx, identitydb.InsertLocalCeremonyParams{TokenHash: domainHash("lindm.local.ceremony.v1", token), AccountID: principal.ID, Kind: kind, ChallengeHash: digest, SessionData: data, PasswordHash: password, IncidentReason: reason, AuthorizationVersion: principal.AuthorizationVersion})
	if err != nil {
		return nil, s.dbErr(err)
	}
	return &authv1.WebAuthnChallenge{Token: token, OptionsJson: string(encoded)}, nil
}

func (s *Service) finishLocalCeremony(ctx context.Context, request *authv1.WebAuthnFinishRequest, kind, remote string) (result string, resultErr error) {
	// Consumption commits before parsing or verification: even a failed response cannot replay a challenge.
	ceremony, err := identitydb.New(s.pool).ConsumeLocalCeremony(ctx, identitydb.ConsumeLocalCeremonyParams{TokenHash: domainHash("lindm.local.ceremony.v1", request.GetToken()), Kind: kind})
	if err != nil {
		return "", errUnauthenticated
	}
	defer func() {
		if resultErr != nil && kind == "login" {
			failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			action := "identity.local_mfa_denied"
			if !s.localPrimary {
				action = "identity.break_glass_denied"
			}
			resultErr = errors.Join(resultErr, s.emergencyAudit(failureCtx, ceremony.AccountID, action, "WebAuthn ceremony denied"))
		}
	}()
	var stored localCeremonySession
	if err = json.Unmarshal(ceremony.SessionData, &stored); err != nil {
		return "", errStore
	}
	var envelope struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err = json.Unmarshal([]byte(request.GetCredentialJson()), &envelope); err != nil {
		return "", errUnauthenticated
	}
	client, err := base64.RawURLEncoding.DecodeString(envelope.Response.ClientDataJSON)
	if err != nil {
		return "", errUnauthenticated
	}
	session, err := restoreWebAuthnSession(stored.SessionData, ceremony.ChallengeHash, client)
	if err != nil {
		return "", errUnauthenticated
	}
	var cookie string
	denied := false
	err = s.withTx(ctx, func(q *identitydb.Queries) error {
		principal, err := q.GetPrincipalForUpdate(ctx, ceremony.AccountID)
		if err != nil {
			return s.dbErr(err)
		}
		account, err := q.GetLocalAccount(ctx, ceremony.AccountID)
		if err != nil {
			return s.dbErr(err)
		}
		now, err := s.authorizationTime(ctx, q)
		if err != nil {
			return err
		}
		if !account.Enabled || principal.AuthorizationVersion != ceremony.AuthorizationVersion || !now.Before(ceremony.ExpiresAt.Time) {
			return errUnauthenticated
		}
		user, err := s.localUser(ctx, q, account)
		if err != nil {
			return err
		}
		var credential *webauthn.Credential
		if kind == "enroll" {
			parsed, parseErr := protocol.ParseCredentialCreationResponseBytes([]byte(request.GetCredentialJson()))
			if parseErr != nil {
				return errUnauthenticated
			}
			credential, err = s.webauthn.CreateCredential(user, session, parsed)
		} else {
			if !s.localLoginAllowed(account, ceremony.IncidentReason, remote) || (account.LockedUntil.Valid && now.Before(account.LockedUntil.Time)) {
				return errUnauthenticated
			}
			parsed, parseErr := protocol.ParseCredentialRequestResponseBytes([]byte(request.GetCredentialJson()))
			if parseErr != nil {
				denied = true
				return s.dbErr(q.RecordLocalFailure(ctx, account.ID))
			}
			credential, err = s.webauthn.ValidateLogin(user, session, parsed)
		}
		if err != nil || credential == nil || credential.Authenticator.CloneWarning {
			denied = true
			if kind == "login" {
				if err := q.RecordLocalFailure(ctx, account.ID); err != nil {
					return s.dbErr(err)
				}
			}
			return s.insertAudit(ctx, q, &account.ID, "identity.local_mfa_denied", principalResource(account.ID), "WebAuthn verification denied")
		}
		data, err := json.Marshal(credential)
		if err != nil {
			return err
		}
		if kind == "enroll" {
			consumed, err := q.ConsumeLocalEnrollment(ctx, stored.EnrollmentSecretHash)
			if err != nil || consumed != account.ID {
				return errUnauthenticated
			}
			if err = q.InsertLocalCredential(ctx, identitydb.InsertLocalCredentialParams{CredentialID: credential.ID, AccountID: account.ID, CredentialJson: data}); err != nil {
				return s.dbErr(err)
			}
			if err = q.SetLocalPassword(ctx, identitydb.SetLocalPasswordParams{ID: account.ID, PasswordHash: ceremony.PasswordHash}); err != nil {
				return s.dbErr(err)
			}
			return s.insertAudit(ctx, q, &account.ID, "identity.local_enrolled", principalResource(account.ID), "")
		}
		if err = q.UpdateLocalCredential(ctx, identitydb.UpdateLocalCredentialParams{CredentialID: credential.ID, AccountID: account.ID, CredentialJson: data}); err != nil {
			return s.dbErr(err)
		}
		if err = q.ClearLocalFailures(ctx, account.ID); err != nil {
			return s.dbErr(err)
		}
		cookie, err = randomToken()
		if err != nil {
			return err
		}
		lifetime := 12 * time.Hour
		reason := ""
		action := auditLogin
		if !s.localPrimary {
			lifetime = s.breakGlass.GetMaxSessionLifetime().AsDuration()
			reason = ceremony.IncidentReason
			action = "identity.break_glass_activated"
		}
		if err = q.InsertLocalSession(ctx, identitydb.InsertLocalSessionParams{TokenHash: sessionHash(cookie), PrincipalID: account.ID, ExpiresAt: pgStamp(now.Add(lifetime), true), BreakGlass: !s.localPrimary, IncidentReason: reason}); err != nil {
			return s.dbErr(err)
		}
		return s.insertAudit(ctx, q, &account.ID, action, principalResource(account.ID), reason)
	})
	if err != nil {
		return "", err
	}
	if denied {
		return "", errUnauthenticated
	}
	return cookie, nil
}

func (s *Service) verifyLocalPassword(ctx context.Context, encoded, password string) (bool, error) {
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
		return verifyPassword(encoded, password), nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (s *Service) hashLocalPassword(ctx context.Context, password string) (string, error) {
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
		return hashPassword(password)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
