// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"lindm/gen/lindm/admin/v1/adminv1connect"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/devlab/webauthnlab"
	"lindm/internal/labexec"
)

type localAuthority struct {
	owner, approver *localAccount
}

type localAccount struct {
	mu            sync.Mutex
	id, username  string
	password      []byte
	authenticator *webauthnlab.Authenticator
	counter       uint32
	statePath     string
	// role is the account's role in memory only; empty means owner.
	role string
}

func (a *localAccount) accountRole() string {
	if a.role == "" {
		return "owner"
	}
	return a.role
}

// OpenLocalAuthorityFixture uses the existing isolated process/database lifecycle
// but claims the first local owner through protected setup and real HTTPS ceremonies.
// It never reserves the shared console port or changes shared accounts.
func OpenLocalAuthorityFixture(ctx context.Context, repository, binary string) (*AuthorityFixture, error) {
	return openAuthorityFixture(ctx, repository, binary, authorityLocal)
}

// OpenDeviceActionAuthorityFixture signs both allocated listener ports into its
// private bootstrap before starting the server. Recovery guests can reach those
// exact HTTPS origins without a console-port tunnel or a TLS/origin override.
// Call ReadAgentFixture for the signed provisioning bytes used by this instance.
func OpenDeviceActionAuthorityFixture(ctx context.Context, repository, binary string) (*AuthorityFixture, error) {
	return openAuthorityFixture(ctx, repository, binary, authorityDeviceActions)
}

func (f *AuthorityFixture) bootstrapLocalOwner(ctx context.Context) (_ string, resultErr error) {
	path := filepath.Join(f.directory, "first-run-code")
	if err := labexec.Run(ctx, labexec.Command{Path: f.binary, Args: []string{"setup-code", "-config", f.configPath(), "-output", path}, Stdout: f.log, Stderr: f.log, Timeout: time.Minute}); err != nil {
		return "", errors.New("issue local fixture setup code failed")
	}
	defer func() { resultErr = errors.Join(resultErr, os.Remove(path)) }()
	code, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("read local fixture setup code failed")
	}
	defer clear(code)
	if len(code) != 44 || code[43] != '\n' {
		return "", errors.New("invalid local fixture setup code file")
	}
	owner, err := newLocalAccount(f.relyingPartyID(), "owner", "")
	if err != nil {
		return "", err
	}
	f.local = &localAuthority{owner: owner}
	return string(code[:43]), nil
}

// relyingPartyID is the WebAuthn RP ID lindmd derives from its public_url host.
func (f *AuthorityFixture) relyingPartyID() string {
	if f.publicHost != "" {
		return f.publicHost
	}
	return "localhost"
}

// adminDial reaches the admin listener under the console origin's name: a lab
// public host need not resolve on the controller, and TLS still verifies it.
func (f *AuthorityFixture) adminDial(adminAddress string) func(context.Context, string, string) (net.Conn, error) {
	dial := ownerDialContext(adminAddress)
	if f.publicHost == "" {
		return dial
	}
	origin := strings.TrimPrefix(f.ConsoleOrigin, "https://")
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == origin {
			address = adminAddress
		}
		return dial(ctx, network, address)
	}
}

func newLocalAccount(rpID, username, id string) (*localAccount, error) {
	authenticator, err := webauthnlab.New(rpID)
	if err != nil {
		return nil, err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	defer clear(random[:])
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(random)))
	base64.RawURLEncoding.Encode(password, random[:])
	return &localAccount{id: id, username: username, password: password, authenticator: authenticator}, nil
}

func (f *AuthorityFixture) newLocalSession(account *localAccount) (*OwnerSession, error) {
	if f.closed || account == nil {
		return nil, errors.New("local authority fixture is unavailable")
	}
	tlsConfig, err := f.localTLSConfig()
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	dial := f.adminDial(f.AdminAddress)
	if f.connected != nil {
		dial = f.connectedDialContext()
	}
	// The header timeout exceeds the server's own 15 s RPC bound, so a loaded
	// host answers with its definitive result instead of a client-side cut.
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: dial, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	session := &OwnerSession{client: client, transport: transport, local: account, AccountID: account.id, origin: f.ConsoleOrigin}
	session.Admin = adminv1connect.NewAdminServiceClient(client, f.ConsoleOrigin, connect.WithInterceptors(connect.UnaryInterceptorFunc(retryLoadedHost), connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Origin", f.ConsoleOrigin)
			req.Header().Set("X-CSRF-Token", session.csrf)
			return next(ctx, req)
		}
	})))
	return session, nil
}

func (s *OwnerSession) localRequest(ctx context.Context, path string, request, result proto.Message, status int) error {
	body, err := protojson.Marshal(request)
	if err != nil {
		return err
	}
	defer clear(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.origin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", s.origin)
	if path == "/auth/setup/begin" {
		req.Header.Set("X-Lindm-Setup", "1")
	}
	if s.csrf != "" {
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	response, err := s.client.Do(req)
	if err != nil {
		return errors.New("local fixture HTTPS request failed")
	}
	encoded, err := readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	defer clear(encoded)
	if err != nil {
		return err
	}
	if response.StatusCode != status {
		return fmt.Errorf("local fixture %s: HTTP %d", path, response.StatusCode)
	}
	if result != nil {
		return protojson.Unmarshal(encoded, result)
	}
	return nil
}

// localCeremony serializes this credential's counter through server acceptance.
func (s *OwnerSession) localCeremony(ctx context.Context, secret string) error {
	return s.localCeremonyRole(ctx, secret, s.local.accountRole())
}

func (s *OwnerSession) localCeremonyRole(ctx context.Context, secret, role string) error {
	a := s.local
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.authenticator == nil || len(a.password) == 0 {
		return errors.New("local fixture credential is closed")
	}
	path := "/auth/local/login/begin"
	var request proto.Message = &authv1.LocalLoginRequest{Username: a.username, Password: string(a.password)}
	setup := secret != "" && a.id == ""
	if setup {
		path = "/auth/setup/begin"
		request = &authv1.FirstRunSetupRequest{Code: secret, Username: a.username, Password: string(a.password)}
	} else if secret != "" {
		path = "/auth/local/enroll/begin"
		request = &authv1.LocalEnrollmentRequest{Secret: secret, Password: string(a.password)}
	}
	challenge := new(authv1.WebAuthnChallenge)
	if err := s.localRequest(ctx, path, request, challenge, http.StatusOK); err != nil {
		return err
	}
	var options struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(challenge.GetOptionsJson()), &options); err != nil || options.Challenge == "" {
		return errors.New("invalid fixture WebAuthn challenge")
	}
	if setup {
		raw, err := base64.RawURLEncoding.DecodeString(options.User.ID)
		if err != nil {
			return errors.New("invalid fixture setup user handle")
		}
		id, err := uuid.FromBytes(raw)
		if err != nil || id == uuid.Nil {
			return errors.New("invalid fixture setup identity")
		}
		a.id, s.AccountID = id.String(), id.String()
	}
	if a.counter == ^uint32(0) {
		return errors.New("fixture authenticator counter exhausted")
	}
	a.counter++
	// Persist before sending the assertion: an ambiguous response must never
	// cause reuse of a counter already accepted by the server.
	if err := a.persist(); err != nil {
		return err
	}
	credential, _, err := a.authenticator.Response(options.Challenge, s.origin, secret != "", true, a.counter)
	if err != nil {
		return err
	}
	finish := &authv1.WebAuthnFinishRequest{Token: challenge.GetToken(), CredentialJson: string(credential)}
	if secret != "" {
		return s.localRequest(ctx, "/auth/local/enroll/finish", finish, nil, http.StatusNoContent)
	}
	principal := new(authv1.SessionPrincipal)
	if err := s.localRequest(ctx, "/auth/local/login/finish", finish, principal, http.StatusOK); err != nil {
		return err
	}
	if principal.GetId() != a.id || principal.GetRole() != role || principal.GetCsrfToken() == "" || principal.GetBreakGlass() || principal.GetServiceAccount() {
		return errors.New("local fixture session does not bind the enrolled owner")
	}
	s.csrf = principal.GetCsrfToken()
	return nil
}

func (f *AuthorityFixture) enrollLocalOwners(ctx context.Context, secret, approverName string) (resultErr error) {
	session, err := f.newLocalSession(f.local.owner)
	if err != nil {
		return err
	}
	defer session.transport.CloseIdleConnections()
	if err := session.localCeremony(ctx, secret); err != nil {
		return err
	}
	if err := session.localCeremony(ctx, ""); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close(ctx)) }()
	return f.enrollLocalApprover(ctx, session, approverName)
}

func (f *AuthorityFixture) enrollLocalApprover(ctx context.Context, session *OwnerSession, approverName string) error {
	enrollment := new(authv1.AccountEnrollment)
	if err := session.localRequest(ctx, "/auth/accounts/create", &authv1.CreateAccountRequest{Username: approverName, Role: "owner"}, enrollment, http.StatusOK); err != nil {
		return err
	}
	defer func() { enrollment.Secret = "" }()
	id, err := uuid.Parse(enrollment.GetAccountId())
	if err != nil || id == uuid.Nil || strings.TrimSpace(enrollment.GetSecret()) == "" {
		return errors.New("invalid fixture approver enrollment")
	}
	f.local.approver, err = newLocalAccount(f.relyingPartyID(), approverName, id.String())
	if err != nil {
		return err
	}
	approver, err := f.newLocalSession(f.local.approver)
	if err != nil {
		return err
	}
	defer approver.transport.CloseIdleConnections()
	return approver.localCeremony(ctx, enrollment.GetSecret())
}

func (f *AuthorityFixture) openLocalSession(ctx context.Context, account *localAccount) (*OwnerSession, error) {
	session, err := f.newLocalSession(account)
	if err != nil {
		return nil, err
	}
	if err := session.localCeremony(ctx, ""); err != nil {
		session.transport.CloseIdleConnections()
		return nil, err
	}
	return session, nil
}

func (f *AuthorityFixture) OpenApproverSession(ctx context.Context) (*OwnerSession, error) {
	if f.local == nil {
		return nil, errors.New("approver requires local authority fixture")
	}
	return f.openLocalSession(ctx, f.local.approver)
}

// StepUp retires any remaining session authority, then obtains fresh password +
// WebAuthn assurance even if the old session expired or was revoked. Like Close,
// it must not race other uses of this OwnerSession.
func (s *OwnerSession) StepUp(ctx context.Context) error {
	if s.local == nil {
		return errors.New("step-up requires local fixture authentication")
	}
	if s.csrf != "" {
		if err := s.Close(ctx); err != nil {
			return err
		}
	}
	return s.localCeremony(ctx, "")
}

// RevokeAccount disables one owned account through the real account API. Existing
// sessions and pending approval authority are invalidated by production identity.
func (f *AuthorityFixture) RevokeAccount(ctx context.Context, accountID string) (resultErr error) {
	if f.local == nil || f.local.approver == nil {
		return errors.New("account revocation requires local fixture owners")
	}
	actor, role := f.local.owner, f.local.approver.accountRole()
	if accountID == f.local.owner.id {
		if role != "owner" {
			return errors.New("an admin approver cannot revoke the fixture owner")
		}
		actor = f.local.approver
	} else if accountID != f.local.approver.id {
		return errors.New("account is not owned by this fixture")
	}
	session, err := f.openLocalSession(ctx, actor)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close(ctx)) }()
	return session.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: accountID, Enabled: false, Role: role}, nil, http.StatusNoContent)
}

// RestoreAccount re-enables only the owned approver through the normal account
// API. It never revives revoked sessions or approvals; obtain a fresh session.
func (f *AuthorityFixture) RestoreAccount(ctx context.Context, accountID string) (resultErr error) {
	if f.local == nil || f.local.approver == nil || accountID != f.local.approver.id {
		return errors.New("account restoration requires the owned fixture approver")
	}
	session, err := f.openLocalSession(ctx, f.local.owner)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close(ctx)) }()
	return session.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: accountID, Enabled: true, Role: f.local.approver.accountRole()}, nil, http.StatusNoContent)
}

// UseAdminApprover gives the fixture approver the built-in admin role, the least
// role holding every permission an approval can bind, through the real account
// API. Afterwards the approver decides every approval kind but cannot manage
// accounts, so RevokeAccount of the owner is refused. The role is not persisted:
// call it only on fixtures that never resume their accounts.
func (f *AuthorityFixture) UseAdminApprover(ctx context.Context) (resultErr error) {
	if f.local == nil || f.local.approver == nil {
		return errors.New("admin approver requires local fixture owners")
	}
	session, err := f.openLocalSession(ctx, f.local.owner)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close(ctx)) }()
	if err := session.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: f.local.approver.id, Enabled: true, Role: "admin"}, nil, http.StatusNoContent); err != nil {
		return err
	}
	f.local.approver.role = "admin"
	return nil
}

func (f *localAuthority) close() {
	for _, account := range []*localAccount{f.owner, f.approver} {
		if account != nil {
			account.mu.Lock()
			clear(account.password)
			account.password, account.authenticator = nil, nil
			account.mu.Unlock()
		}
	}
}
