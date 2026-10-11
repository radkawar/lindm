package devlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
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
}

// OpenLocalAuthorityFixture uses the existing isolated process/database lifecycle
// but bootstraps two local owners through the CLI and real HTTPS ceremonies.
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

type enrollmentOutput struct {
	data [4096]byte
	n    int
}

func (b *enrollmentOutput) Write(p []byte) (int, error) {
	if len(p) > len(b.data)-b.n {
		return 0, io.ErrShortBuffer
	}
	n := copy(b.data[b.n:], p)
	b.n += n
	return n, nil
}

func (f *AuthorityFixture) bootstrapLocalOwner(ctx context.Context) (string, error) {
	var output enrollmentOutput
	defer clear(output.data[:])
	if err := labexec.Run(ctx, labexec.Command{Path: f.binary, Args: []string{"bootstrap-owner", "-config", f.configPath(), "-username", "owner"}, Stdout: &output, Stderr: f.log, Timeout: time.Minute}); err != nil {
		return "", errors.New("bootstrap local fixture owner failed")
	}
	lines := bytes.Split(bytes.TrimSpace(output.data[:output.n]), []byte("\n"))
	if len(lines) != 4 || string(lines[0]) != "Enrollment URL: "+f.ConsoleOrigin+"/enroll" {
		return "", errors.New("unexpected local bootstrap output")
	}
	secret, ok := bytes.CutPrefix(lines[1], []byte("Enrollment secret (shown once): "))
	id, idOK := bytes.CutPrefix(lines[3], []byte("Account ID: "))
	accountID, err := uuid.ParseBytes(id)
	if !ok || !idOK || len(secret) == 0 || err != nil || accountID == uuid.Nil {
		return "", errors.New("invalid local bootstrap enrollment")
	}
	owner, err := newLocalAccount("owner", accountID.String())
	if err != nil {
		return "", err
	}
	f.local = &localAuthority{owner: owner}
	return string(secret), nil
}

func newLocalAccount(username, id string) (*localAccount, error) {
	authenticator, err := webauthnlab.New("localhost")
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
	dial := ownerDialContext(f.AdminAddress)
	if f.connected != nil {
		dial = f.connectedDialContext()
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: dial, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	session := &OwnerSession{client: client, transport: transport, local: account, AccountID: account.id, origin: f.ConsoleOrigin}
	session.Admin = adminv1connect.NewAdminServiceClient(client, f.ConsoleOrigin, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
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
	return s.localCeremonyRole(ctx, secret, "owner")
}

func (s *OwnerSession) localCeremonyRole(ctx context.Context, secret, role string) error {
	a := s.local
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.authenticator == nil || len(a.password) == 0 {
		return errors.New("local fixture credential is closed")
	}
	kind := "login"
	var request proto.Message = &authv1.LocalLoginRequest{Username: a.username, Password: string(a.password)}
	if secret != "" {
		kind = "enroll"
		request = &authv1.LocalEnrollmentRequest{Secret: secret, Password: string(a.password)}
	}
	challenge := new(authv1.WebAuthnChallenge)
	if err := s.localRequest(ctx, "/auth/local/"+kind+"/begin", request, challenge, http.StatusOK); err != nil {
		return err
	}
	var options struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(challenge.GetOptionsJson()), &options); err != nil || options.Challenge == "" {
		return errors.New("invalid fixture WebAuthn challenge")
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
	f.local.approver, err = newLocalAccount(approverName, id.String())
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
	actor := f.local.owner
	if accountID == f.local.owner.id {
		actor = f.local.approver
	} else if accountID != f.local.approver.id {
		return errors.New("account is not owned by this fixture")
	}
	session, err := f.openLocalSession(ctx, actor)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close(ctx)) }()
	return session.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: accountID, Enabled: false, Role: "owner"}, nil, http.StatusNoContent)
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
	return session.localRequest(ctx, "/auth/accounts/update", &authv1.UpdateAccountRequest{AccountId: accountID, Enabled: true, Role: "owner"}, nil, http.StatusNoContent)
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
