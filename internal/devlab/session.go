// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/html"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
	authv1 "lindm/gen/lindm/auth/v1"
)

const consoleOrigin = "https://localhost:18444"

// OwnerSession is a real console login against the protected development fixture.
// It holds an in-memory cookie jar and request-scoped CSRF authority, never a
// production bypass, password grant, browser-storage export or service-account
// impersonation. Close revokes the console session through its normal HTTP route.
type OwnerSession struct {
	Admin     adminv1connect.AdminServiceClient
	AccountID string
	client    *http.Client
	transport *http.Transport
	csrf      string
	origin    string
	local     *localAccount
	login     func(context.Context) (*OwnerSession, error)
}

// OpenOwnerSession follows the server's authorization-code/S256-PKCE flow and
// submits only the fixed fixture owner's password to the pinned Keycloak origin.
// This deterministic fixture adapter deliberately does not automate arbitrary IdPs.
func OpenOwnerSession(ctx context.Context, repoRoot string) (_ *OwnerSession, resultErr error) {
	return openOwnerSession(ctx, repoRoot, "")
}

// openOwnerSession changes only this session's TCP destination. Logical URLs,
// TLS hostname verification, redirect checks and CSRF origins remain unchanged.
func openOwnerSession(ctx context.Context, repoRoot, adminAddress string) (_ *OwnerSession, resultErr error) {
	return openFixtureSession(ctx, repoRoot, adminAddress, nil)
}

type fixtureLoginAccount struct {
	username, password, subject, role string
}

// Only fixed or test-owned Keycloak accounts may reach this private login path.
func openFixtureSession(ctx context.Context, repoRoot, adminAddress string, account *fixtureLoginAccount) (_ *OwnerSession, resultErr error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, err
	}
	dir := FixturePath(root)
	if adminAddress != "" {
		if err := validateAuthorityFixture(dir); err != nil {
			return nil, err
		}
	} else {
		if err := validateFixture(dir); err != nil {
			return nil, err
		}
		if err := requireKeycloakFixture(dir); err != nil {
			return nil, err
		}
	}
	tlsConfig, err := trustClient(dir)
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	if adminAddress != "" {
		transport.DialContext = ownerDialContext(adminAddress)
	}
	seenPKCE := false
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 || !fixtureURL(req.URL) || req.Method != http.MethodGet {
			return errors.New("fixture login redirect rejected")
		}
		if req.URL.Path == "/realms/lindm/protocol/openid-connect/auth" {
			query := req.URL.Query()
			if query.Get("client_id") != "lindm-console" || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || query.Get("redirect_uri") != consoleOrigin+"/auth/callback" || query.Get("state") == "" || query.Get("nonce") == "" {
				return errors.New("fixture login did not use the expected code/PKCE flow")
			}
			seenPKCE = true
		}
		return nil
	}}
	session := &OwnerSession{client: client, transport: transport, origin: consoleOrigin}
	defer func() {
		if resultErr != nil {
			transport.CloseIdleConnections()
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, consoleOrigin+"/auth/login", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("fixture authorization login failed")
	}
	body, err := readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || !seenPKCE || response.Request.URL.Scheme+"://"+response.Request.URL.Host != "https://localhost:18443" {
		return nil, errors.New("fixture login did not reach the expected Keycloak form")
	}
	action, form, err := fixtureLoginForm(body, response.Request.URL)
	if err != nil {
		return nil, err
	}
	if account == nil {
		password, err := os.ReadFile(filepath.Join(dir, "owner-password"))
		if err != nil {
			return nil, errors.New("read protected fixture owner credential failed")
		}
		account = &fixtureLoginAccount{username: "owner", password: strings.TrimSpace(string(password)), subject: ownerSubject, role: "owner"}
		clear(password)
	}
	form.Set("username", account.username)
	form.Set("password", account.password)
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, action.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	form.Del("password")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://localhost:18443")
	response, err = client.Do(req)
	if err != nil {
		return nil, errors.New("fixture owner authorization failed")
	}
	_, err = readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Request.URL.Scheme+"://"+response.Request.URL.Host != consoleOrigin || response.Request.URL.Path != "/" {
		return nil, errors.New("fixture owner did not complete the authenticated callback")
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, consoleOrigin+"/auth/session", nil)
	if err != nil {
		return nil, err
	}
	response, err = client.Do(req)
	if err != nil {
		return nil, errors.New("read authenticated fixture session failed")
	}
	body, err = readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return nil, err
	}
	principal := new(authv1.SessionPrincipal)
	if response.StatusCode != http.StatusOK || protojson.Unmarshal(body, principal) != nil || principal.GetIssuer() != issuer || principal.GetSubject() != account.subject || principal.GetRole() != account.role || principal.GetCsrfToken() == "" {
		return nil, errors.New("fixture session does not bind the expected authorized account")
	}
	session.AccountID = principal.GetId()
	session.csrf = principal.GetCsrfToken()
	session.Admin = adminv1connect.NewAdminServiceClient(client, consoleOrigin, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Origin", consoleOrigin)
			req.Header().Set("X-CSRF-Token", session.csrf)
			return next(ctx, req)
		}
	})))
	return session, nil
}

func ownerDialContext(adminAddress string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "localhost:18444" {
			address = adminAddress
		}
		return dialer.DialContext(ctx, network, address)
	}
}

// ApproveApproval authenticates again before deciding an approval. Native local
// lanes use password + WebAuthn; directory approval fixtures repeat code/PKCE.
// Only authentication is renewed: a failed approval mutation is never retried.
func (s *OwnerSession) ApproveApproval(ctx context.Context, request *connect.Request[adminv1.ApproveApprovalRequest]) (_ *connect.Response[adminv1.ApproveApprovalResponse], resultErr error) {
	if s.local != nil {
		if err := s.StepUp(ctx); err != nil {
			return nil, err
		}
		return s.Admin.ApproveApproval(ctx, request)
	}
	if s.login == nil {
		return nil, errors.New("approval requires renewable laboratory authentication")
	}
	fresh, err := s.login(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, fresh.Close(context.WithoutCancel(ctx))) }()
	if fresh.AccountID != s.AccountID {
		return nil, errors.New("fresh approval login changed laboratory principal")
	}
	return fresh.Admin.ApproveApproval(ctx, request)
}

func (s *OwnerSession) Close(ctx context.Context) error {
	defer s.transport.CloseIdleConnections()
	if s.csrf == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.origin+"/auth/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Origin", s.origin)
	req.Header.Set("X-CSRF-Token", s.csrf)
	response, err := s.client.Do(req)
	if err != nil {
		return errors.New("revoke laboratory console session failed")
	}
	_, err = readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return err
	}
	// An expired or revoked session has no remaining logout authority. This
	// does not authenticate it: callers must complete a new real login.
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("revoke laboratory console session: HTTP %d", response.StatusCode)
	}
	s.csrf = ""
	return nil
}

func fixtureURL(endpoint *url.URL) bool {
	return endpoint != nil && endpoint.Scheme == "https" && endpoint.User == nil && endpoint.Fragment == "" && (endpoint.Host == "localhost:18444" || endpoint.Host == "localhost:18443")
}

func readFixtureResponse(response *http.Response) ([]byte, error) {
	const maximum = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(body) > maximum {
		return nil, errors.New("fixture HTTP response is unreadable or exceeds capacity")
	}
	return body, nil
}

func fixtureLoginForm(body []byte, base *url.URL) (*url.URL, url.Values, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, errors.New("invalid fixture login document")
	}
	var formNode *html.Node
	var walk func(*html.Node) error
	walk = func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == "form" && htmlAttribute(node, "id") == "kc-form-login" {
			if formNode != nil {
				return errors.New("ambiguous fixture login form")
			}
			formNode = node
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(document); err != nil {
		return nil, nil, err
	}
	if formNode == nil || !strings.EqualFold(htmlAttribute(formNode, "method"), http.MethodPost) {
		return nil, nil, errors.New("expected fixture password login form")
	}
	action, err := base.Parse(htmlAttribute(formNode, "action"))
	if err != nil || !fixtureURL(action) || action.Host != "localhost:18443" || action.Path != "/realms/lindm/login-actions/authenticate" || action.Query().Get("client_id") != "lindm-console" {
		return nil, nil, errors.New("fixture credential destination rejected")
	}
	values := make(url.Values)
	walk = func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == "input" && htmlAttribute(node, "type") == "hidden" {
			name := htmlAttribute(node, "name")
			if name != "" {
				values.Add(name, htmlAttribute(node, "value"))
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(formNode); err != nil {
		return nil, nil, err
	}
	return action, values, nil
}

func htmlAttribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == name {
			return attribute.Val
		}
	}
	return ""
}
