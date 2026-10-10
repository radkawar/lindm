package devlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/html"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/ctl"
)

// CLIEvidence contains only observed, nonsecret outcomes. It deliberately excludes
// configuration, cookies, authorization URLs, passwords and bearer credentials.
type CLIEvidence struct {
	ServerOrigin           string    `json:"server_origin"`
	IsolatedDatabase       string    `json:"isolated_database,omitempty"`
	CompletedAt            time.Time `json:"completed_at"`
	KeycloakLogin          bool      `json:"keycloak_login"`
	ExplicitApproval       bool      `json:"explicit_approval"`
	LoopbackPKCELogin      bool      `json:"loopback_pkce_login"`
	OwnerWhoami            bool      `json:"owner_whoami"`
	AdminRead              bool      `json:"admin_read"`
	DevicePageCount        int       `json:"device_page_count"`
	Logout                 bool      `json:"logout"`
	RevokedWhoamiDenied    bool      `json:"revoked_whoami_denied"`
	RevokedAdminReadDenied bool      `json:"revoked_admin_read_denied"`
}

// CheckCLI exercises the actual CLI client and a real Keycloak browser session.
// An empty binary requires an already-running server; a supplied binary owns an
// isolated console fixture. Neither mode resets or stops the shared development lab.
func CheckCLI(ctx context.Context, repository, binary string) (_ *CLIEvidence, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	evidence := &CLIEvidence{ServerOrigin: consoleOrigin}
	var owner *OwnerSession
	var err error
	if binary != "" {
		fixture, err := OpenConsoleAuthorityFixture(ctx, repository, binary)
		if err != nil {
			return nil, err
		}
		defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
		evidence.IsolatedDatabase = fixture.DatabaseName
		owner, err = fixture.OpenOwnerSession(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		owner, err = OpenOwnerSession(ctx, repository)
		if err != nil {
			return nil, fmt.Errorf("CLI check requires a running development server and Keycloak fixture: %w", err)
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, owner.Close(cleanup))
	}()
	evidence.KeycloakLogin = true
	ca, err := os.ReadFile(filepath.Join(FixturePath(repository), "transport-ca.crt"))
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "lindm-cli-check-")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(directory)) }()
	configPath := filepath.Join(directory, "config.json")
	client, err := ctl.New(configPath, &authv1.CLIConfig{ServerOrigin: consoleOrigin, CaPem: string(ca)})
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	if err := client.Login(ctx, func(ctx context.Context, authorize string) error {
		if err := owner.approveCLI(ctx, authorize); err != nil {
			return err
		}
		evidence.ExplicitApproval = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("CLI loopback PKCE login: %w", err)
	}
	loggedOut := false
	defer func() {
		if !loggedOut {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, client.Logout(cleanup))
		}
	}()
	evidence.LoopbackPKCELogin = true
	principal, err := client.Whoami(ctx)
	if err != nil {
		return nil, fmt.Errorf("CLI whoami: %w", err)
	}
	if principal.GetIssuer() != issuer || principal.GetSubject() != ownerSubject || principal.GetRole() != "owner" {
		return nil, errors.New("CLI whoami does not bind the expected fixture owner")
	}
	evidence.OwnerWhoami = true
	page, err := client.Admin().ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1}))
	if err != nil {
		return nil, fmt.Errorf("CLI authenticated admin read: %w", err)
	}
	evidence.AdminRead, evidence.DevicePageCount = true, len(page.Msg.GetDevices())
	// A separately loaded client retains the original credential only in memory
	// after logout clears the first client's configuration and bearer authority.
	revoked, err := ctl.New(configPath, nil)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, revoked.Close()) }()
	if err := client.Logout(ctx); err != nil {
		return nil, fmt.Errorf("CLI logout: %w", err)
	}
	loggedOut, evidence.Logout = true, true
	_, err = revoked.Whoami(ctx)
	var denied *ctl.HTTPError
	if !errors.As(err, &denied) || denied.StatusCode != http.StatusUnauthorized {
		return nil, errors.New("revoked CLI bearer was not rejected by whoami as unauthenticated")
	}
	evidence.RevokedWhoamiDenied = true
	if _, err := revoked.Admin().ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{PageSize: 1})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		return nil, errors.New("revoked CLI bearer was not rejected by AdminService as unauthenticated")
	}
	evidence.RevokedAdminReadDenied = true
	evidence.CompletedAt = time.Now().UTC()
	return evidence, nil
}

// approveCLI confines cookies to the console and follows the loopback redirect
// separately, with no cookie jar or proxy. No authorization URL enters evidence.
func (s *OwnerSession) approveCLI(ctx context.Context, authorize string) error {
	endpoint, err := url.Parse(authorize)
	if err != nil || !cliConsoleURL(endpoint, "/auth/cli/authorize") {
		return errors.New("unexpected CLI authorization destination")
	}
	query := endpoint.Query()
	callback, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || callback.Scheme != "http" || callback.Hostname() != "127.0.0.1" || callback.Port() == "" || callback.User != nil || callback.Path != "/callback" || callback.RawQuery != "" || callback.Fragment != "" || len(query.Get("state")) != 43 || len(query.Get("code_challenge")) != 43 {
		return errors.New("unexpected CLI loopback PKCE request")
	}
	browser := *s.client
	browser.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.Method != http.MethodGet || !cliConsoleURL(req.URL, "/auth/cli/approve") {
			return errors.New("CLI approval redirect rejected")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorize, nil)
	if err != nil {
		return errors.New("construct CLI authorization request failed")
	}
	response, err := browser.Do(req)
	if err != nil {
		return errors.New("load CLI approval failed")
	}
	body, err := readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || !cliConsoleURL(response.Request.URL, "/auth/cli/approve") {
		return errors.New("CLI authorization did not reach the approval page")
	}
	csrf, err := cliApprovalCSRF(body)
	if err != nil {
		return err
	}
	form := url.Values{"csrf_token": {csrf}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, consoleOrigin+"/auth/cli/approve", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Origin", consoleOrigin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err = browser.Do(req)
	if err != nil {
		return errors.New("submit explicit CLI approval failed")
	}
	_, err = readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusSeeOther && response.StatusCode != http.StatusFound {
		return fmt.Errorf("CLI approval did not redirect: HTTP %d", response.StatusCode)
	}
	location, err := response.Location()
	if err != nil || location.Scheme != callback.Scheme || location.Host != callback.Host || location.Path != callback.Path || location.User != nil || location.Fragment != "" {
		return errors.New("CLI approval callback destination rejected")
	}
	values := location.Query()
	if len(values) != 2 || len(values["code"]) != 1 || values.Get("code") == "" || len(values["state"]) != 1 || values.Get("state") != query.Get("state") {
		return errors.New("CLI approval callback must contain only one-time code and matching state")
	}
	transport := &http.Transport{ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	loopback := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("CLI loopback callback redirect rejected")
	}}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return errors.New("construct CLI loopback callback failed")
	}
	response, err = loopback.Do(req)
	if err != nil {
		return errors.New("deliver CLI loopback callback failed")
	}
	_, err = readFixtureResponse(response)
	err = errors.Join(err, response.Body.Close())
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("CLI loopback callback rejected: HTTP %d", response.StatusCode)
	}
	return nil
}

func cliConsoleURL(endpoint *url.URL, path string) bool {
	return endpoint != nil && endpoint.Scheme == "https" && endpoint.Host == "localhost:18444" && endpoint.User == nil && endpoint.Fragment == "" && endpoint.Path == path
}

func cliApprovalCSRF(body []byte) (string, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", errors.New("invalid CLI approval document")
	}
	var form *html.Node
	var walk func(*html.Node) error
	walk = func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == "form" {
			if form != nil || htmlAttribute(node, "action") != "/auth/cli/approve" || !strings.EqualFold(htmlAttribute(node, "method"), http.MethodPost) {
				return errors.New("unexpected or ambiguous CLI approval form")
			}
			form = node
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(document); err != nil {
		return "", err
	}
	if form == nil {
		return "", errors.New("CLI approval form is absent")
	}
	var csrf string
	walk = func(node *html.Node) error {
		if node.Type == html.ElementNode && node.Data == "input" && htmlAttribute(node, "name") == "csrf_token" {
			if csrf != "" || htmlAttribute(node, "type") != "hidden" || htmlAttribute(node, "value") == "" {
				return errors.New("invalid or ambiguous CLI approval CSRF field")
			}
			csrf = htmlAttribute(node, "value")
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(form); err != nil {
		return "", err
	}
	if csrf == "" {
		return "", errors.New("CLI approval CSRF field is absent")
	}
	return csrf, nil
}
