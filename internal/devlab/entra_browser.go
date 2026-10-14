// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"

	"lindm/gen/lindm/admin/v1/adminv1connect"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
	"lindm/internal/labexec"
)

// entraFixtureURL is also enforced at the HTTP transport boundary, not just on
// redirects: neither cookies nor CSRF-bearing RPCs can leave the fixture origin.
func entraFixtureURL(endpoint *url.URL, origin string) bool {
	return endpoint != nil && endpoint.Scheme == "https" && endpoint.User == nil &&
		endpoint.Fragment == "" && endpoint.Opaque == "" && endpoint.Scheme+"://"+endpoint.Host == origin
}

func entraLoginURL(endpoint *url.URL) bool {
	return endpoint != nil && endpoint.Scheme == "https" && endpoint.Host == "login.microsoftonline.com" &&
		endpoint.User == nil && endpoint.Fragment == "" && endpoint.Opaque == ""
}

func entraSecurityInfoURL(endpoint *url.URL) bool {
	return endpoint != nil && endpoint.Scheme == "https" && endpoint.Host == "mysignins.microsoft.com" &&
		endpoint.User == nil && endpoint.Fragment == "" && endpoint.Opaque == ""
}

func entraRequestAllowed(endpoint *url.URL, origin, method, resource string) bool {
	if entraFixtureURL(endpoint, origin) || entraLoginURL(endpoint) || entraSecurityInfoURL(endpoint) || entraFixtureURL(endpoint, "https://login.live.com") {
		return true
	}
	// Microsoft-hosted static assets are needed by the actual sign-in UI. They
	// never receive form submissions, navigations, cookies from another domain,
	// or our credentials. Only the exact approved Microsoft sign-in origins
	// may navigate; federated account redirects are not followed.
	if endpoint == nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.Port() != "" || method != http.MethodGet || resource == "Document" {
		return false
	}
	host := endpoint.Hostname()
	return host == "static2.sharepointonline.com" || strings.HasSuffix(host, ".msauth.net") || strings.HasSuffix(host, ".msftauth.net")
}

var entraAADSTS = regexp.MustCompile(`\bAADSTS[0-9]{5,9}\b`)

var errEntraNavigating = errors.New("entra: browser document changed during inspection")

// Only a fixed category and a syntactically constrained code leave the browser.
// Never return Microsoft text: it can contain passwords, UPNs, tokens and IDs.
func entraChallenge(text string) string {
	code := entraAADSTS.FindString(text)
	lower := strings.ToLower(text)
	category := ""
	switch {
	case code == "AADSTS50076" || code == "AADSTS50079" || code == "AADSTS50074" || strings.Contains(lower, "approve sign in") || strings.Contains(lower, "approve sign-in") || strings.Contains(lower, "verify your identity") || strings.Contains(lower, "enter code") || strings.Contains(lower, "more information required") || strings.Contains(lower, "authenticator"):
		category = "mfa_required"
	case strings.HasPrefix(code, "AADSTS530") || strings.Contains(lower, "conditional access") || strings.Contains(lower, "you can't get there from here") || strings.Contains(lower, "device to be managed"):
		category = "conditional_access"
	case code == "AADSTS65001" || code == "AADSTS65004" || strings.Contains(lower, "permissions requested") || strings.Contains(lower, "need admin approval") || strings.Contains(lower, "consent required"):
		category = "consent_required"
	case code == "AADSTS50055" || strings.Contains(lower, "update your password") || strings.Contains(lower, "change your password") || strings.Contains(lower, "password has expired"):
		category = "password_change_required"
	case code == "AADSTS50126" || strings.Contains(lower, "incorrect password") || strings.Contains(lower, "password is incorrect") || strings.Contains(lower, "account or password is incorrect"):
		category = "invalid_credentials"
	case code != "":
		category = "identity_provider_rejected"
	}
	if category != "" && code != "" {
		return category + " (" + code + ")"
	}
	return category
}

type entraOriginTransport struct {
	origin string
	base   *http.Transport
}

func (t *entraOriginTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !entraFixtureURL(request.URL, t.origin) {
		return nil, errors.New("entra: session request escaped fixture origin")
	}
	return t.base.RoundTrip(request)
}

func (t *entraOriginTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

// openEntraBrowser drives the public authorization-code UI, never a password
// grant. CDP uses inherited anonymous pipes rather than an exposed debug socket.
// Browser state is destroyed before returning; only fixture cookies stay in RAM.
func openEntraBrowser(ctx context.Context, root, runDir, origin, username, password string, unsandboxed bool, mfa *entraMFA) (result *brokerBrowser, resultErr error) {
	endpoint, err := url.Parse(origin)
	if err != nil || !entraFixtureURL(endpoint, origin) || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || (endpoint.Hostname() != "localhost" && endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "::1") {
		return nil, errors.New("entra: browser requires an exact loopback HTTPS fixture origin")
	}
	if username == "" || password == "" {
		return nil, errors.New("entra: browser credentials are missing")
	}
	if _, err := custody.Owned(runDir, true); err != nil {
		return nil, errors.New("entra: browser run directory is not private and owned")
	}
	shared := FixturePath(root)
	certificatePEM, err := readOwned(filepath.Join(shared, "server.crt"))
	if err != nil {
		return nil, errors.New("entra: browser fixture certificate is not private, owned and readable")
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("entra: browser fixture certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate.VerifyHostname(endpoint.Hostname()) != nil {
		return nil, errors.New("entra: browser fixture certificate does not bind origin")
	}
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	tlsConfig, err := trustClient(shared)
	if err != nil {
		return nil, errors.New("load Entra browser fixture trust failed")
	}
	transport := &entraOriginTransport{origin: origin, base: &http.Transport{TLSClientConfig: tlsConfig, ResponseHeaderTimeout: 10 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 15 * time.Second}}
	defer func() {
		if resultErr != nil {
			transport.CloseIdleConnections()
			result = nil
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cdp, closeBrowser, err := startEntraChromium(ctx, runDir, base64.StdEncoding.EncodeToString(pin[:]), origin, unsandboxed)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeBrowser()) }()
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := cdp.call(ctx, "Target.createTarget", map[string]any{"url": "about:blank"}, &target); err != nil {
		return nil, err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := cdp.call(ctx, "Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}, &attached); err != nil {
		return nil, err
	}
	cdp.session = attached.SessionID
	if err := cdp.call(ctx, "Fetch.enable", map[string]any{"patterns": []map[string]string{{"urlPattern": "*", "requestStage": "Request"}}}, nil); err != nil {
		return nil, err
	}
	if err := cdp.call(ctx, "Page.navigate", map[string]any{"url": origin + "/auth/login"}, nil); err != nil {
		return nil, err
	}
	if err := cdp.login(ctx, username, password, mfa); err != nil {
		return nil, err
	}
	var cookies struct {
		Cookies []struct {
			Name     string `json:"name"`
			Value    string `json:"value"`
			Domain   string `json:"domain"`
			Path     string `json:"path"`
			Secure   bool   `json:"secure"`
			HTTPOnly bool   `json:"httpOnly"`
		} `json:"cookies"`
	}
	if err := cdp.call(ctx, "Network.getCookies", map[string]any{"urls": []string{origin + "/auth/session"}}, &cookies); err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("create Entra session cookie jar failed")
	}
	for _, cookie := range cookies.Cookies {
		if cookie.Domain != endpoint.Hostname() || !cookie.Secure {
			return nil, errors.New("entra: fixture cookie is not host-bound and secure")
		}
		jar.SetCookies(endpoint, []*http.Cookie{{Name: cookie.Name, Value: cookie.Value, Path: cookie.Path, Secure: true, HttpOnly: cookie.HTTPOnly}})
	}
	browser := &brokerBrowser{origin: origin, client: &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	status, principal, err := browser.session(ctx)
	if err != nil || status != http.StatusOK || principal.GetSubject() == "" || principal.GetCsrfToken() == "" {
		return nil, errors.New("entra: browser did not establish an authenticated fixture principal")
	}
	browser.principal = principal
	browser.admin = adminv1connect.NewAdminServiceClient(browser.client, origin, connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			request.Header().Set("Origin", origin)
			request.Header().Set("X-CSRF-Token", principal.GetCsrfToken())
			return next(ctx, request)
		}
	})))
	return browser, nil
}

// entraCDP deliberately supports only sequential requests. Events are consumed
// while waiting, with a hard message bound; protocol errors never expose payloads.
type entraCDP struct {
	input           *os.File
	output          *os.File
	scanner         *bufio.Scanner
	nextID          int
	session         string
	origin          string
	codeFlow        bool
	blockedRequests []string
}

func startEntraChromium(ctx context.Context, runDir, pin, origin string, unsandboxed bool) (_ *entraCDP, _ func() error, resultErr error) {
	binary := os.Getenv("LINDM_ENTRA_CHROMIUM")
	if binary == "" {
		for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
			if found, err := exec.LookPath(name); err == nil {
				binary = found
				break
			}
		}
	}
	if binary == "" {
		return nil, nil, errors.New("install Chromium or set LINDM_ENTRA_CHROMIUM")
	}
	profile, err := os.MkdirTemp(runDir, "entra-chromium-")
	if err != nil {
		return nil, nil, errors.New("create private Entra browser profile failed")
	}
	var files []*os.File
	defer func() {
		if resultErr != nil {
			for _, file := range files {
				resultErr = errors.Join(resultErr, file.Close())
			}
			resultErr = errors.Join(resultErr, os.RemoveAll(profile))
		}
	}()
	childInput, input, err := os.Pipe()
	if err != nil {
		return nil, nil, errors.New("create Entra browser command pipe failed")
	}
	files = append(files, childInput, input)
	output, childOutput, err := os.Pipe()
	if err != nil {
		return nil, nil, errors.New("create Entra browser response pipe failed")
	}
	files = append(files, output, childOutput)
	// Umask belongs to this child, never the multithreaded Go process. The fixed
	// launcher execs Chromium without interpolation or credential arguments and
	// keeps inherited CDP pipes. Any browser-created secret file is mode 0600.
	args := []string{"-c", `umask 077; exec "$@"`, "lindm-entra-chromium",
		binary, "--headless=new", "--incognito", "--remote-debugging-pipe", "--user-data-dir=" + profile,
		"--ignore-certificate-errors-spki-list=" + pin, "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-sync", "--disable-extensions", "--disable-breakpad", "--disable-crash-reporter", "--lang=en-US", "about:blank"}
	if unsandboxed {
		// Explicit operator consent only; never an automatic sandbox fallback.
		args = append(args, "--no-sandbox")
	}
	diagnostic := nativeexec.NewBuffer(64 << 10)
	// Explicit environment: caller-provided Entra secrets must not be inherited.
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + profile, "TMPDIR=" + profile, "LANG=C.UTF-8"}
	browser, err := labexec.Start(ctx, labexec.Command{Path: "sh", Args: args, Env: env, Files: []*os.File{childInput, childOutput}, Stderr: diagnostic})
	if err != nil {
		return nil, nil, errors.New("start isolated Entra Chromium failed")
	}
	closeErr := errors.Join(childInput.Close(), childOutput.Close())
	files = []*os.File{input, output}
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, 0); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) != 0 {
			return 0, nil, errors.New("truncated CDP frame")
		}
		return 0, nil, nil
	})
	cdp := &entraCDP{input: input, output: output, scanner: scanner, origin: origin}
	cleanup := func() error {
		// Close kills the owned process group before reaping its leader, so PID
		// reuse cannot redirect cleanup. This does not depend on caller context.
		defer func() { clear(diagnostic.Bytes()) }()
		waitErr := browser.Close()
		var exitErr *exec.ExitError
		errors.As(waitErr, &exitErr)
		pipeErr := errors.Join(input.Close(), output.Close())
		removeErr := os.RemoveAll(profile)
		if errors.Join(closeErr, waitErr, pipeErr, removeErr) != nil {
			detail := "unknown"
			switch {
			case bytes.Contains(diagnostic.Bytes(), []byte("No usable sandbox")) || bytes.Contains(diagnostic.Bytes(), []byte("Failed to move to new namespace")) || bytes.Contains(diagnostic.Bytes(), []byte("SUID sandbox helper binary")):
				detail = "sandbox_unavailable (install an administrator-supported sandboxed Chromium; no sandbox bypass is enabled)"
			case bytes.Contains(diagnostic.Bytes(), []byte("error while loading shared libraries")):
				detail = "missing_shared_library"
			}
			if exitErr != nil {
				detail += fmt.Sprintf("; exit=%d", exitErr.ExitCode())
			}
			return fmt.Errorf("owned Entra Chromium startup/cleanup failed: %s", detail)
		}
		return nil
	}
	return cdp, cleanup, nil
}

func checkEntraChromium(ctx context.Context, runDir string, unsandboxed bool) (resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cdp, cleanup, err := startEntraChromium(ctx, runDir, "", "https://localhost:1", unsandboxed)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	return cdp.call(ctx, "Browser.getVersion", nil, nil)
}

func (c *entraCDP) send(method string, params any, session string) (int, error) {
	c.nextID++
	request := struct {
		ID        int    `json:"id"`
		Method    string `json:"method"`
		Params    any    `json:"params,omitempty"`
		SessionID string `json:"sessionId,omitempty"`
	}{c.nextID, method, params, session}
	encoded, err := json.Marshal(request)
	if err != nil {
		return 0, errors.New("encode Entra browser command failed")
	}
	defer clear(encoded)
	encoded = append(encoded, 0)
	if _, err := c.input.Write(encoded); err != nil {
		return 0, errors.New("write Entra browser command failed")
	}
	return request.ID, nil
}

func (c *entraCDP) call(ctx context.Context, method string, params, result any) error {
	if ctx.Err() != nil {
		return errors.New("entra: browser authorization cancelled or timed out")
	}
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := errors.Join(c.input.SetWriteDeadline(deadline), c.output.SetReadDeadline(deadline)); err != nil {
		return errors.New("set Entra browser pipe deadline failed")
	}
	id, err := c.send(method, params, c.session)
	if err != nil {
		return err
	}
	for c.scanner.Scan() {
		var message struct {
			ID        int             `json:"id"`
			Method    string          `json:"method"`
			SessionID string          `json:"sessionId"`
			Params    json.RawMessage `json:"params"`
			Result    json.RawMessage `json:"result"`
			Error     json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(c.scanner.Bytes(), &message); err != nil {
			return errors.New("decode Entra browser response failed")
		}
		if message.Method == "Fetch.requestPaused" {
			if err := c.intercept(message.Params, message.SessionID); err != nil {
				return err
			}
		}
		if message.ID != id {
			continue
		}
		if len(message.Error) != 0 {
			var protocolError struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if json.Unmarshal(message.Error, &protocolError) == nil && protocolError.Code == -32000 &&
				(protocolError.Message == "Execution context was destroyed." || protocolError.Message == "Cannot find context with specified id") {
				return errEntraNavigating
			}
			return errors.New("entra: browser protocol command failed")
		}
		if result != nil && json.Unmarshal(message.Result, result) != nil {
			return errors.New("decode Entra browser command result failed")
		}
		return nil
	}
	return errors.New("entra: browser pipe closed or response deadline exceeded")
}

func (c *entraCDP) intercept(raw json.RawMessage, session string) error {
	var event struct {
		RequestID    string `json:"requestId"`
		ResourceType string `json:"resourceType"`
		Request      struct {
			URL    string `json:"url"`
			Method string `json:"method"`
		} `json:"request"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return errors.New("decode Entra browser request failed")
	}
	endpoint, err := url.Parse(event.Request.URL)
	allowed := err == nil && entraRequestAllowed(endpoint, c.origin, event.Request.Method, event.ResourceType)
	if allowed && event.ResourceType == "Document" && entraLoginURL(endpoint) && !c.codeFlow && (strings.HasSuffix(endpoint.Path, "/oauth2/v2.0/authorize") || strings.HasSuffix(endpoint.Path, "/oauth2/authorize")) {
		query := endpoint.Query()
		if query.Get("response_type") != "code" || query.Get("redirect_uri") != c.origin+"/auth/callback" || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || query.Get("state") == "" || query.Get("nonce") == "" {
			return errors.New("entra: browser authorization did not bind exact code/PKCE flow")
		}
		c.codeFlow = true
	}
	method := "Fetch.continueRequest"
	params := map[string]any{"requestId": event.RequestID}
	if !allowed {
		category := entraBlockedHost(endpoint)
		seen := false
		for _, existing := range c.blockedRequests {
			if existing == category {
				seen = true
				break
			}
		}
		if !seen {
			c.blockedRequests = append(c.blockedRequests, category)
		}
		method = "Fetch.failRequest"
		params["errorReason"] = "BlockedByClient"
	}
	if _, err := c.send(method, params, session); err != nil {
		return err
	}
	if !allowed && event.ResourceType == "Document" {
		return fmt.Errorf("entra: browser navigation escaped trusted origins (%s)", entraBlockedHost(endpoint))
	}
	return nil
}

func (c *entraCDP) evaluate(ctx context.Context, expression string, value any) error {
	var response struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	if err := c.call(ctx, "Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "awaitPromise": true}, &response); err != nil {
		return err
	}
	if len(response.Exception) != 0 {
		var exception struct {
			Exception struct {
				Class string `json:"className"`
			} `json:"exception"`
		}
		if json.Unmarshal(response.Exception, &exception) == nil {
			switch exception.Exception.Class {
			case "TypeError", "ReferenceError", "SyntaxError", "EvalError", "RangeError":
				return fmt.Errorf("entra: browser page evaluation failed (%s)", exception.Exception.Class)
			}
		}
	}
	if len(response.Exception) != 0 || len(response.Result.Value) == 0 || json.Unmarshal(response.Result.Value, value) != nil {
		return errors.New("entra: browser page evaluation failed")
	}
	return nil
}

func (c *entraCDP) login(ctx context.Context, username, password string, mfa *entraMFA) error {
	originJSON, err := json.Marshal(c.origin)
	if err != nil {
		return errors.New("encode Entra fixture origin failed")
	}
	if mfa != nil {
		if err := mfa.bind(username); err != nil {
			return err
		}
	}
	mfaActions := make(map[string]bool)
	inspect := `(async () => {
		if (!document.body) return {stage:'waiting'};
		if (location.origin === ` + string(originJSON) + `) {
			if (location.pathname === '/auth/login' || location.pathname === '/auth/callback') return {stage:'waiting'};
			const response = await fetch('/auth/session', {credentials:'same-origin', redirect:'error'});
			return {stage:response.status === 200 ? 'session' : 'waiting'};
		}
		if (location.href === 'about:blank') return {stage:'waiting'};
		if (location.origin === 'https://login.live.com') return {stage:'waiting'};
		if (location.origin === 'https://mysignins.microsoft.com') return {stage:'mfa'};
		if (location.origin !== 'https://login.microsoftonline.com') return {stage:'untrusted'};
		const visible = selector => {
			const e = document.querySelector(selector);
			if (!e || e.disabled || !e.checkVisibility({opacityProperty:true,visibilityProperty:true})) return false;
			const r = e.getBoundingClientRect();
			return r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth;
		};
		let stage = 'login_waiting';
		if (visible('#idSIButton9') && /stay signed in/i.test(document.body.innerText)) stage = 'stay';
		else if (visible('input[name="loginfmt"]')) stage = 'username';
		else if (visible('input[name="passwd"]')) stage = 'password';
		return {stage, text:document.body.innerText.slice(0,32768)};
	})()`
	usernameSent, passwordSent, staySent := false, false, false
	mfaActive := false
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var page struct {
			Stage string `json:"stage"`
			Text  string `json:"text"`
		}
		if err := c.evaluate(ctx, inspect, &page); err != nil {
			if !errors.Is(err, errEntraNavigating) {
				if mfaActive {
					return c.mfaDiagnosticError(mfa, err)
				}
				return err
			}
			// Navigation replaces the inspected document. Only observation is
			// repeated; credential submissions are never retried.
			page.Stage, page.Text = "waiting", ""
		}
		challenge := entraChallenge(page.Text)
		if (page.Stage == "mfa" || strings.HasPrefix(challenge, "mfa_required") || (mfaActive && page.Stage == "login_waiting")) && mfa != nil && passwordSent && c.codeFlow {
			mfaActive = true
			if err := c.continueMFA(ctx, mfa, mfaActions); err != nil && !errors.Is(err, errEntraNavigating) {
				return c.mfaDiagnosticError(mfa, err)
			}
			page.Stage = "waiting"
		} else if challenge != "" {
			return fmt.Errorf("entra: browser interrupted: %s", challenge)
		}
		page.Text = ""
		switch page.Stage {
		case "session":
			if !c.codeFlow || !usernameSent || !passwordSent {
				return errors.New("entra: browser session did not follow real username/password code authorization")
			}
			return nil
		case "untrusted":
			return errors.New("entra: browser credential page is not Microsoft sign-in")
		case "username":
			if !c.codeFlow {
				return errors.New("entra: browser username request preceded code authorization")
			}
			if !usernameSent {
				usernameSent = true
				if err := c.submit(ctx, "loginfmt", username, "#idSIButton9"); err != nil {
					return err
				}
			}
		case "password":
			if !usernameSent || !c.codeFlow {
				return errors.New("entra: browser password request preceded code authorization")
			}
			if !passwordSent {
				passwordSent = true
				if err := c.submit(ctx, "passwd", password, "#idSIButton9"); err != nil {
					return err
				}
			}
		case "stay":
			if !staySent {
				staySent = true
				// Decline persistent sign-in; do not grant application consent.
				if err := c.submit(ctx, "", "", "#idBtn_Back"); err != nil {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			if mfaActive {
				return c.mfaDiagnosticError(mfa, errors.New("entra: software TOTP continuation cancelled or timed out before fixture session"))
			}
			return errors.New("entra: browser authorization cancelled or timed out (unsupported sign-in interaction)")
		case <-ticker.C:
		}
	}
}

func (c *entraCDP) submit(ctx context.Context, field, value, button string) error {
	arguments, err := json.Marshal([]string{field, value, button})
	if err != nil {
		return errors.New("encode Entra browser form input failed")
	}
	defer clear(arguments)
	var submitted bool
	expression := `(([field,value,button]) => {
		if (location.origin !== 'https://login.microsoftonline.com') return false;
		const submit = document.querySelector(button);
		if (!submit || submit.disabled || !submit.getClientRects().length) return false;
		if (field) {
			const input = document.querySelector('input[name="'+field+'"]');
			if (!input || !input.getClientRects().length || input.disabled) return false;
			if (input.form && new URL(input.form.action, location.href).origin !== location.origin) return false;
			Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
			input.dispatchEvent(new Event('input', {bubbles:true}));
			input.dispatchEvent(new Event('change', {bubbles:true}));
		}
		submit.click();
		return true;
	})(` + string(arguments) + `)`
	if err := c.evaluate(ctx, expression, &submitted); err != nil {
		return err
	}
	if !submitted {
		return errors.New("entra: browser refused an untrusted or unavailable sign-in form")
	}
	return nil
}
