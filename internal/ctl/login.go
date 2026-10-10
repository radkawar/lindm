package ctl

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

// OpenBrowser launches the system browser without forwarding browser output to
// terminal logs. The login URL contains only state, challenge and loopback URI.
func OpenBrowser(ctx context.Context, authorizeURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "xdg-open", authorizeURL)
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return errors.New("could not open system browser using xdg-open")
	}
	return nil
}

// Login runs S256 PKCE against an exact ephemeral IPv4 loopback callback and
// persists only the returned session token. openBrowser receives the authorize
// URL and must honor ctx; a lab may drive the real browser protocol there instead
// of starting a graphical process. No token or verifier enters a URL.
func (c *Client) Login(ctx context.Context, openBrowser func(context.Context, string) error) (resultErr error) {
	if openBrowser == nil {
		return errors.New("browser opener is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	state, err := randomToken()
	if err != nil {
		return err
	}
	verifier, err := randomToken()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("listen on login loopback")
	}
	redirectURI := "http://" + listener.Addr().String() + "/callback"
	challenge := sha256.Sum256([]byte(verifier))
	codes := make(chan string, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != http.MethodGet || r.URL.Path != "/callback" || r.Host != listener.Addr().String() {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) != 2 || len(query["state"]) != 1 || len(query["code"]) != 1 || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		request := &authv1.CLIExchangeRequest{Code: query.Get("code"), CodeVerifier: verifier, RedirectUri: redirectURI}
		if err := c.rules.Validate(request); err != nil {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		select {
		case codes <- request.GetCode():
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Callback already received", http.StatusConflict)
		}
	})
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		resultErr = errors.Join(resultErr, server.Close())
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			resultErr = errors.Join(resultErr, errors.New("login loopback server failed"))
		}
	}()
	authorize := c.origin + "/auth/cli/authorize?" + url.Values{
		"redirect_uri": {redirectURI}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "state": {state},
	}.Encode()
	if err := openBrowser(ctx, authorize); err != nil {
		return errors.New("browser authorization failed")
	}
	var code string
	select {
	case code = <-codes:
	case <-ctx.Done():
		return errors.New("browser login cancelled or expired")
	}
	response := &authv1.CLIExchangeResponse{}
	if err := c.authRequest(ctx, http.MethodPost, "/auth/cli/exchange", "", &authv1.CLIExchangeRequest{Code: code, CodeVerifier: verifier, RedirectUri: redirectURI}, response); err != nil {
		return err
	}
	if response.GetExpiresAt() == nil || !response.GetExpiresAt().AsTime().After(time.Now()) {
		return errors.New("server returned an expired CLI session")
	}
	cfg := proto.CloneOf(c.config)
	cfg.SessionToken = response.GetToken()
	if err := c.rules.Validate(cfg); err != nil {
		return errors.New("server returned invalid CLI credentials")
	}
	if err := c.store.save(cfg); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cleanupCancel()
		return errors.Join(err, c.authRequest(cleanupCtx, http.MethodPost, "/auth/logout", cfg.GetSessionToken(), nil, nil))
	}
	c.config = cfg
	return nil
}

func readDocument(path string) (_ []byte, resultErr error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	data, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDocumentBytes {
		return nil, errors.New("input exceeds document limit")
	}
	return data, nil
}
