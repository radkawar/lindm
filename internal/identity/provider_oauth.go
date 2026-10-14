// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// providerOAuth caches credentials only, never directory authority. Token waits,
// retries and API reads all share the caller's bounded observation context.
type providerOAuth struct {
	client   *http.Client
	now      func() time.Time
	tokenURL string
	form     func() (url.Values, error)
	retry    func(int, http.Header, []byte, int, time.Time) (time.Duration, bool, error)
	wait     func(context.Context, time.Duration) error
	gate     chan struct{}
	access   string
	expires  time.Time
}

func newProviderOAuth(client *http.Client, now func() time.Time) (*providerOAuth, error) {
	if client == nil || now == nil {
		return nil, errInvalidConfig
	}
	bounded := *client
	bounded.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &providerOAuth{client: &bounded, now: now, wait: waitProviderRetry, gate: make(chan struct{}, 1)}, nil
}

func providerSigner(keyPEM []byte, keyID string) (jose.Signer, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || keyID == "" {
		return nil, errInvalidConfig
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errInvalidConfig
		}
		key, _ = parsed.(*rsa.PrivateKey)
	case "RSA PRIVATE KEY":
		var err error
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errInvalidConfig
		}
	}
	if key == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errInvalidConfig
	}
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
}

func (p *providerOAuth) token(ctx context.Context, rejected string) (string, error) {
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return "", ErrDirectoryUnavailable
	}
	if rejected != "" && rejected == p.access {
		p.access = ""
	}
	if p.access != "" && p.now().Before(p.expires) {
		return p.access, nil
	}
	form, err := p.form()
	if err != nil {
		return "", ErrDirectoryUnavailable
	}
	started := p.now()
	body, status, _, err := p.request(ctx, http.MethodPost, p.tokenURL, form.Encode(), "")
	if err != nil || status != http.StatusOK {
		return "", ErrDirectoryUnavailable
	}
	var token struct {
		Access  string `json:"access_token"`
		Type    string `json:"token_type"`
		Expires int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &token) != nil || token.Access == "" || !strings.EqualFold(token.Type, "Bearer") || token.Expires <= 30 || token.Expires > 86400 {
		return "", ErrDirectoryUnavailable
	}
	p.access = token.Access
	p.expires = started.Add(time.Duration(token.Expires-30) * time.Second)
	if !p.now().Before(p.expires) {
		return "", ErrDirectoryUnavailable
	}
	return p.access, nil
}

func (p *providerOAuth) get(ctx context.Context, target string) ([]byte, int, http.Header, error) {
	token, err := p.token(ctx, "")
	if err != nil {
		return nil, 0, nil, err
	}
	body, status, header, err := p.request(ctx, http.MethodGet, target, "", token)
	if err != nil || status != http.StatusUnauthorized {
		return body, status, header, err
	}
	token, err = p.token(ctx, token)
	if err != nil {
		return nil, 0, nil, err
	}
	return p.request(ctx, http.MethodGet, target, "", token)
}

func (p *providerOAuth) request(ctx context.Context, method, target, form, token string) ([]byte, int, http.Header, error) {
	for attempt := range 4 {
		body, status, header, err := p.once(ctx, method, target, form, token)
		if err != nil {
			return nil, status, nil, err
		}
		delay, retry, err := p.retry(status, header, body, attempt, p.now())
		if err != nil {
			return nil, status, nil, err
		}
		if !retry {
			return body, status, header, nil
		}
		if attempt == 3 || p.wait(ctx, delay) != nil {
			return nil, status, nil, ErrDirectoryUnavailable
		}
	}
	return nil, 0, nil, ErrDirectoryUnavailable
}

func (p *providerOAuth) once(ctx context.Context, method, target, form, token string) (_ []byte, _ int, _ http.Header, err error) {
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(form))
	if err != nil {
		return nil, 0, nil, errDirectoryResponse
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, nil, directoryUnavailable(ctx)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, ErrDirectoryUnavailable)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBody+1))
	if ctx.Err() != nil {
		return nil, 0, nil, directoryUnavailable(ctx)
	}
	if err != nil || len(body) > maxDirectoryBody {
		return nil, resp.StatusCode, nil, errDirectoryResponse
	}
	return body, resp.StatusCode, resp.Header, nil
}

func providerRetryAfter(value string, now time.Time) (time.Duration, error) {
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}
	at, err := http.ParseTime(value)
	if err != nil {
		return 0, ErrDirectoryUnavailable
	}
	return max(0, at.Sub(now)), nil
}

func waitProviderRetry(ctx context.Context, delay time.Duration) error {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || delay >= time.Until(deadline) {
		return ErrDirectoryUnavailable
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ErrDirectoryUnavailable
	case <-timer.C:
		return nil
	}
}

// IDs are opaque and case-sensitive, but never accept an email, alias or path as
// an immutable provider object ID. Exact response correlation is still required.
func providerObjectID(id string) bool {
	if id == "" || len(id) > 255 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
