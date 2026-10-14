// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func databaseConnection(ctx context.Context, dir, file string) (*pgx.Conn, error) {
	data, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return nil, err
	}
	cfg, err := pgx.ParseConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("invalid %s PostgreSQL configuration", file)
	}
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("%s does not enable TLS", file)
	}
	cfg.TLSConfig.MinVersion = tls.VersionTLS13
	cfg.TLSConfig.MaxVersion = tls.VersionTLS13
	for _, fallback := range cfg.Fallbacks {
		if fallback.TLSConfig == nil {
			return nil, fmt.Errorf("%s permits a plaintext fallback", file)
		}
		fallback.TLSConfig.MinVersion = tls.VersionTLS13
		fallback.TLSConfig.MaxVersion = tls.VersionTLS13
	}
	cfg.ConnectTimeout = 5 * time.Second
	return pgx.ConnectConfig(ctx, cfg)
}

func databaseReady(ctx context.Context, dir string) (err error) {
	conn, err := databaseConnection(ctx, dir, "database-url")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close(ctx)) }()
	var role, protocol string
	var encrypted bool
	if err := conn.QueryRow(ctx, "SELECT current_user, ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&role, &encrypted, &protocol); err != nil {
		return err
	}
	if role != "lindm_runtime" || !encrypted || protocol != "TLSv1.3" {
		return fmt.Errorf("unexpected runtime database role or TLS protocol")
	}
	return nil
}

func oidcReady(ctx context.Context, dir string) error {
	tlsConfig, err := trustClient(dir)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, endpoint, token string, form url.Values, target any) (err error) {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
		if err != nil {
			return err
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, resp.Body.Close()) }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s %s: HTTP %d", method, endpoint, resp.StatusCode)
		}
		if target != nil {
			return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(target)
		}
		return nil
	}
	var discovery struct {
		Issuer                string `json:"issuer"`
		TokenEndpoint         string `json:"token_endpoint"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := request(http.MethodGet, issuer+"/.well-known/openid-configuration", "", nil, &discovery); err != nil {
		return err
	}
	if discovery.Issuer != issuer || discovery.TokenEndpoint != issuer+"/protocol/openid-connect/token" || discovery.AuthorizationEndpoint != issuer+"/protocol/openid-connect/auth" || discovery.JWKSURI != issuer+"/protocol/openid-connect/certs" {
		return fmt.Errorf("keycloak discovery does not describe the expected HTTPS realm")
	}
	secret, err := os.ReadFile(filepath.Join(dir, "directory-secret"))
	if err != nil {
		return err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := request(http.MethodPost, discovery.TokenEndpoint, "", url.Values{"grant_type": {"client_credentials"}, "client_id": {"lindm-directory"}, "client_secret": {string(secret)}}, &token); err != nil {
		return err
	}
	if token.AccessToken == "" {
		return fmt.Errorf("keycloak returned an empty directory token")
	}
	base := "https://localhost:18443/admin/realms/lindm/users/" + ownerSubject
	var owner struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := request(http.MethodGet, base, token.AccessToken, nil, &owner); err != nil {
		return err
	}
	if owner.ID != ownerSubject {
		return fmt.Errorf("keycloak owner subject does not match fixture")
	}
	// Check actual directory permissions, without undoing administrative edits to
	// group membership or enabled state on subsequent up/check operations.
	for _, suffix := range []string{"/groups", "/federated-identity"} {
		if err := request(http.MethodGet, base+suffix, token.AccessToken, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func awaitReady(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	local, err := localFixture(dir)
	if err != nil {
		return err
	}
	checks := []struct {
		name  string
		check func(context.Context, string) error
	}{{"PostgreSQL TLS/runtime login", databaseReady}, {"Keycloak HTTPS/discovery/directory", oidcReady}}
	if local {
		checks = checks[:1]
	}
	for _, check := range checks {
		var last error
		for {
			attempt, stop := context.WithTimeout(ctx, 10*time.Second)
			last = check.check(attempt, dir)
			stop()
			if last == nil {
				fmt.Fprintln(os.Stderr, check.name+" ready")
				break
			}
			fmt.Fprintf(os.Stderr, "Waiting for %s: %v\n", check.name, last)
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s readiness failed: %w (last error: %v); inspect docker compose logs; never regenerate credentials over preserved volumes", check.name, ctx.Err(), last)
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil
}

func restrictMigrationMetadata(ctx context.Context, dir string) (err error) {
	conn, err := databaseConnection(ctx, dir, "migration-database-url")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close(ctx)) }()
	_, err = conn.Exec(ctx, "REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.goose_db_version FROM lindm_runtime")
	return err
}
