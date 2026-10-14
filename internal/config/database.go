// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/pki"
)

func (d *Document) database(path string) (*pgxpool.Config, error) {
	var connection []byte
	var err error
	if d.databaseURLCredential != nil {
		connection, err = d.databaseURLCredential.read()
	} else {
		connection, err = readFile(reference(d.base, path), true)
	}
	defer clear(connection)
	if err != nil {
		return nil, fmt.Errorf("read database credential: %w", err)
	}
	// The protected URL is authoritative. Inherited libpq settings may redirect
	// connections or load unvalidated service, password and certificate files.
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") && value != "" {
			return nil, errors.New("PostgreSQL environment variables are not supported; use database.url_file")
		}
	}
	connectionURL, options, err := parseDatabaseURL(strings.TrimSpace(string(connection)))
	if err != nil {
		return nil, err
	}
	for key, values := range options {
		if len(values) != 1 {
			return nil, errors.New("database URL must not repeat connection options")
		}
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "target_session_attrs", "channel_binding", "require_auth", "sslnegotiation":
		default:
			return nil, errors.New("database URL contains unsupported connection options")
		}
	}
	if options.Get("sslmode") != "verify-full" {
		return nil, errors.New("all PostgreSQL connections require TLS with sslmode=verify-full")
	}
	var roots *x509.CertPool
	if path := options.Get("sslrootcert"); path != "" && path != "system" {
		pem, err := readFile(reference(d.base, path), false)
		if err != nil {
			return nil, fmt.Errorf("read database sslrootcert: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("database sslrootcert contains no PEM certificates")
		}
	}
	var certificates []tls.Certificate
	certFile, keyFile := options.Get("sslcert"), options.Get("sslkey")
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("database sslcert and sslkey must be supplied together")
		}
		pair, err := keyPair(d.base, certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load database client certificate: %w", err)
		}
		if !pki.PermitsUsage(pair.Leaf, x509.ExtKeyUsageClientAuth) {
			return nil, errors.New("database client certificate must permit client authentication")
		}
		certificates = []tls.Certificate{pair}
	}
	// Empty explicit settings override pgx's home-directory defaults. pgx must
	// never reopen our checked resources or implicitly load ~/.pgpass.
	for _, key := range []string{"sslrootcert", "sslcert", "sslkey", "passfile"} {
		options.Set(key, "")
	}
	// pgx uses PostgreSQL URI decoding, where '+' is literal, not a space.
	cfg, err := pgxpool.ParseConfig(connectionURL + "?" + strings.ReplaceAll(options.Encode(), "+", "%20"))
	if err != nil {
		// Driver parse errors may contain the complete URL and password.
		return nil, errors.New("database credential contains an invalid PostgreSQL connection configuration")
	}
	if err := configureDatabaseTLS(cfg.ConnConfig.TLSConfig, roots, certificates); err != nil {
		return nil, err
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if err := configureDatabaseTLS(fallback.TLSConfig, roots, certificates); err != nil {
			return nil, err
		}
	}
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	return cfg, nil
}

func parseDatabaseURL(connection string) (string, url.Values, error) {
	invalid := errors.New("database credential must be a PostgreSQL URL with explicit host, user and database")
	if strings.Contains(connection, "#") {
		return "", nil, invalid
	}
	base, query, _ := strings.Cut(connection, "?")
	scheme, rest, ok := strings.Cut(base, "://")
	if !ok || (scheme != "postgres" && scheme != "postgresql") {
		return "", nil, invalid
	}
	authority, database, ok := strings.Cut(rest, "/")
	if !ok || strings.Trim(database, " ") == "" {
		return "", nil, invalid
	}
	userinfo, hosts, ok := strings.Cut(authority, "@")
	if !ok {
		return "", nil, invalid
	}
	// net/url cannot parse PostgreSQL's multihost authority. Validate the
	// user and database with a placeholder host, retaining the actual authority
	// verbatim for pgx's libpq-compatible host, port and IPv6 parser.
	u, err := url.Parse(scheme + "://" + userinfo + "@localhost/" + database)
	if err != nil || u.User == nil || u.User.Username() == "" {
		return "", nil, invalid
	}
	// pgx substitutes defaults for empty hosts, including empty entries in a
	// failover list. Check explicit hosts before that substitution; leave port
	// and remaining authority syntax validation to pgx.
	for {
		host, remaining, more := strings.Cut(hosts, ",")
		if strings.HasPrefix(hosts, "[") {
			var closed bool
			host, remaining, closed = strings.Cut(hosts[1:], "]")
			if !closed {
				return "", nil, invalid
			}
			_, remaining, more = strings.Cut(remaining, ",")
		} else {
			host, _, _ = strings.Cut(host, ":")
		}
		host, err = url.PathUnescape(strings.Trim(host, " "))
		if err != nil {
			return "", nil, invalid
		}
		// pgx decodes before splitting its final host list, so encoded commas
		// must not introduce implicit hosts either.
		for _, decodedHost := range strings.Split(host, ",") {
			if decodedHost == "" {
				return "", nil, invalid
			}
		}
		if !more {
			break
		}
		hosts = remaining
	}
	options, err := url.ParseQuery(strings.ReplaceAll(query, "+", "%2B"))
	if err != nil {
		return "", nil, errors.New("database URL has invalid connection options")
	}
	return base, options, nil
}

func configureDatabaseTLS(cfg *tls.Config, roots *x509.CertPool, certificates []tls.Certificate) error {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.ServerName == "" {
		return errors.New("all PostgreSQL connections require TLS with sslmode=verify-full")
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.RootCAs = roots
	cfg.Certificates = certificates
	return nil
}
