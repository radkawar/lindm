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
)

func (d *Document) database(path string) (*pgxpool.Config, error) {
	connection, err := readFile(reference(d.base, path), true)
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
	u, err := url.Parse(strings.TrimSpace(string(connection)))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" || u.User == nil || u.User.Username() == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" {
		return nil, errors.New("database credential must be a PostgreSQL URL with explicit host, user and database")
	}
	options, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("database URL has invalid connection options")
	}
	for key, values := range options {
		if len(values) != 1 {
			return nil, errors.New("database URL must not repeat connection options")
		}
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "target_session_attrs", "load_balance_hosts", "channel_binding", "require_auth", "sslnegotiation":
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
		if !permitsUsage(pair.Leaf, x509.ExtKeyUsageClientAuth) {
			return nil, errors.New("database client certificate must permit client authentication")
		}
		certificates = []tls.Certificate{pair}
	}
	// Empty explicit settings override pgx's home-directory defaults. pgx must
	// never reopen our checked resources or implicitly load ~/.pgpass.
	for _, key := range []string{"sslrootcert", "sslcert", "sslkey", "passfile"} {
		options.Set(key, "")
	}
	u.RawQuery = options.Encode()
	cfg, err := pgxpool.ParseConfig(u.String())
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

func configureDatabaseTLS(cfg *tls.Config, roots *x509.CertPool, certificates []tls.Certificate) error {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.ServerName == "" {
		return errors.New("all PostgreSQL connections require TLS with sslmode=verify-full")
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.RootCAs = roots
	cfg.Certificates = certificates
	return nil
}
