package config

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/pki"
)

// Resources contains resolved dependencies, not a second serialized schema.
// HTTPClient owns its transport; close idle connections during server shutdown.
type Resources struct {
	Proto                 *configv1.ServerConfig
	Database              *pgxpool.Config
	ServerCertificate     tls.Certificate
	DeviceCACertificate   *x509.Certificate
	DeviceCAKey           crypto.Signer
	HTTPClient            *http.Client
	ClientSecret          string
	DirectoryClientSecret string
	InventoryBudgetBytes  int64
	ExecutionBootstrap    *ExecutionBootstrap
	// ExecutionSigning is nil unless execution_signing is configured. Loaded
	// keys are not a delegation and do not authorize issuance.
	ExecutionSigning *ExecutionSigning
}

// Address renders the typed bind address using the standard IPv6-aware formatter.
func Address(listener *configv1.ListenerConfig) string {
	return net.JoinHostPort(listener.GetAddress(), strconv.FormatUint(uint64(listener.GetPort()), 10))
}

const (
	DefaultInventoryBudgetBytes int64 = 10 << 30
	MinInventoryBudgetBytes     int64 = 64 << 20
)

// InventoryBudget returns the deployment package-snapshot byte cap. An absent
// field selects the initial 10 GiB budget.
func InventoryBudget(cfg *configv1.ServerConfig) (int64, error) {
	if cfg == nil || cfg.InventoryBudgetBytes == nil {
		return DefaultInventoryBudgetBytes, nil
	}
	value := cfg.GetInventoryBudgetBytes()
	if value < uint64(MinInventoryBudgetBytes) || value > uint64(math.MaxInt64) {
		return 0, errors.New("inventory_budget_bytes is outside the admitted range")
	}
	return int64(value), nil
}

// Resolve loads the runtime dependencies needed by a control-plane process.
func (d *Document) Resolve() (*Resources, error) {
	cfg, base := d.Proto, d.base
	result := &Resources{Proto: cfg}
	var err error
	result.InventoryBudgetBytes, err = InventoryBudget(cfg)
	if err != nil {
		return nil, err
	}
	result.Database, err = d.Database()
	if err != nil {
		return nil, err
	}

	result.ServerCertificate, err = keyPair(base, cfg.GetTls().GetCertificateFile(), cfg.GetTls().GetPrivateKeyFile())
	if err != nil {
		return nil, fmt.Errorf("load tls certificate: %w", err)
	}
	publicURL, err := url.Parse(cfg.GetPublicUrl())
	if err != nil {
		return nil, fmt.Errorf("parse public_url: %w", err)
	}
	if err := result.ServerCertificate.Leaf.VerifyHostname(publicURL.Hostname()); err != nil {
		return nil, fmt.Errorf("tls certificate does not cover public_url: %w", err)
	}
	if !pki.PermitsUsage(result.ServerCertificate.Leaf, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("tls certificate must permit server authentication")
	}
	ca, err := keyPair(base, cfg.GetDeviceCa().GetCertificateFile(), cfg.GetDeviceCa().GetPrivateKeyFile())
	if err != nil {
		return nil, fmt.Errorf("load device_ca certificate: %w", err)
	}
	if !ca.Leaf.IsCA || !ca.Leaf.BasicConstraintsValid || ca.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("device_ca certificate must be a certificate-signing CA")
	}
	if !pki.PermitsUsage(ca.Leaf, x509.ExtKeyUsageClientAuth) {
		return nil, errors.New("device_ca certificate must permit client authentication")
	}
	if bytes.Equal(result.ServerCertificate.Leaf.RawSubjectPublicKeyInfo, ca.Leaf.RawSubjectPublicKeyInfo) {
		return nil, errors.New("device_ca and server TLS must use separate keys")
	}
	result.DeviceCACertificate = ca.Leaf
	var ok bool
	result.DeviceCAKey, ok = ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("device_ca private key cannot sign certificates")
	}
	bootstrap, verifier, err := d.executionBootstrap(result)
	if err != nil {
		return nil, err
	}
	result.ExecutionBootstrap = bootstrap
	result.ExecutionSigning, err = d.executionSigning(verifier)
	if err != nil {
		return nil, err
	}

	secret, err := readFile(reference(base, cfg.GetOidc().GetClientSecretFile()), true)
	if err != nil {
		return nil, fmt.Errorf("read oidc.client_secret_file: %w", err)
	}
	result.ClientSecret = strings.TrimSpace(string(secret))
	secret, err = readFile(reference(base, cfg.GetOidc().GetDirectoryClientSecretFile()), true)
	if err != nil {
		return nil, fmt.Errorf("read oidc.directory_client_secret_file: %w", err)
	}
	result.DirectoryClientSecret = strings.TrimSpace(string(secret))
	if result.ClientSecret == "" || result.DirectoryClientSecret == "" {
		return nil, errors.New("OIDC secret files must not be empty")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system trust roots: %w", err)
	}
	if cfg.GetTrustedCaFile() != "" {
		pem, err := readFile(reference(base, cfg.GetTrustedCaFile()), false)
		if err != nil {
			return nil, fmt.Errorf("read trusted_ca_file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("trusted_ca_file contains no PEM certificates")
		}
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not an *http.Transport")
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	result.HTTPClient = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return result, nil
}

// Database resolves only the runtime database credential.
func (d *Document) Database() (*pgxpool.Config, error) {
	cfg, err := d.database(d.Proto.GetDatabase().GetUrlFile())
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = int32(d.Proto.GetDatabase().GetMaxConnections())
	return cfg, nil
}

// MigrationDatabase resolves the separately privileged migration credential.
func (d *Document) MigrationDatabase() (*pgxpool.Config, error) {
	path := d.Proto.GetDatabase().GetMigrationUrlFile()
	if path == "" {
		return nil, errors.New("migration command requires database.migration_url_file")
	}
	cfg, err := d.database(path)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 2
	return cfg, nil
}

func keyPair(base, certificateFile, privateKeyFile string) (tls.Certificate, error) {
	cert, err := readFile(reference(base, certificateFile), false)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := readFile(reference(base, privateKeyFile), true)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if pair.Leaf == nil {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return tls.Certificate{}, err
		}
	}
	now := time.Now()
	if now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return tls.Certificate{}, errors.New("certificate is not currently valid")
	}
	if err := pki.ValidatePublicKey(pair.Leaf.PublicKey); err != nil {
		return tls.Certificate{}, err
	}
	return pair, nil
}
