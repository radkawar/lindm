// SPDX-License-Identifier: Apache-2.0

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
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/assistrelay"
	"lindm/internal/escrow"
	"lindm/internal/pki"
)

// Resources contains resolved dependencies, not a second serialized schema.
// HTTPClient owns its transport; close idle connections during server shutdown.
type Resources struct {
	Proto    *configv1.ServerConfig
	Database *pgxpool.Config
	// AdminDatabase is the separate console/identity pool (same credential).
	AdminDatabase     *pgxpool.Config
	ServerCertificate tls.Certificate
	// Enrollment HTTPS trust is selected from verified server certificate
	// material, not from the independently provisioned device-client CA.
	EnrollmentTLSCAPEM          string
	EnrollmentTLSCASHA256       string
	EnrollmentTLSUnavailable    bool
	DeviceCACertificate         *x509.Certificate
	DeviceCAKey                 crypto.Signer
	HTTPClient                  *http.Client
	ClientSecret                string
	DirectoryClientSecret       string
	DirectoryPrivateKeyPEM      []byte
	BrokerDirectoryClientSecret string
	InventoryBudgetBytes        int64
	ExecutionBootstrap          *ExecutionBootstrap
	// ExecutionSigning is nil unless execution_signing is configured. Loaded
	// keys are not a delegation and do not authorize issuance.
	ExecutionSigning *ExecutionSigning
	// IntegrationEncryptionKey protects destination credentials at rest.
	IntegrationEncryptionKey []byte
	// Escrow uses distinct ingress and wrapping keys, never inventory storage.
	Escrow                            *escrow.Custody
	EscrowRevealApprovalRequired      bool
	ReleaseRepositoryDirectory        string
	ReleaseSigningDirectory           string
	ReleaseVerificationStateDirectory string
	// Offline bundle paths are resolved only when offline_bundles is configured.
	OfflineBundleDirectory        string
	OfflineBundleSigningPublicKey string
	OfflineBundleReleasePublicKey string
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

// listenersOverlap reports whether binding both listeners would conflict on a
// shared port: same address, or either side binds every address.
func listenersOverlap(a, b *configv1.ListenerConfig) bool {
	if a.GetPort() != b.GetPort() {
		return false
	}
	first, errFirst := netip.ParseAddr(a.GetAddress())
	second, errSecond := netip.ParseAddr(b.GetAddress())
	if errFirst != nil || errSecond != nil {
		return true
	}
	return first.Unmap() == second.Unmap() || first.IsUnspecified() || second.IsUnspecified()
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
	if err == nil {
		result.AdminDatabase, err = d.AdminDatabase()
	}
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
	if err := d.resolveEnrollmentTLS(result); err != nil {
		return nil, fmt.Errorf("resolve enrollment HTTPS trust: %w", err)
	}
	result.ExecutionSigning, err = d.executionSigning(verifier)
	if err != nil {
		return nil, err
	}
	if integration := cfg.GetIntegrations(); integration != nil {
		result.IntegrationEncryptionKey, err = readFile(reference(base, integration.GetEncryptionKeyFile()), true)
		if err != nil {
			return nil, fmt.Errorf("read integrations.encryption_key_file: %w", err)
		}
		if len(result.IntegrationEncryptionKey) != 32 {
			return nil, errors.New("integrations.encryption_key_file must contain exactly 32 raw bytes")
		}
	}
	result.Escrow, err = d.escrowCustody()
	if err != nil {
		return nil, fmt.Errorf("load recovery escrow custody: %w", err)
	}
	result.EscrowRevealApprovalRequired = cfg.GetEscrow().GetRevealApprovalRequired()
	if release := cfg.GetReleaseRepository(); release != nil {
		result.ReleaseRepositoryDirectory = reference(base, release.GetDirectory())
		if release.GetSigning() != nil {
			result.ReleaseSigningDirectory = reference(base, release.GetSigning().GetDirectory())
		}
		if release.GetVerificationStateDirectory() != "" {
			result.ReleaseVerificationStateDirectory = reference(base, release.GetVerificationStateDirectory())
		}
	}
	if bundles := cfg.GetOfflineBundles(); bundles != nil {
		result.OfflineBundleDirectory = reference(base, bundles.GetDirectory())
		result.OfflineBundleSigningPublicKey = reference(base, bundles.GetSigningPublicKeyFile())
		result.OfflineBundleReleasePublicKey = reference(base, bundles.GetReleaseAttestationPublicKeyFile())
	}
	if assistance := cfg.GetAssistance(); assistance != nil {
		if err := assistrelay.Validate(assistance); err != nil {
			return nil, fmt.Errorf("invalid assistance configuration: %w", err)
		}
		relay := assistance.GetRelay().GetListener()
		for _, other := range []*configv1.ListenerConfig{cfg.GetAdminListener(), cfg.GetDeviceListener(), cfg.GetProfiling().GetListener()} {
			if other != nil && listenersOverlap(relay, other) {
				return nil, errors.New("assistance relay listener must not overlap the administrative, device or profiling listener")
			}
		}
	}

	if err := d.authenticationSecrets(result); err != nil {
		return nil, err
	}
	result.HTTPClient, err = d.outboundHTTPClient()
	if err != nil {
		return nil, err
	}
	return result, nil
}

// outboundHTTPClient trusts the system roots plus trusted_ca_file, requires TLS
// 1.3 and never follows redirects.
func (d *Document) outboundHTTPClient() (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system trust roots: %w", err)
	}
	if d.Proto.GetTrustedCaFile() != "" {
		pem, err := readFile(reference(d.base, d.Proto.GetTrustedCaFile()), false)
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
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (d *Document) authenticationSecrets(result *Resources) error {
	auth := d.Proto.GetAuthentication()
	var provider, loginFile, directoryFile, privateKeyFile string
	if keycloak := auth.GetKeycloak(); keycloak != nil {
		provider, loginFile, directoryFile = "keycloak", keycloak.GetClientSecretFile(), keycloak.GetDirectoryClientSecretFile()
		if upstream := keycloak.GetUpstream(); upstream != nil {
			secret, err := d.authenticationSecret("keycloak.upstream.directory_client_secret_file", upstream.GetDirectoryClientSecretFile())
			if err != nil {
				return err
			}
			result.BrokerDirectoryClientSecret = secret
		}
	} else if entra := auth.GetEntra(); entra != nil {
		provider, loginFile, directoryFile = "entra", entra.GetClientSecretFile(), entra.GetDirectoryClientSecretFile()
	} else if okta := auth.GetOkta(); okta != nil {
		provider, loginFile, privateKeyFile = "okta", okta.GetClientSecretFile(), okta.GetDirectoryPrivateKeyFile()
	} else if google := auth.GetGoogle(); google != nil {
		provider, loginFile, privateKeyFile = "google", google.GetClientSecretFile(), google.GetPrivateKeyFile()
	} else {
		return nil
	}
	var err error
	result.ClientSecret, err = d.authenticationSecret(provider+".client_secret_file", loginFile)
	if err != nil {
		return err
	}
	if directoryFile != "" {
		result.DirectoryClientSecret, err = d.authenticationSecret(provider+".directory_client_secret_file", directoryFile)
		if err != nil {
			return err
		}
	}
	if privateKeyFile != "" {
		result.DirectoryPrivateKeyPEM, err = readFile(reference(d.base, privateKeyFile), true)
		if err != nil {
			return fmt.Errorf("read authentication.%s directory private key: %w", provider, err)
		}
		if len(bytes.TrimSpace(result.DirectoryPrivateKeyPEM)) == 0 {
			return fmt.Errorf("authentication.%s directory private key must not be empty", provider)
		}
	}
	return nil
}

func (d *Document) authenticationSecret(field, path string) (string, error) {
	secret, err := readFile(reference(d.base, path), true)
	if err != nil {
		return "", fmt.Errorf("read authentication.%s: %w", field, err)
	}
	value := strings.TrimSpace(string(secret))
	if value == "" {
		return "", fmt.Errorf("authentication.%s must not be empty", field)
	}
	return value, nil
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

// DefaultAdminConnections sizes the console/identity pool when unset.
const DefaultAdminConnections = 4

// AdminDatabase resolves the runtime credential for the separate console and
// identity pool, so device traffic saturating Database cannot delay operators.
func (d *Document) AdminDatabase() (*pgxpool.Config, error) {
	cfg, err := d.database(d.Proto.GetDatabase().GetUrlFile())
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = DefaultAdminConnections
	if d.Proto.GetDatabase().AdminConnections != nil {
		cfg.MaxConns = int32(d.Proto.GetDatabase().GetAdminConnections())
	}
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
