package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestDatabaseRejectsUnprotectedTLSResources(t *testing.T) {
	for _, test := range []struct {
		name string
		file string
		mode os.FileMode
	}{
		{name: "writable trust anchor", file: "root.crt", mode: 0666},
		{name: "readable client private key", file: "client.key", mode: 0644},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := databaseFixture(t)
			root := writeCertificate(t, dir, "root", true, nil, nil)
			writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
			document := &Document{base: dir}
			cfg, err := document.database("database-url")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.Verify(x509.VerifyOptions{Roots: cfg.ConnConfig.TLSConfig.RootCAs, DNSName: "localhost"}); err != nil {
				t.Fatalf("configured database trust does not verify its CA: %v", err)
			}
			if err := os.Chmod(filepath.Join(dir, test.file), test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := document.database("database-url"); err == nil {
				t.Fatalf("accepted %s", test.name)
			}
		})
	}
}

func TestResolveDeviceCAUsage(t *testing.T) {
	for _, test := range []struct {
		name     string
		usage    []x509.ExtKeyUsage
		unknown  []asn1.ObjectIdentifier
		accepted bool
	}{
		{name: "unrestricted", accepted: true},
		{name: "client authentication", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, accepted: true},
		{name: "any usage", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, accepted: true},
		{name: "server only", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "unknown only", unknown: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := databaseFixture(t)
			writeCertificate(t, dir, "root", true, nil, nil)
			writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
			writeCertificate(t, dir, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
			writeCertificate(t, dir, "device", true, test.usage, test.unknown)
			writeFixtureFile(t, dir, "oidc-secret", []byte("isolated-test-credential"))
			document := &Document{base: dir, Proto: &configv1.ServerConfig{
				PublicUrl: "https://localhost",
				Database:  &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
				Tls:       &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
				DeviceCa:  &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
				Oidc:      &configv1.OIDCConfig{ClientSecretFile: "oidc-secret", DirectoryClientSecretFile: "oidc-secret"},
			}}
			resources, err := document.Resolve()
			if !test.accepted {
				if err == nil {
					resources.HTTPClient.CloseIdleConnections()
					t.Fatalf("accepted device CA restricted to %s", test.name)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			resources.HTTPClient.CloseIdleConnections()
			pool := x509.NewCertPool()
			pool.AddCert(resources.DeviceCACertificate)
			if _, err := resources.DeviceCACertificate.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatalf("accepted CA cannot verify client authentication: %v", err)
			}
		})
	}
}

func databaseFixture(t *testing.T) string {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") {
			t.Setenv(name, "")
		}
	}
	dir := t.TempDir()
	options := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"root.crt"}, "sslcert": {"client.crt"}, "sslkey": {"client.key"}}
	u := url.URL{Scheme: "postgresql", Host: "localhost:5432", Path: "/isolated_test", User: url.UserPassword("isolated_test", "not-a-deployed-credential"), RawQuery: options.Encode()}
	writeFixtureFile(t, dir, "database-url", []byte(u.String()))
	return dir
}

func writeCertificate(t *testing.T, dir, name string, ca bool, usage []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, UnknownExtKeyUsage: unknown}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, dir, name+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFixtureFile(t, dir, name+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func writeFixtureFile(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
		t.Fatal(err)
	}
}
