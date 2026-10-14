// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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

func TestDatabaseFailoverTLS(t *testing.T) {
	for _, test := range []struct {
		name      string
		authority string
		hosts     []string
		ports     []uint16
	}{
		{name: "single host", authority: "db1:6543", hosts: []string{"db1"}, ports: []uint16{6543}},
		{name: "default ports", authority: "db1,db2", hosts: []string{"db1", "db2"}, ports: []uint16{5432, 5432}},
		{name: "mixed ports", authority: "db1:5432,db2", hosts: []string{"db1", "db2"}, ports: []uint16{5432, 5432}},
		{name: "default and custom ports", authority: "db1,db2:6543,db3:", hosts: []string{"db1", "db2", "db3"}, ports: []uint16{5432, 6543, 5432}},
		{name: "IPv6 list", authority: "[2001:db8::1]:6543,[2001:db8::2]", hosts: []string{"2001:db8::1", "2001:db8::2"}, ports: []uint16{6543, 5432}},
		{name: "mixed IPv6 and DNS", authority: "db1:6543,[::1]:5433,db2", hosts: []string{"db1", "::1", "db2"}, ports: []uint16{6543, 5433, 5432}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := databaseFixture(t)
			root := writeCertificate(t, dir, "root", true, nil, nil)
			client := writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
			connection := "postgresql://user%40name:p%40ss%2Fword@" + test.authority + "/db%2Fname?sslmode=verify-full&sslrootcert=root.crt&sslcert=client.crt&sslkey=client.key&application_name=failover%20test+client"
			writeFixtureFile(t, dir, "database-url", []byte(connection))
			cfg, err := (&Document{base: dir}).database("database-url")
			if err != nil {
				t.Fatal(err)
			}
			conn := cfg.ConnConfig
			if conn.User != "user@name" || conn.Password != "p@ss/word" || conn.Database != "db/name" {
				t.Fatal("explicit URL credentials or database were changed")
			}
			if conn.RuntimeParams["application_name"] != "failover test+client" {
				t.Fatalf("application name changed: %q", conn.RuntimeParams["application_name"])
			}
			if conn.ConnectTimeout != 10*time.Second || len(conn.Fallbacks) != len(test.hosts)-1 {
				t.Fatalf("unexpected timeout or fallback count: %v, %d", conn.ConnectTimeout, len(conn.Fallbacks))
			}
			for i, expectedHost := range test.hosts {
				host, port, tlsConfig := conn.Host, conn.Port, conn.TLSConfig
				if i > 0 {
					fallback := conn.Fallbacks[i-1]
					host, port, tlsConfig = fallback.Host, fallback.Port, fallback.TLSConfig
				}
				if host != expectedHost || port != test.ports[i] {
					t.Fatalf("endpoint %d: got %s:%d, want %s:%d", i, host, port, expectedHost, test.ports[i])
				}
				if tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.ServerName != expectedHost {
					t.Fatalf("endpoint %d lacks verified TLS 1.3 for %s", i, expectedHost)
				}
				if tlsConfig.RootCAs == nil {
					t.Fatalf("endpoint %d lacks protected roots", i)
				}
				if _, err := root.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs, DNSName: "localhost"}); err != nil {
					t.Fatalf("endpoint %d cannot verify configured root: %v", i, err)
				}
				if len(tlsConfig.Certificates) != 1 || !tlsConfig.Certificates[0].Leaf.Equal(client) {
					t.Fatalf("endpoint %d lacks the protected client certificate", i)
				}
			}
		})
	}
}

func TestDatabaseRejectsUnsafeFailoverURLs(t *testing.T) {
	const base = "postgresql://user:fixture-secret@db1:5432,db2/database"
	for _, test := range []struct {
		name string
		url  string
	}{
		{name: "unsupported balancing", url: base + "?sslmode=verify-full&load_balance_hosts=random"},
		{name: "unsupported balancing disabled", url: base + "?sslmode=verify-full&load_balance_hosts=disable"},
		{name: "duplicate TLS mode", url: base + "?sslmode=disable&sslmode=verify-full"},
		{name: "encoded duplicate", url: base + "?sslmode=verify-full&%73slmode=verify-full"},
		{name: "TLS disabled", url: base + "?sslmode=disable"},
		{name: "unverified TLS", url: base + "?sslmode=require"},
		{name: "query host override", url: base + "?sslmode=verify-full&host=db3"},
		{name: "query user override", url: base + "?sslmode=verify-full&user=other"},
		{name: "query database override", url: base + "?sslmode=verify-full&dbname=other"},
		{name: "passfile", url: base + "?sslmode=verify-full&passfile=other"},
		{name: "service file", url: base + "?sslmode=verify-full&servicefile=other"},
		{name: "service", url: base + "?sslmode=verify-full&service=other"},
		{name: "empty fragment", url: base + "?sslmode=verify-full#"},
		{name: "fragment", url: base + "?sslmode=verify-full#fixture-secret"},
		{name: "missing user", url: "postgresql://db1,db2/database?sslmode=verify-full"},
		{name: "empty user", url: "postgresql://:fixture-secret@db1,db2/database?sslmode=verify-full"},
		{name: "empty database", url: "postgresql://user:fixture-secret@db1,db2/?sslmode=verify-full"},
		{name: "blank database", url: "postgresql://user:fixture-secret@db1,db2/ ?sslmode=verify-full"},
		{name: "missing database", url: "postgresql://user:fixture-secret@db1,db2?sslmode=verify-full"},
		{name: "empty primary", url: "postgresql://user:fixture-secret@,db2/database?sslmode=verify-full"},
		{name: "empty fallback", url: "postgresql://user:fixture-secret@db1,/database?sslmode=verify-full"},
		{name: "port only fallback", url: "postgresql://user:fixture-secret@db1,:5432/database?sslmode=verify-full"},
		{name: "encoded empty fallback", url: "postgresql://user:fixture-secret@db1%2C/database?sslmode=verify-full"},
		{name: "bracketed empty fallback", url: "postgresql://user:fixture-secret@[db1,]/database?sslmode=verify-full"},
		{name: "empty IPv6 fallback", url: "postgresql://user:fixture-secret@db1,[]/database?sslmode=verify-full"},
		{name: "malformed IPv6", url: "postgresql://user:fixture-secret@db1,[::1/database?sslmode=verify-full"},
		{name: "invalid port", url: "postgresql://user:fixture-secret@db1,db2:fixture-secret/database?sslmode=verify-full"},
		{name: "socket fallback", url: "postgresql://user:fixture-secret@db1,%2Ftmp/database?sslmode=verify-full"},
		{name: "NUL database", url: base + "%00?sslmode=verify-full"},
		{name: "malformed option escape", url: base + "?sslmode=verify-full&application_name=%zzfixture-secret"},
		{name: "invalid driver option", url: base + "?sslmode=verify-full&target_session_attrs=fixture-secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := databaseFixture(t)
			writeFixtureFile(t, dir, "database-url", []byte(test.url))
			_, err := (&Document{base: dir}).database("database-url")
			if err == nil {
				t.Fatal("accepted unsafe database URL")
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("database parse error exposed credential content")
			}
		})
	}
}

func TestDatabaseFailoverIgnoresHomeCredentials(t *testing.T) {
	dir := databaseFixture(t)
	t.Setenv("HOME", dir)
	if err := os.Mkdir(filepath.Join(dir, ".postgresql"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, dir, ".pgpass", []byte("*:*:*:*:home-secret\n"))
	for _, name := range []string{"root.crt", "postgresql.crt", "postgresql.key"} {
		writeFixtureFile(t, dir, filepath.Join(".postgresql", name), []byte("invalid implicit certificate"))
	}
	writeFixtureFile(t, dir, "database-url", []byte("postgresql://user@db1:5432,db2/database?sslmode=verify-full"))
	cfg, err := (&Document{base: dir}).database("database-url")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.Password != "" {
		t.Fatal("loaded an implicit password")
	}
	if len(cfg.ConnConfig.Fallbacks) != 1 {
		t.Fatalf("expected one fallback, got %d", len(cfg.ConnConfig.Fallbacks))
	}
	for _, tlsConfig := range []*tls.Config{cfg.ConnConfig.TLSConfig, cfg.ConnConfig.Fallbacks[0].TLSConfig} {
		if tlsConfig == nil {
			t.Fatal("missing verified TLS")
		}
		if tlsConfig.RootCAs != nil || len(tlsConfig.Certificates) != 0 {
			t.Fatal("loaded implicit home certificates")
		}
	}
	t.Setenv("PGPASSWORD", "environment-secret")
	if _, err := (&Document{base: dir}).database("database-url"); err == nil || strings.Contains(err.Error(), "environment-secret") {
		t.Fatal("inherited PostgreSQL credentials were accepted or exposed")
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
				PublicUrl:      "https://localhost",
				Database:       &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
				Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
				DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
				Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{ClientSecretFile: "oidc-secret", DirectoryClientSecretFile: "oidc-secret"}}},
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
	u := url.URL{Scheme: "postgresql", Host: "localhost:5432,db2", Path: "/isolated_test", User: url.UserPassword("isolated_test", "not-a-deployed-credential"), RawQuery: options.Encode()}
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
