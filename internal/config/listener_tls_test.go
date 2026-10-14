// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestResolvedIndependentConsoleAndDeviceTLS(t *testing.T) {
	fixture, consoleCA := splitTLSFixture(t)
	resources, err := fixture.document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if !resources.AdminCACertificate.Equal(consoleCA.Leaf) || resources.AdminServerCertificate.Leaf.Equal(resources.ServerCertificate.Leaf) {
		t.Fatal("console identity was not independently resolved")
	}
	if resources.AdminServerCertificate.Leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || resources.ServerCertificate.Leaf.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatal("console and device algorithms changed")
	}
	if err := resources.ServerCertificate.Leaf.VerifyHostname("console.example"); err == nil {
		t.Fatal("fixture does not prove separate hostnames")
	}
	if err := resources.AdminServerCertificate.Leaf.VerifyHostname("devices.example"); err == nil {
		t.Fatal("console certificate unexpectedly covers device hostname")
	}
	digest := sha256.Sum256(consoleCA.Leaf.Raw)
	if resources.EnrollmentTLSUnavailable || resources.EnrollmentTLSCASHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("native downloads did not receive the approved console-origin CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(consoleCA.Leaf)
	if _, err := resources.ServerCertificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "devices.example"}); err == nil {
		t.Fatal("device transport trusted the console CA")
	}
	fixture.bundle.TransportCaPem = executionConfigFile(t, fixture.document.base, "console-ca.crt")
	fixture.publish(t)
	if resources, err := fixture.document.Resolve(); err == nil {
		resources.HTTPClient.CloseIdleConnections()
		t.Fatal("bootstrap accepted console CA as device transport authority")
	}
}

func TestSplitBootstrapRejectsConsoleSignedDeviceHostnameCertificate(t *testing.T) {
	fixture, consoleCA := splitTLSFixture(t)
	deviceKey := executionFixturePrivateKey(t, fixture.document.base, "server.key")
	certificate := writeListenerCertificate(t, fixture.document.base, "server", consoleCA, deviceKey, func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.DNSNames = []string{"devices.example"}
	})
	roots := x509.NewCertPool()
	roots.AddCert(consoleCA.Leaf)
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "devices.example"}); err != nil {
		t.Fatalf("console-signed same-DNS attack certificate is invalid: %v", err)
	}
	resources, err := fixture.document.Resolve()
	if err == nil {
		resources.HTTPClient.CloseIdleConnections()
		t.Fatal("device endpoint accepted a same-DNS certificate signed by the console CA")
	}
	if !strings.Contains(err.Error(), "server TLS at https://devices.example:7445 does not satisfy execution bootstrap origin pins") {
		t.Fatalf("device certificate was not rejected by its signed origin pool: %v", err)
	}
}

func TestSplitBootstrapMustAuthorizeConsoleEnrollmentRoot(t *testing.T) {
	fixture, _ := splitTLSFixture(t)
	fixture.bundle.ConsoleCaPem = executionConfigFile(t, fixture.document.base, "transport.crt")
	fixture.publish(t)
	resources, err := fixture.document.Resolve()
	if err == nil {
		resources.HTTPClient.CloseIdleConnections()
		t.Fatal("split console CA was not required in signed enrollment trust")
	}
	if !strings.Contains(err.Error(), "console pins omit admin_ca_file") {
		t.Fatalf("unexpected missing console trust error: %v", err)
	}
}

func TestAdminTLSRejectsInvalidIdentityAndCA(t *testing.T) {
	for _, kind := range []string{"wrong host", "expired leaf", "client only", "wrong CA", "non CA", "expired CA", "malformed CA", "missing pair", "missing CA"} {
		t.Run(kind, func(t *testing.T) {
			fixture, consoleCA := splitTLSFixture(t)
			document := fixture.document
			consoleSigner, ok := consoleCA.PrivateKey.(crypto.Signer)
			if !ok {
				t.Fatal("console fixture has no private signer")
			}
			switch kind {
			case "wrong host", "expired leaf", "client only":
				writeListenerCertificate(t, document.base, "admin", consoleCA, consoleSigner, func(c *x509.Certificate) {
					c.IsCA = false
					c.KeyUsage = x509.KeyUsageDigitalSignature
					c.DNSNames = []string{"console.example"}
					c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
					if kind == "wrong host" {
						c.DNSNames = []string{"wrong.example"}
					}
					if kind == "expired leaf" {
						c.NotAfter = time.Now().Add(-time.Minute)
					}
					if kind == "client only" {
						c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
					}
				})
			case "wrong CA":
				document.Proto.AdminCaFile = proto.String("transport.crt")
			case "non CA":
				document.Proto.AdminCaFile = proto.String("admin.crt")
			case "expired CA":
				writeListenerCertificate(t, document.base, "console-ca", tls.Certificate{}, consoleSigner, func(c *x509.Certificate) {
					c.NotAfter = time.Now().Add(-time.Minute)
				})
			case "malformed CA":
				writeFixtureFile(t, document.base, "console-ca.crt", []byte("not a certificate"))
			case "missing pair":
				document.Proto.AdminTls = nil
			case "missing CA":
				document.Proto.AdminCaFile = nil
			}
			if resources, err := document.Resolve(); err == nil {
				resources.HTTPClient.CloseIdleConnections()
				t.Fatalf("accepted %s", kind)
			}
		})
	}
}

func TestAdminTLSAbsentRetainsExistingSharedFixture(t *testing.T) {
	fixture := newExecutionConfigFixture(t)
	fixture.document.Proto.AdminTls = nil
	fixture.document.Proto.AdminCaFile = nil
	consoleCA, err := keyPair(fixture.document.base, "console-ca.crt", "console-ca.key")
	if err != nil {
		t.Fatal(err)
	}
	consoleSigner, ok := consoleCA.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("console fixture has no private signer")
	}
	writeListenerCertificate(t, fixture.document.base, "server", consoleCA, consoleSigner, func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.DNSNames = []string{"localhost"}
	})
	fixture.bundle.TransportCaPem = executionConfigFile(t, fixture.document.base, "console-ca.crt")
	fixture.publish(t)
	resources, err := fixture.document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if resources.AdminCACertificate != nil || !resources.AdminServerCertificate.Leaf.Equal(resources.ServerCertificate.Leaf) {
		t.Fatal("absent override did not retain shared TLS")
	}
}

func TestAdminTLSConfigPairPresence(t *testing.T) {
	for _, kind := range []string{"absent", "both", "pair only", "CA only", "empty CA"} {
		t.Run(kind, func(t *testing.T) {
			cfg := executionSigningSchemaConfig()
			if kind == "both" || kind == "pair only" || kind == "empty CA" {
				cfg.AdminTls = &configv1.TLSConfig{CertificateFile: "admin.crt", PrivateKeyFile: "admin.key"}
			}
			if kind == "both" || kind == "CA only" {
				cfg.AdminCaFile = proto.String("console-ca.crt")
			}
			if kind == "empty CA" {
				cfg.AdminCaFile = proto.String("")
			}
			err := protovalidate.Validate(cfg)
			accepted := kind == "absent" || kind == "both"
			if (err == nil) != accepted {
				t.Fatalf("config presence acceptance = %t, want %t: %v", err == nil, accepted, err)
			}
		})
	}
}

func splitTLSFixture(t *testing.T) (*executionConfigFixture, tls.Certificate) {
	t.Helper()
	fixture := newExecutionConfigFixture(t)
	document := fixture.document
	document.Proto.PublicUrl = "https://console.example:7444"
	document.Proto.DevicePublicUrl = proto.String("https://devices.example:7445")
	deviceKey := executionFixturePrivateKey(t, document.base, "server.key")
	writeListenerCertificate(t, document.base, "server", fixture.transport, deviceKey, func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.DNSNames = []string{"devices.example"}
	})
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	consoleCA := writeListenerCertificate(t, document.base, "console-ca", tls.Certificate{}, caKey, nil)
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeListenerCertificate(t, document.base, "admin", consoleCA, adminKey, func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.DNSNames = []string{"console.example"}
	})
	document.Proto.AdminTls = &configv1.TLSConfig{CertificateFile: "admin.crt", PrivateKeyFile: "admin.key"}
	document.Proto.AdminCaFile = proto.String("console-ca.crt")
	fixture.bundle.EnrollmentOrigin = document.Proto.GetPublicUrl()
	fixture.bundle.DeviceOrigin = document.Proto.GetDevicePublicUrl()
	// Fresh bootstrap authorizes console-origin public enrollment/downloads
	// and device transport separately; neither identity changes issuer.
	fixture.bundle.TransportCaPem = executionConfigFile(t, document.base, "transport.crt")
	fixture.bundle.ConsoleCaPem = executionConfigFile(t, document.base, "console-ca.crt")
	fixture.publish(t)
	return fixture, consoleCA
}

func writeListenerCertificate(t *testing.T, dir, name string, issuer tls.Certificate, key crypto.Signer, change func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	if change != nil {
		change(certificate)
	}
	parent, signer := issuer.Leaf, issuer.PrivateKey
	if parent == nil {
		parent, signer = certificate, key
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, dir, name+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFixtureFile(t, dir, name+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
