// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
)

func TestSharedEd25519AdminTLSFailsClosed(t *testing.T) {
	fixture := newExecutionConfigFixture(t)
	fixture.document.Proto.AdminTls = nil
	fixture.document.Proto.AdminCaFile = nil
	// The existing fixture's device certificate is valid Ed25519. Resolving
	// it as a browser identity must fail without an explicit console override.
	resources, err := fixture.document.Resolve()
	if err == nil {
		resources.HTTPClient.CloseIdleConnections()
		t.Fatal("shared Ed25519 identity bypassed console admission")
	}
	if !strings.Contains(err.Error(), "admin_tls certificate is not browser-compatible") {
		t.Fatalf("missing shared console browser rejection reason: %v", err)
	}
}

func TestExplicitAdminTLSRejectsEd25519LeafAndIssuer(t *testing.T) {
	for _, kind := range []string{"Ed25519 public key", "Ed25519 issuer signature"} {
		t.Run(kind, func(t *testing.T) {
			fixture, consoleCA := splitTLSFixture(t)
			document := fixture.document
			pair, err := keyPair(document.base, "admin.crt", "admin.key")
			if err != nil {
				t.Fatal(err)
			}
			key, ok := pair.PrivateKey.(crypto.Signer)
			if !ok {
				t.Fatal("admin fixture has no private signer")
			}
			if kind == "Ed25519 public key" {
				key = executionFixturePrivateKey(t, document.base, "server.key")
			} else {
				consoleCA = fixture.transport
				*document.Proto.AdminCaFile = "transport.crt"
			}
			admin := writeListenerCertificate(t, document.base, "admin", consoleCA, key, consoleLeafTemplate)
			// Establish that the failure is browser admission, not an invalid
			// cryptographic chain, hostname, lifetime or key pair.
			roots := x509.NewCertPool()
			roots.AddCert(consoleCA.Leaf)
			if _, err := admin.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "console.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				t.Fatalf("negative fixture is not otherwise valid: %v", err)
			}
			if kind == "Ed25519 public key" && (admin.Leaf.PublicKeyAlgorithm != x509.Ed25519 || admin.Leaf.SignatureAlgorithm == x509.PureEd25519) {
				t.Fatal("fixture must isolate the unsupported leaf public key")
			}
			if kind == "Ed25519 issuer signature" && (admin.Leaf.PublicKeyAlgorithm == x509.Ed25519 || admin.Leaf.SignatureAlgorithm != x509.PureEd25519) {
				t.Fatal("fixture must isolate the unsupported issuer signature")
			}
			resources, err := document.Resolve()
			if err == nil {
				resources.HTTPClient.CloseIdleConnections()
				t.Fatalf("accepted browser-incompatible %s", kind)
			}
			if !strings.Contains(err.Error(), "admin_tls certificate is not browser-compatible") {
				t.Fatalf("missing browser-specific admission reason: %v", err)
			}
		})
	}
}

func TestExplicitAdminTLSAllowsBrowserCompatibleBYOAlgorithms(t *testing.T) {
	for _, kind := range []string{"ECDSA P384", "RSA 3072"} {
		t.Run(kind, func(t *testing.T) {
			fixture, _ := splitTLSFixture(t)
			document := fixture.document
			var key crypto.Signer
			var err error
			if kind == "ECDSA P384" {
				key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			} else {
				key, err = rsa.GenerateKey(rand.Reader, 3072)
			}
			if err != nil {
				t.Fatal(err)
			}
			consoleCA := writeListenerCertificate(t, document.base, "console-ca", tls.Certificate{}, key, nil)
			writeListenerCertificate(t, document.base, "admin", consoleCA, key, consoleLeafTemplate)
			fixture.bundle.ConsoleCaPem = executionConfigFile(t, document.base, "console-ca.crt")
			fixture.publish(t)
			resources, err := document.Resolve()
			if err != nil {
				t.Fatalf("browser-compatible %s rejected: %v", kind, err)
			}
			defer resources.HTTPClient.CloseIdleConnections()
			if resources.ServerCertificate.Leaf.PublicKeyAlgorithm != x509.Ed25519 {
				t.Fatal("browser admission changed device Ed25519 identity")
			}
		})
	}
}

func consoleLeafTemplate(c *x509.Certificate) {
	c.IsCA = false
	c.KeyUsage = x509.KeyUsageDigitalSignature
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	c.DNSNames = []string{"console.example"}
}
