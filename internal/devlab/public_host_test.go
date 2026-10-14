// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidatePublicHost(t *testing.T) {
	for _, host := range []string{"lindm-console.test", "a.b.example", "x1.test"} {
		if err := ValidatePublicHost(host); err != nil {
			t.Errorf("%q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"", "localhost", "console.localhost", "lindm", "127.0.0.1", "::1", "10.0.2.2", "1.2.3", "Lindm.test", "-a.test", "a-.test", "a..test", "a.test.", "a_b.test", "https://a.test", "a.test:443", string(make([]byte, 254))} {
		if err := ValidatePublicHost(host); err == nil {
			t.Errorf("%q accepted", host)
		}
	}
}

func TestPublicHostCertificateNamesHostUnderSharedCA(t *testing.T) {
	shared, directory := t.TempDir(), t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test transport CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "transport-ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "transport-ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePublicHostCertificate(shared, directory, "lindm-console.test"); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(directory, "public-server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"lindm-console.test", "localhost", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("leaf does not serve %s under the shared CA: %v", name, err)
		}
	}
	if err := leaf.VerifyHostname("other.test"); err == nil {
		t.Fatal("leaf names an unrequested host")
	}
	info, err := os.Stat(filepath.Join(directory, "public-server.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("leaf key is not private: %v", err)
	}
}
