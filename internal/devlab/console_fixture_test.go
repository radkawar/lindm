// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/escrow"
)

func TestConsoleIntegrationsUseOwnedProtectedKey(t *testing.T) {
	fixture := &AuthorityFixture{directory: t.TempDir()}
	cfg := new(configv1.ServerConfig)
	if err := fixture.configureConsoleIntegrations(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.GetIntegrations() == nil {
		t.Fatal("console integrations/report services were not configured")
	}
	keyFile := cfg.GetIntegrations().GetEncryptionKeyFile()
	if keyFile == "" || filepath.Base(keyFile) != keyFile {
		t.Fatal("integration key is not relative to the owned fixture")
	}
	path := filepath.Join(fixture.directory, keyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 32 {
		t.Fatal("integration encryption key is not a protected 32-byte file")
	}
}

func TestConsoleEscrowUsesOwnedProtectedKeys(t *testing.T) {
	fixture := &AuthorityFixture{directory: t.TempDir()}
	cfg := new(configv1.ServerConfig)
	if err := fixture.configureConsoleEscrow(cfg); err != nil {
		t.Fatal(err)
	}
	custody := cfg.GetEscrow()
	if custody == nil || custody.GetRevealApprovalRequired() {
		t.Fatal("console escrow missing or not single-owner revealable")
	}
	transport, wrapping := custody.GetTransportKeyFile(), custody.GetWrappingKeyFile()
	for _, name := range []string{transport, wrapping} {
		if name == "" || filepath.Base(name) != name {
			t.Fatal("escrow key is not relative to the owned fixture")
		}
		info, err := os.Stat(filepath.Join(fixture.directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("escrow key is not a protected regular file")
		}
	}
	if transport == wrapping {
		t.Fatal("escrow keys share one file")
	}
	encoded, err := os.ReadFile(filepath.Join(fixture.directory, transport))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("escrow transport key is not PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 3072 {
		t.Fatal("escrow transport key is not RSA-3072")
	}
	kek, err := os.ReadFile(filepath.Join(fixture.directory, wrapping))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := escrow.New(key, kek); err != nil {
		t.Fatal(err)
	}
}
