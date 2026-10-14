// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestEscrowProtectedCustodyFiles(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	dir := t.TempDir()
	transportPath := filepath.Join(dir, "transport.pem")
	wrappingPath := filepath.Join(dir, "wrapping.key")
	if err := os.WriteFile(transportPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	wrapping := make([]byte, 32)
	if _, err := rand.Read(wrapping); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrappingPath, wrapping, 0600); err != nil {
		t.Fatal(err)
	}
	defer clear(wrapping)
	d := &Document{Proto: &configv1.ServerConfig{Escrow: &configv1.EscrowConfig{TransportKeyFile: "transport.pem", WrappingKeyFile: "wrapping.key"}}, base: dir}
	custody, err := d.escrowCustody()
	if err != nil || custody == nil {
		t.Fatalf("protected resources: %v", err)
	}
	if err := os.Chmod(wrappingPath, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := d.escrowCustody(); err == nil {
		t.Fatal("accepted group-readable wrapping key")
	}
	if err := os.Chmod(wrappingPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(transportPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.escrowCustody(); err == nil {
		t.Fatal("accepted public transport private key")
	}
	if err := os.Chmod(transportPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrappingPath, make([]byte, 31), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.escrowCustody(); err == nil {
		t.Fatal("accepted short wrapping key")
	}
}
