// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

func integrationCLIConfig(t *testing.T) string {
	t.Helper()
	path := credentialCLIConfig(t)
	document, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	document.Proto.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: "persistent-integrations.key"}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(path)
	if err := os.WriteFile(filepath.Join(base, "database-url"), []byte("postgresql://runtime@localhost/lindm?sslmode=verify-full"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "persistent-integrations.key"), bytes.Repeat([]byte{0x70}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server", "device"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if name == "device" {
			certificate.IsCA, certificate.BasicConstraintsValid = true, true
			certificate.KeyUsage |= x509.KeyUsageCertSign
			certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		for extension, block := range map[string]*pem.Block{"crt": {Type: "CERTIFICATE", Bytes: der}, "key": {Type: "PRIVATE KEY", Bytes: privateDER}} {
			if err := os.WriteFile(filepath.Join(base, name+"."+extension), pem.EncodeToMemory(block), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return path
}

func TestCLIExplicitIntegrationCredentialFailsClosed(t *testing.T) {
	for _, command := range []string{"serve", "check-config"} {
		for _, failure := range []string{"missing directory", "missing file", "empty name", "path instead of name", "unsafe mode", "truncated key"} {
			t.Run(command+"/"+failure, func(t *testing.T) {
				path := integrationCLIConfig(t)
				directory := t.TempDir()
				if err := os.Chmod(directory, 0700); err != nil {
					t.Fatal(err)
				}
				name := "integrations-key"
				want := "read integrations.encryption_key_file"
				switch failure {
				case "missing directory":
					directory = ""
					want = "CREDENTIALS_DIRECTORY"
				case "empty name":
					name = ""
					want = "valid credential name"
				case "path instead of name":
					name = "/etc/lindm/integrations.key"
					want = "valid credential name"
				case "unsafe mode", "truncated key":
					mode, length := os.FileMode(0400), 31
					if failure == "unsafe mode" {
						mode, length = 0644, 32
					} else {
						want = "exactly 32 raw bytes"
					}
					if err := os.WriteFile(filepath.Join(directory, name), bytes.Repeat([]byte{0x65}, length), mode); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("CREDENTIALS_DIRECTORY", directory)
				err := run(context.Background(), []string{command, "-config", path, "-integrations-key-credential=" + name})
				if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), strings.Repeat("e", 31)) {
					t.Fatalf("explicit integration credential failure was not closed/redacted: %v", err)
				}
			})
		}
	}
}

func TestCLIIntegrationCredentialRequiresExplicitFlagWithoutFallback(t *testing.T) {
	path := integrationCLIConfig(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "integrations-key"), bytes.Repeat([]byte{0x65}, 32), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), "persistent-integrations.key")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	if err := run(context.Background(), []string{"check-config", "-config", path}); err == nil || !strings.Contains(err.Error(), "read integrations.encryption_key_file") {
		t.Fatalf("ambient credentials selected an integration key: %v", err)
	}
	if err := run(context.Background(), []string{"check-config", "-config", path, "-integrations-key-credential", "integrations-key"}); err != nil {
		t.Fatalf("explicit ephemeral credential did not complete normal runtime resolution: %v", err)
	}
}

func TestCLIIntegrationCredentialIsRuntimeOnly(t *testing.T) {
	for _, command := range []string{"migrate", "setup-code", "bootstrap-owner", "schema-check", "backup", "restore", "custody-status"} {
		t.Run(command, func(t *testing.T) {
			err := run(context.Background(), []string{command, "-integrations-key-credential", "integrations-key"})
			want := "flag provided but not defined"
			if command == "backup" || command == "restore" || command == "custody-status" {
				want = "operations: invalid_arguments"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unrelated command accepted integration secret access: %v", err)
			}
		})
	}
	for _, command := range []string{"serve", "check-config"} {
		if err := run(context.Background(), []string{command, "-integrations-key-credential", "integrations-key", "-help"}); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("runtime public capability preflight rejected the explicit credential flag: %v", err)
		}
	}
}
