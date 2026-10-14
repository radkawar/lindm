// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestIntegrationEncryptionKeyProtection(t *testing.T) {
	for _, test := range []struct {
		name     string
		length   int
		mode     os.FileMode
		accepted bool
	}{
		{name: "protected exact key", length: 32, mode: 0600, accepted: true},
		{name: "short key", length: 31, mode: 0600},
		{name: "newline is not trimmed", length: 33, mode: 0600},
		{name: "public key file", length: 32, mode: 0644},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := databaseFixture(t)
			writeCertificate(t, dir, "root", true, nil, nil)
			writeCertificate(t, dir, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
			writeBrowserCertificate(t, dir, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
			writeCertificate(t, dir, "device", true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
			key := bytes.Repeat([]byte{0x73}, test.length)
			writeFixtureFile(t, dir, "integration-key", key)
			if err := os.Chmod(filepath.Join(dir, "integration-key"), test.mode); err != nil {
				t.Fatal(err)
			}
			document := &Document{base: dir, Proto: &configv1.ServerConfig{
				PublicUrl: "https://localhost", Database: &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 2},
				Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
				DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
				Authentication: localAuthentication(),
				Integrations:   &configv1.IntegrationsConfig{EncryptionKeyFile: "integration-key"},
			}}
			resources, err := document.Resolve()
			if err != nil {
				if test.accepted {
					t.Fatal(err)
				}
				if strings.Contains(err.Error(), string(key)) {
					t.Fatal("error exposed encryption key")
				}
				return
			}
			defer resources.HTTPClient.CloseIdleConnections()
			if !test.accepted {
				t.Fatal("unsafe integration encryption key accepted")
			}
			if !bytes.Equal(resources.IntegrationEncryptionKey, key) {
				t.Fatal("encryption key bytes changed")
			}
		})
	}
}
