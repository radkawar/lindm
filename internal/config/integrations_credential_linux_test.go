// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestIntegrationCredentialFailsClosedWithoutPersistentFallback(t *testing.T) {
	for _, failure := range []string{"missing", "empty", "truncated", "newline", "oversized", "readable", "writable", "executable", "directory", "symlink", "hardlink", "fifo", "unsafe directory", "symlink directory", "replaceable ancestor", "foreign owner"} {
		t.Run(failure, func(t *testing.T) {
			base := t.TempDir()
			persistent := bytes.Repeat([]byte{0x61}, 32)
			writeFixtureFile(t, base, "persistent-key", persistent)
			credential := credentialDirectory(t, nil)
			path := filepath.Join(credential, "integrations-key")
			key := bytes.Repeat([]byte{0x62}, 32)
			if err := os.WriteFile(path, key, 0400); err != nil {
				t.Fatal(err)
			}
			var err error
			switch failure {
			case "missing", "directory", "symlink", "fifo":
				err = os.Remove(path)
				if err == nil {
					switch failure {
					case "directory":
						err = os.Mkdir(path, 0700)
					case "symlink":
						err = os.Symlink(filepath.Join(base, "persistent-key"), path)
					case "fifo":
						err = unix.Mkfifo(path, 0600)
					}
				}
			case "empty", "truncated", "newline", "oversized":
				length := map[string]int{"empty": 0, "truncated": 31, "newline": 33, "oversized": maxFileBytes + 1}[failure]
				err = os.Remove(path)
				if err == nil {
					err = os.WriteFile(path, bytes.Repeat([]byte{0x62}, length), 0400)
				}
			case "readable":
				err = os.Chmod(path, 0444)
			case "writable":
				err = os.Chmod(path, 0620)
			case "executable":
				err = os.Chmod(path, 0500)
			case "hardlink":
				err = os.Link(path, filepath.Join(credential, "alias"))
			case "unsafe directory":
				err = os.Chmod(credential, 0755)
			case "symlink directory":
				link := filepath.Join(t.TempDir(), "credentials")
				err = os.Symlink(credential, link)
				credential = link
			case "replaceable ancestor":
				parent := t.TempDir()
				err = os.Chmod(parent, 0777)
				if err == nil {
					credential = filepath.Join(parent, "credentials")
					err = os.Mkdir(credential, 0700)
				}
			case "foreign owner":
				if os.Geteuid() != 0 {
					t.Skip("foreign credential ownership requires root")
				}
				err = os.Chown(path, 65534, 65534)
			}
			if err != nil {
				t.Fatal(err)
			}
			document := &Document{base: base, Proto: &configv1.ServerConfig{Integrations: &configv1.IntegrationsConfig{EncryptionKeyFile: "persistent-key"}}}
			if err := document.UseIntegrationEncryptionKeyCredential("integrations-key", credential); err != nil {
				t.Fatal(err)
			}
			if got, err := document.integrationEncryptionKey(); err == nil || got != nil || strings.Contains(err.Error(), string(key)) || strings.Contains(err.Error(), string(persistent)) {
				t.Fatal("unsafe explicit credential was accepted, fell back, or exposed key bytes")
			}
		})
	}
}

func TestIntegrationCredentialRejectsAmbiguousSelection(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../integrations-key", "/etc/lindm/integrations.key", "integrations/key", "integrations-key\x00", "integrations key", strings.Repeat("a", 256)} {
		if err := (&Document{}).UseIntegrationEncryptionKeyCredential(name, "/run/credentials/lindmd.service"); err == nil {
			t.Fatalf("accepted invalid credential name %q", name)
		}
	}
	for _, directory := range []string{"", ".", "/", "run/credentials", "/run/credentials/../lindmd", "/run/credentials/", "/run/credentials\x00"} {
		if err := (&Document{}).UseIntegrationEncryptionKeyCredential("integrations-key", directory); err == nil {
			t.Fatalf("accepted invalid credentials directory %q", directory)
		}
	}
}

func TestIntegrationCredentialDoesNotChangeOptionalOrMigrationReads(t *testing.T) {
	base := databaseFixture(t)
	writeCertificate(t, base, "root", true, nil, nil)
	writeCertificate(t, base, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	document := &Document{base: base, Proto: &configv1.ServerConfig{Database: &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("database-url"), MaxConnections: 2}}}
	t.Setenv("CREDENTIALS_DIRECTORY", "/missing/credentials")
	if key, err := document.integrationEncryptionKey(); err != nil || key != nil {
		t.Fatal("unconfigured custom deployment no longer has optional integrations")
	}
	document.Proto.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: "missing-persistent-key"}
	if _, err := document.integrationEncryptionKey(); err == nil {
		t.Fatal("ambient credentials directory selected a credential")
	}
	if err := document.UseIntegrationEncryptionKeyCredential("integrations-key", "/missing/credentials"); err != nil {
		t.Fatal(err)
	}
	if _, err := document.MigrationDatabase(); err != nil {
		t.Fatalf("migration read an unnecessary integration secret: %v", err)
	}
}
