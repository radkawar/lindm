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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func credentialDirectory(t *testing.T, connection []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "database-url"), connection, 0400); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDatabaseCredentialPreservesLoadedContractAndTLSBase(t *testing.T) {
	base := databaseFixture(t)
	writeCertificate(t, base, "root", true, nil, nil)
	writeCertificate(t, base, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	writeCertificate(t, base, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
	writeCertificate(t, base, "device", true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	cfg := executionSigningSchemaConfig()
	cfg.ExecutionBootstrap, cfg.ExecutionSigning = nil, nil
	cfg.Authentication = localAuthentication()
	cfg.Database.UrlFile = "/etc/lindm/database-url"
	cfg.Database.MigrationUrlFile = proto.String("/etc/lindm/migrate/database-url")
	cfg.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: "/etc/lindm/integrations.key"}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, base, "server.json", encoded)
	document, err := Load(filepath.Join(base, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	credential := credentialDirectory(t, []byte("postgresql://runtime:fresh-secret@localhost/lindm?sslmode=verify-full&sslrootcert=root.crt&sslcert=client.crt&sslkey=client.key"))
	key := bytes.Repeat([]byte{0x61}, 32)
	if err := os.WriteFile(filepath.Join(credential, "integrations-key"), key, 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(credential, 0700); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(credential, 0500); err != nil {
		t.Fatal(err)
	}
	if err := document.UseDatabaseURLCredential("database-url", credential); err != nil {
		t.Fatal(err)
	}
	if err := document.UseIntegrationEncryptionKeyCredential("integrations-key", credential); err != nil {
		t.Fatal(err)
	}
	resources, err := document.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	defer resources.HTTPClient.CloseIdleConnections()
	if !bytes.Equal(resources.IntegrationEncryptionKey, key) {
		t.Fatal("runtime did not receive the exact explicit integration credential")
	}
	for _, database := range []string{resources.Database.ConnConfig.User, resources.AdminDatabase.ConnConfig.User} {
		if database != "runtime" {
			t.Fatal("runtime pools did not use the explicit credential")
		}
	}
	if resources.Database.ConnConfig.Password != "fresh-secret" || resources.Database.ConnConfig.TLSConfig.RootCAs == nil || len(resources.Database.ConnConfig.TLSConfig.Certificates) != 1 {
		t.Fatal("credential or config-relative database TLS resources were lost")
	}
	if !proto.Equal(cfg, document.Proto) || !proto.Equal(cfg, resources.Proto) {
		t.Fatal("ephemeral credential changed the persistent contract")
	}
	after, err := protojson.Marshal(document.Proto)
	if err != nil || !bytes.Equal(encoded, after) {
		t.Fatal("ephemeral credential changed serialized config or its fingerprint input")
	}
	migration := credentialDirectory(t, []byte("postgresql://migrator:separate-secret@localhost/lindm?sslmode=verify-full&sslrootcert=root.crt"))
	if err := document.UseDatabaseURLCredential("database-url", migration); err != nil {
		t.Fatal(err)
	}
	migrationConfig, err := document.MigrationDatabase()
	if err != nil || migrationConfig.ConnConfig.User != "migrator" || migrationConfig.ConnConfig.Password != "separate-secret" || migrationConfig.MaxConns != 2 {
		t.Fatal("migration did not use its own explicit credential")
	}
}

func TestDatabaseCredentialFailsClosed(t *testing.T) {
	for _, name := range []string{"missing", "readable", "writable", "executable", "directory", "symlink", "hardlink", "fifo", "oversized", "malformed", "unsafe directory", "symlink directory", "foreign owner"} {
		t.Run(name, func(t *testing.T) {
			base := databaseFixture(t)
			// A valid persistent URL must never rescue an unsafe explicit credential.
			writeFixtureFile(t, base, "database-url", []byte("postgresql://persistent:old-secret@localhost/lindm?sslmode=verify-full"))
			credential := credentialDirectory(t, []byte("postgresql://runtime:new-secret@localhost/lindm?sslmode=verify-full"))
			path := filepath.Join(credential, "database-url")
			var err error
			switch name {
			case "missing", "directory", "symlink", "fifo":
				err = os.Remove(path)
				if err == nil {
					switch name {
					case "directory":
						err = os.Mkdir(path, 0700)
					case "symlink":
						err = os.Symlink(filepath.Join(base, "database-url"), path)
					case "fifo":
						err = unix.Mkfifo(path, 0600)
					}
				}
			case "readable":
				err = os.Chmod(path, 0444)
			case "writable":
				err = os.Chmod(path, 0620)
			case "executable":
				err = os.Chmod(path, 0700)
			case "hardlink":
				err = os.Link(path, filepath.Join(credential, "alias"))
			case "oversized", "malformed":
				err = os.Remove(path)
				if err == nil {
					data := []byte("malformed-secret-canary")
					if name == "oversized" {
						data = make([]byte, maxFileBytes+1)
					}
					err = os.WriteFile(path, data, 0400)
				}
			case "unsafe directory":
				err = os.Chmod(credential, 0755)
			case "symlink directory":
				link := filepath.Join(t.TempDir(), "credentials")
				err = os.Symlink(credential, link)
				credential = link
			case "foreign owner":
				if os.Geteuid() != 0 {
					t.Skip("foreign credential ownership requires root")
				}
				err = os.Chown(path, 65534, 65534)
			}
			if err != nil {
				t.Fatal(err)
			}
			document := &Document{base: base}
			if err := document.UseDatabaseURLCredential("database-url", credential); err != nil {
				t.Fatal(err)
			}
			if _, err := document.database("database-url"); err == nil || strings.Contains(err.Error(), "secret-canary") || strings.Contains(err.Error(), "old-secret") || strings.Contains(err.Error(), "new-secret") {
				t.Fatal("unsafe credential was accepted, fell back, or leaked")
			}
		})
	}
}

func TestDatabaseCredentialRejectsAmbiguousSelection(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../database-url", "/etc/lindm/database-url", "database/url", "database-url\x00", "database url", strings.Repeat("a", 256)} {
		if err := (&Document{}).UseDatabaseURLCredential(name, "/run/credentials/lindmd.service"); err == nil {
			t.Fatalf("accepted invalid credential name %q", name)
		}
	}
	for _, directory := range []string{"", ".", "/", "run/credentials", "/run/credentials/../lindmd", "/run/credentials/", "/run/credentials\x00"} {
		if err := (&Document{}).UseDatabaseURLCredential("database-url", directory); err == nil {
			t.Fatalf("accepted invalid credentials directory %q", directory)
		}
	}
}
