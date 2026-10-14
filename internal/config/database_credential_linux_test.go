// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
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
	writeBrowserCertificate(t, base, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
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

func TestSystemdCredentialCanonicalServiceACL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real root-owned systemd ACL fixture requires root")
	}
	for _, mutation := range []string{"canonical", "ordinary group mode", "other user", "owning group", "other access", "write mask", "extra reader"} {
		t.Run(mutation, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "credential")
			want := []byte("private credential canary")
			if err := os.WriteFile(path, want, 0400); err != nil {
				t.Fatal(err)
			}
			fileACL := systemdACLFixture(4)
			directoryACL := systemdACLFixture(5)
			switch mutation {
			case "other user":
				binary.LittleEndian.PutUint32(fileACL[16:20], uint32(os.Geteuid())+1)
			case "owning group":
				binary.LittleEndian.PutUint16(fileACL[22:24], 4)
			case "other access":
				binary.LittleEndian.PutUint16(directoryACL[38:40], 5)
			case "write mask":
				binary.LittleEndian.PutUint16(fileACL[30:32], 6)
			case "extra reader":
				extra := make([]byte, len(fileACL)+8)
				copy(extra, fileACL[:20])
				binary.LittleEndian.PutUint16(extra[20:22], 2)
				binary.LittleEndian.PutUint16(extra[22:24], 4)
				binary.LittleEndian.PutUint32(extra[24:28], uint32(os.Geteuid())+1)
				copy(extra[28:], fileACL[20:])
				fileACL = extra
			}
			if mutation == "ordinary group mode" {
				if err := os.Chmod(path, 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(directory, 0550); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := unix.Setxattr(path, "system.posix_acl_access", fileACL, 0); err != nil {
					t.Fatal(err)
				}
				if err := unix.Setxattr(directory, "system.posix_acl_access", directoryACL, 0); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				if err := os.Chmod(directory, 0700); err != nil {
					t.Error(err)
				}
			})
			credential := &systemdCredential{directory: directory, name: "credential", kind: "database"}
			got, err := credential.read()
			defer clear(got)
			if mutation == "canonical" {
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("canonical systemd ACL rejected: %v", err)
				}
				file, err := os.Stat(path)
				if err != nil || file.Mode().Perm() != 0440 {
					t.Fatal("canonical file ACL mask fixture is not 0440")
				}
				dir, err := os.Stat(directory)
				if err != nil || dir.Mode().Perm() != 0550 {
					t.Fatal("canonical directory ACL mask fixture is not 0550")
				}
			} else if err == nil || len(got) != 0 {
				t.Fatal("broadened or absent credential ACL was accepted")
			}
		})
	}
}

func systemdACLFixture(permissions uint16) []byte {
	acl := make([]byte, 44)
	binary.LittleEndian.PutUint32(acl[:4], 2)
	for i, entry := range [5]struct {
		tag         uint16
		permissions uint16
		id          uint32
	}{
		{1, permissions, ^uint32(0)},
		{2, permissions, uint32(os.Geteuid())},
		{4, 0, ^uint32(0)},
		{16, permissions, ^uint32(0)},
		{32, 0, ^uint32(0)},
	} {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(acl[offset+2:offset+4], entry.permissions)
		binary.LittleEndian.PutUint32(acl[offset+4:offset+8], entry.id)
	}
	return acl
}
