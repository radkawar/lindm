// SPDX-License-Identifier: Apache-2.0

package install

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func rootDatabaseFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("installation ownership policy requires root")
	}
	dir, err := os.MkdirTemp("/run", "lindm-database-custody-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func assertDatabaseFileCustody(t *testing.T, path string, uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("incorrect database file custody for %s: %v", filepath.Base(path), info)
	}
}

func TestGeneratedDatabaseURLRemainsRootPrivateAndCreateOnly(t *testing.T) {
	path := filepath.Join(rootDatabaseFixture(t), "database-url")
	content := []byte("postgresql://runtime:password@localhost/lindm?sslmode=verify-full\n")
	if err := newDatabaseURL(path, content); err != nil {
		t.Fatal(err)
	}
	assertDatabaseFileCustody(t, path, 0, 0)
	if err := newDatabaseURL(path, []byte("replacement")); err == nil {
		t.Fatal("existing database credential was replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(content) {
		t.Fatal("create-only refusal changed the original URL")
	}
}

func TestExternalDatabaseURLRootCustodyKeepsRoleOwnedTLS(t *testing.T) {
	root := rootDatabaseFixture(t)
	for _, name := range []string{"root.crt", "client.crt", "client.key"} {
		if err := newFile(filepath.Join(root, name), []byte("explicit database TLS material"), 0, 0, 0600); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(root, "source-url")
	if err := newDatabaseURL(source, []byte("postgresql://external:password@database/lindm?sslmode=verify-full&sslrootcert=root.crt&sslcert=client.crt&sslkey=client.key")); err != nil {
		t.Fatal(err)
	}
	for _, role := range []struct {
		name string
		id   int
	}{{"runtime", 65534}, {"migrator", 65533}} {
		t.Run(role.name, func(t *testing.T) {
			destination := filepath.Join(root, role.name)
			if err := directory(destination, 0, 0, 0755); err != nil {
				t.Fatal(err)
			}
			if err := externalDatabaseCredential(source, destination, role.id, role.id); err != nil {
				t.Fatal(err)
			}
			urlPath := filepath.Join(destination, "database-url")
			assertDatabaseFileCustody(t, urlPath, 0, 0)
			data, err := os.ReadFile(urlPath)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			options := parsed.Query()
			for option, name := range map[string]string{"sslrootcert": "external-database-ca.crt", "sslcert": "external-database-client.crt", "sslkey": "external-database-client.key"} {
				path := filepath.Join(destination, name)
				assertDatabaseFileCustody(t, path, uint32(role.id), uint32(role.id))
				if options.Get(option) != path {
					t.Fatal("URL did not retain its dedicated role TLS resource")
				}
			}
		})
	}
}
