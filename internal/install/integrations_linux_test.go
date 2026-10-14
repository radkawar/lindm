// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestIntegrationKeyGenerationIsRootPrivateAndCreateOnly(t *testing.T) {
	root := rootDatabaseFixture(t)
	path := filepath.Join(root, "integrations.key")
	if err := ensureIntegrationKey(path, ""); err != nil {
		t.Fatal(err)
	}
	assertDatabaseFileCustody(t, path, 0, 0)
	key, err := readIntegrationSource(path)
	if err != nil || len(key) != 32 {
		t.Fatalf("generated source is not an exact raw key: %v", err)
	}
	defer clear(key)
	if err := ensureIntegrationKey(path, ""); err != nil {
		t.Fatal(err)
	}
	if err := ensureIntegrationKey(path, path); err != nil {
		t.Fatal(err)
	}
	if err := atomicNativeFile(path, bytes.Repeat([]byte{0x71}, 32), 0, 0, nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("create-only collision was not refused: %v", err)
	}
	after, err := readIntegrationSource(path)
	defer clear(after)
	if err != nil || !bytes.Equal(key, after) {
		t.Fatal("existing integration key was replaced")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("atomic publication left temporary secret files")
	}
}

func TestIntegrationKeyRejectsUnsafeExistingSourcesWithoutRekey(t *testing.T) {
	for _, failure := range []string{"short", "long", "public", "group writable", "owner executable", "foreign owner", "foreign group", "symlink", "hardlink", "fifo", "directory", "unsafe ancestor", "symlink ancestor"} {
		t.Run(failure, func(t *testing.T) {
			root := rootDatabaseFixture(t)
			path := filepath.Join(root, "source.key")
			original := bytes.Repeat([]byte{0x63}, 32)
			if err := newFile(path, original, 0, 0, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch failure {
			case "short", "long":
				length := 31
				if failure == "long" {
					length = 33
				}
				err = os.Truncate(path, int64(length))
			case "public":
				err = os.Chmod(path, 0644)
			case "group writable":
				err = os.Chmod(path, 0620)
			case "owner executable":
				err = os.Chmod(path, 0700)
			case "foreign owner":
				err = os.Chown(path, 65534, 65534)
			case "foreign group":
				err = os.Chown(path, 0, 65534)
			case "hardlink":
				err = os.Link(path, filepath.Join(root, "alias"))
			case "symlink", "fifo", "directory":
				err = os.Remove(path)
				if err == nil {
					switch failure {
					case "symlink":
						target := filepath.Join(root, "original.key")
						err = newFile(target, original, 0, 0, 0600)
						if err == nil {
							err = os.Symlink(target, path)
						}
					case "fifo":
						err = unix.Mkfifo(path, 0600)
					case "directory":
						err = os.Mkdir(path, 0700)
					}
				}
			case "unsafe ancestor":
				err = os.Chmod(root, 0777)
			case "symlink ancestor":
				link := filepath.Join(rootDatabaseFixture(t), "linked")
				err = os.Symlink(root, link)
				path = filepath.Join(link, "source.key")
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := ensureIntegrationKey(path, ""); err == nil {
				t.Fatal("unsafe existing source was accepted or rekeyed")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("unsafe-source refusal mutated the source")
			}
			destination := filepath.Join(rootDatabaseFixture(t), "canonical.key")
			if err := ensureIntegrationKey(destination, path); err == nil {
				t.Fatal("invalid configured source was replaced by a generated key")
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid configured source caused a replacement key to be published")
			}
		})
	}
}

func nativeIntegrationConfigFixture(t *testing.T, root string, integration *configv1.IntegrationsConfig) (string, string, *configv1.ServerConfig) {
	t.Helper()
	cfg := &configv1.ServerConfig{
		DeploymentId: "a9dff5b8-966d-4bbd-a568-b613bc0d056e", PublicUrl: "https://localhost:18444",
		AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
		DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445},
		Database:       &configv1.DatabaseConfig{UrlFile: "/etc/lindm/database-url", MaxConnections: 2},
		Tls:            &configv1.TLSConfig{CertificateFile: "/etc/lindm/server.crt", PrivateKeyFile: "/etc/lindm/server.key"},
		DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "/etc/lindm/device-ca.crt", PrivateKeyFile: "/etc/lindm/device-ca.key"},
		Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}},
		Integrations:   integration,
	}
	runtimePath := filepath.Join(root, "server.json")
	migrationPath := filepath.Join(root, "migration.json")
	if err := writeConfig(runtimePath, cfg, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	migration := proto.CloneOf(cfg)
	migration.Database.UrlFile = "/etc/lindm/migrate/database-url"
	migration.Database.MigrationUrlFile = proto.String("/etc/lindm/migrate/database-url")
	if err := writeConfig(migrationPath, migration, 65533, 65533); err != nil {
		t.Fatal(err)
	}
	return runtimePath, migrationPath, cfg
}

func TestManagedUpgradeEnablesAndPreservesExactIntegrationKey(t *testing.T) {
	for _, prior := range []string{"absent", "canonical", "unconfigured existing key", "relative configured source"} {
		t.Run(prior, func(t *testing.T) {
			root := rootDatabaseFixture(t)
			keyPath := filepath.Join(root, "integrations.key")
			var integration *configv1.IntegrationsConfig
			var expected []byte
			if prior != "absent" {
				source := keyPath
				reference := source
				if prior == "relative configured source" {
					source = filepath.Join(root, "existing.key")
					reference = "existing.key"
				}
				expected = bytes.Repeat([]byte{0x53}, 32)
				if err := newFile(source, expected, 0, 0, 0600); err != nil {
					t.Fatal(err)
				}
				if prior != "unconfigured existing key" {
					integration = &configv1.IntegrationsConfig{EncryptionKeyFile: reference}
				}
			}
			runtimePath, migrationPath, initial := nativeIntegrationConfigFixture(t, root, integration)
			if err := enableNativeIntegrationsAt(runtimePath, migrationPath, keyPath, 65534, 65533); err != nil {
				t.Fatal(err)
			}
			key, err := readIntegrationSource(keyPath)
			defer clear(key)
			if err != nil || (expected != nil && !bytes.Equal(key, expected)) {
				t.Fatal("managed upgrade lost the configured key bytes")
			}
			assertDatabaseFileCustody(t, keyPath, 0, 0)
			assertDatabaseFileCustody(t, runtimePath, 65534, 65534)
			assertDatabaseFileCustody(t, migrationPath, 65533, 65533)
			runtimeConfig, _, err := loadNativeConfig(runtimePath, 65534)
			if err != nil {
				t.Fatal(err)
			}
			initial.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: keyPath}
			if !proto.Equal(initial, runtimeConfig) {
				t.Fatal("upgrade changed unrelated configuration or lost the persistent key reference")
			}
			migrationConfig, _, err := loadNativeConfig(migrationPath, 65533)
			if err != nil || migrationConfig.Integrations != nil || migrationConfig.GetDatabase().GetUrlFile() != "/etc/lindm/migrate/database-url" {
				t.Fatal("migration retained unnecessary integration secret access or lost its database identity")
			}
			if err := enableNativeIntegrationsAt(runtimePath, migrationPath, keyPath, 65534, 65533); err != nil {
				t.Fatal(err)
			}
			after, err := readIntegrationSource(keyPath)
			defer clear(after)
			if err != nil || !bytes.Equal(key, after) {
				t.Fatal("repeat managed upgrade rekeyed the deployment")
			}
		})
	}
}

func TestManagedUpgradeRefusesLostConfiguredKeyAndConflictingCanonicalKey(t *testing.T) {
	for _, failure := range []string{"missing", "truncated", "conflicting canonical"} {
		t.Run(failure, func(t *testing.T) {
			root := rootDatabaseFixture(t)
			source := filepath.Join(root, "existing.key")
			canonical := filepath.Join(root, "integrations.key")
			if failure != "missing" {
				length := 32
				if failure == "truncated" {
					length = 31
				}
				if err := newFile(source, bytes.Repeat([]byte{0x54}, length), 0, 0, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "conflicting canonical" {
				if err := newFile(canonical, bytes.Repeat([]byte{0x55}, 32), 0, 0, 0600); err != nil {
					t.Fatal(err)
				}
			}
			runtimePath, migrationPath, _ := nativeIntegrationConfigFixture(t, root, &configv1.IntegrationsConfig{EncryptionKeyFile: source})
			before, err := os.ReadFile(runtimePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := enableNativeIntegrationsAt(runtimePath, migrationPath, canonical, 65534, 65533); err == nil {
				t.Fatal("configured-key loss/conflict was silently rekeyed")
			}
			after, err := os.ReadFile(runtimePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("key refusal changed managed configuration")
			}
			if failure != "conflicting canonical" {
				if _, err := os.Lstat(canonical); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("lost configured source caused fresh key generation")
				}
			}
		})
	}
}
