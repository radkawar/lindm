// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"archive/tar"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func rootRestoreDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root publication custody requires native root lane")
	}
	directory, err := os.MkdirTemp("/run", "lindmd-restore-publication-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return directory
}

func restoreConfigFixture(urlFile string, migration bool) *configv1.ServerConfig {
	cfg := &configv1.ServerConfig{
		DeploymentId:    "a9dff5b8-966d-4bbd-a568-b613bc0d056e",
		PublicUrl:       "https://admin.example.invalid",
		DevicePublicUrl: proto.String("https://devices.example.invalid"),
		AdminListener:   &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
		DeviceListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445},
		Database:        &configv1.DatabaseConfig{UrlFile: urlFile, MaxConnections: 4},
		Tls:             &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:        &configv1.DeviceCAConfig{CertificateFile: "device.crt", PrivateKeyFile: "device.key"},
		Authentication:  &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}},
	}
	if migration {
		cfg.Database.MigrationUrlFile = proto.String(urlFile)
	}
	return cfg
}

func writeRestoreFixture(t *testing.T, path string, data []byte, uid, gid int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
}

func marshalRestoreFixture(t *testing.T, cfg *configv1.ServerConfig) []byte {
	t.Helper()
	data, err := protojson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertRestoreCustody(t *testing.T, path string, uid, gid uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("incorrect restored resource custody: %s", path)
	}
}

func TestRestorePublicationPreservesFreshStableRootDatabaseURLs(t *testing.T) {
	directory := rootRestoreDirectory(t)
	runtimeConfig := filepath.Join(directory, "server.json")
	migrationConfig := filepath.Join(directory, "migrate", "server.json")
	runtimeURL := filepath.Join(directory, "database-url")
	migrationURL := filepath.Join(directory, "migrate", "database-url")
	// Distinct fresh local role IDs deliberately differ from the source archive's
	// root-owned config metadata. No account lookup may replace this captured identity.
	const runtimeUID, migrationUID = 61001, 61002
	for _, role := range []struct {
		path      string
		migration bool
		uid       int
	}{
		{path: runtimeConfig, uid: runtimeUID},
		{path: migrationConfig, migration: true, uid: migrationUID},
	} {
		cfg := restoreConfigFixture("database-url", role.migration)
		cfg.DeploymentId = "6292851e-a78e-4efe-9b2c-e48e9546fd30"
		writeRestoreFixture(t, role.path, marshalRestoreFixture(t, cfg), role.uid, role.uid)
		base := filepath.Dir(role.path)
		for _, name := range []string{"database-ca.crt", "database-client.crt", "database-client.key"} {
			writeRestoreFixture(t, filepath.Join(base, name), []byte("fresh target "+name), role.uid, role.uid)
		}
		connection := "postgresql://fresh:fresh-password@fresh.invalid/fresh?sslmode=verify-full&sslrootcert=database-ca.crt&sslcert=database-client.crt&sslkey=database-client.key"
		writeRestoreFixture(t, filepath.Join(base, "database-url"), []byte(connection), 0, 0)
	}

	// Exercise the extracted, digest-checked inventory and the exact filesystem
	// publication function called by publishRecovery, not preserveTargetDatabases
	// in isolation. TLS bytes here test custody/copying, not certificate validity.
	oldRuntimeURL := filepath.Join(directory, "source-runtime-url")
	oldMigrationURL := filepath.Join(directory, "migrate", "source-migration-url")
	source := restoreConfigFixture(oldRuntimeURL, false)
	migrationSource := restoreConfigFixture(oldMigrationURL, true)
	oldConnection := []byte("postgresql://source:source-password@source.invalid/source?sslmode=verify-full&sslrootcert=database-ca.crt&sslcert=database-client.crt&sslkey=database-client.key")
	files := map[string][]byte{
		runtimeConfig:   marshalRestoreFixture(t, source),
		migrationConfig: marshalRestoreFixture(t, migrationSource),
		oldRuntimeURL:   oldConnection,
		oldMigrationURL: oldConnection,
		// A signed inventory collision cannot substitute the source URL or its owner.
		runtimeURL:   oldConnection,
		migrationURL: oldConnection,
	}
	for _, base := range []string{directory, filepath.Join(directory, "migrate")} {
		for _, name := range []string{"database-ca.crt", "database-client.crt", "database-client.key", "server.crt", "server.key", "device.crt", "device.key"} {
			files[filepath.Join(base, name)] = []byte("source archive " + name)
		}
	}
	var paths []string
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	dump := []byte("database archive parser is covered by the restore drill")
	dumpHash := sha256.Sum256(dump)
	manifest := archiveManifest{
		Format: 1, CapturedAt: time.Now().UTC(), Version: "0.1.1",
		DeploymentID: source.GetDeploymentId(), PublicURL: source.GetPublicUrl(), DevicePublicURL: source.GetDevicePublicUrl(),
		ConfigPath: runtimeConfig, DatabaseSHA256: hex.EncodeToString(dumpHash[:]),
		SchemaMinimumRuntime: 51, SchemaVersions: []int64{51},
	}
	headers := []*tar.Header{{Name: "database.dump", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(dump))}}
	bodies := [][]byte{dump}
	for _, path := range paths {
		data := files[path]
		digest := sha256.Sum256(data)
		entry := archiveFile{Path: path, SHA256: hex.EncodeToString(digest[:]), Owner: "root", Group: "root", Mode: 0600, Size: int64(len(data))}
		if path == runtimeURL || path == migrationURL || path == oldRuntimeURL || path == oldMigrationURL {
			// Numeric ownership from another host is neither an account name nor
			// authority to publish a password readable by a service role.
			entry.Owner, entry.Group, entry.Mode = "61003", "61003", 0644
		}
		manifest.Files = append(manifest.Files, entry)
		headers = append(headers, &tar.Header{Name: "files/" + strings.TrimPrefix(path, "/"), Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(data))})
		bodies = append(bodies, data)
	}
	archiveDirectory := filepath.Join(directory, "archive")
	if err := os.Mkdir(archiveDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	extracted, err := extractArchive(bytes.NewReader(rawArchive(t, manifest, headers, bodies)), archiveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _, err := archivedConfiguration(extracted, archiveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	migrationTarget, migrationCleanup, err := stageDatabase(migrationConfig, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := migrationCleanup(); err != nil {
			t.Error(err)
		}
	})
	runtimeTarget, runtimeCleanup, err := stageDatabase(runtimeConfig, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtimeCleanup(); err != nil {
			t.Error(err)
		}
	})
	if err := publishRestoredFiles(extracted, inventory, migrationTarget, runtimeTarget); err != nil {
		t.Fatal(err)
	}
	for _, role := range []struct {
		configPath, urlPath string
		migration           bool
		uid                 uint32
	}{
		{configPath: runtimeConfig, urlPath: runtimeURL, uid: runtimeUID},
		{configPath: migrationConfig, urlPath: migrationURL, migration: true, uid: migrationUID},
	} {
		assertRestoreCustody(t, role.urlPath, 0, 0)
		assertRestoreCustody(t, role.configPath, role.uid, role.uid)
		data, err := os.ReadFile(role.urlPath)
		if err != nil {
			t.Fatal(err)
		}
		u, err := databaseURL(string(data))
		clear(data)
		if err != nil {
			t.Fatal(err)
		}
		password, _ := u.User.Password()
		if u.User.Username() != "fresh" || password != "fresh-password" {
			t.Fatal("source credentials replaced the preserved fresh target URL")
		}
		for _, resource := range []struct{ option, name string }{
			{option: "sslrootcert", name: "database-ca.crt"},
			{option: "sslcert", name: "database-client.crt"},
			{option: "sslkey", name: "database-client.key"},
		} {
			path := filepath.Join(filepath.Dir(role.configPath), "database-restored", resource.option)
			if u.Query().Get(resource.option) != path {
				t.Fatal("fresh target database TLS reference was not rewritten")
			}
			assertRestoreCustody(t, path, role.uid, role.uid)
			content, err := os.ReadFile(path)
			if err != nil || string(content) != "fresh target "+resource.name {
				t.Fatal("source publication overwrote fresh target database TLS")
			}
			clear(content)
		}
		data, err = os.ReadFile(role.configPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg := new(configv1.ServerConfig)
		if err := protojson.Unmarshal(data, cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.GetDeploymentId() != source.GetDeploymentId() || cfg.GetDatabase().GetUrlFile() != role.urlPath {
			t.Fatal("restored config lost source authority or original target URL destination")
		}
		if (role.migration && cfg.GetDatabase().GetMigrationUrlFile() != role.urlPath) || (!role.migration && cfg.GetDatabase().GetMigrationUrlFile() != "") {
			t.Fatal("restored config lost database role separation")
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(role.configPath), "database-restored", "database-url")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a role-owned at-rest URL was published in database-restored")
		}
	}
	for _, path := range []string{oldRuntimeURL, oldMigrationURL} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("source archive database password was published")
		}
	}
}

func TestBackupDatabaseURLsRequireRootPrivateCustody(t *testing.T) {
	directory := rootRestoreDirectory(t)
	owner, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(owner.Gid)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		uid, gid int
		mode     os.FileMode
		accepted bool
	}{
		{name: "root private", mode: 0600, accepted: true},
		{name: "service owner", uid: uid, gid: gid, mode: 0600},
		{name: "service group", gid: gid, mode: 0600},
		{name: "group readable", mode: 0640},
		{name: "public readable", mode: 0644},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-"))
			configPath, urlPath := filepath.Join(base, "server.json"), filepath.Join(base, "database-url")
			writeRestoreFixture(t, configPath, marshalRestoreFixture(t, restoreConfigFixture("database-url", false)), uid, gid)
			writeRestoreFixture(t, urlPath, []byte("postgresql://fresh:private@fresh.invalid/fresh?sslmode=verify-full&sslrootcert=system"), test.uid, test.gid)
			if err := os.Chmod(urlPath, test.mode); err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(base, "stage")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			r, err := newResources(configPath, stage)
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.database("database-url")
			if !test.accepted {
				if err == nil || !strings.Contains(err.Error(), "root_private_database_credential_required") {
					t.Fatalf("unsafe database credential admitted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.copy(urlPath); err != nil {
				t.Fatal(err)
			}
			dump := filepath.Join(base, "database.dump")
			writeRestoreFixture(t, dump, []byte("database archive fixture"), 0, 0)
			manifest, err := r.manifest(configPath, dump)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, entry := range manifest.Files {
				if entry.Path == urlPath {
					found = true
					if entry.Owner != "root" || entry.Group != "root" || entry.Mode != 0600 {
						t.Fatal("backup inventory lost root-only URL custody")
					}
				}
			}
			if !found {
				t.Fatal("backup inventory omitted the database URL")
			}
		})
	}
}
