package devlab

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

const fixtureVersion = 1

type manifest struct {
	Version   int               `json:"version"`
	Directory string            `json:"directory"`
	Files     map[string]string `json:"files"`
}

// FixturePath returns the sole directory managed by the local harness.
func FixturePath(repoRoot string) string { return filepath.Join(repoRoot, ".cache", "dev") }

func protected(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("%s must be a non-symlink %s", path, map[bool]string{true: "directory", false: "regular file"}[directory])
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be owned by current user with no group/other permissions", path)
	}
	if !directory && info.Size() > 1<<20 {
		return fmt.Errorf("%s exceeds fixture file size limit", path)
	}
	return nil
}

func initialize(root string) (err error) {
	dir := FixturePath(root)
	if _, err := os.Lstat(dir); err == nil {
		return validateFixture(dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// All credentials are committed together; failures never change live files.
	tmp, err := os.MkdirTemp(filepath.Dir(dir), ".dev-new-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()
	files, err := certificateFiles()
	if err != nil {
		return err
	}
	secrets := make(map[string]string)
	for _, name := range []string{"postgres-password", "runtime-password", "migrator-password", "console-secret", "directory-secret", "lab-admin-secret", "owner-password", "administrator-password"} {
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return err
		}
		secrets[name] = base64.RawURLEncoding.EncodeToString(bytes[:])
		files[name] = []byte(secrets[name])
	}
	dsn := func(role, password string) []byte {
		u := url.URL{Scheme: "postgresql", User: url.UserPassword(role, password), Host: "localhost:15432", Path: "/lindm"}
		q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {filepath.Join(dir, "transport-ca.crt")}}
		u.RawQuery = q.Encode()
		return []byte(u.String())
	}
	files["database-url"] = dsn("lindm_runtime", secrets["runtime-password"])
	files["migration-database-url"] = dsn("lindm_migrator", secrets["migrator-password"])
	files["database-init.sql"] = []byte(fmt.Sprintf(`-- Only cryptographically generated URL-safe passwords are interpolated.
CREATE ROLE lindm_migrator LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE lindm_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER DATABASE lindm OWNER TO lindm_migrator;
REVOKE ALL ON DATABASE lindm FROM PUBLIC;
GRANT CONNECT ON DATABASE lindm TO lindm_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO lindm_migrator;
GRANT USAGE ON SCHEMA public TO lindm_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lindm_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO lindm_runtime;
`, secrets["migrator-password"], secrets["runtime-password"]))
	files["realm.json"], err = realmFile(secrets)
	if err != nil {
		return err
	}
	cfg := &configv1.ServerConfig{
		DeploymentId: uuid.NewString(), PublicUrl: "https://localhost:18444",
		AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
		DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445},
		Database:       &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("migration-database-url"), MaxConnections: 16},
		Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device-ca.crt", PrivateKeyFile: "device-ca.key"},
		Oidc:           &configv1.OIDCConfig{Issuer: issuer, ClientId: "lindm-console", ClientSecretFile: "console-secret", DirectoryClientId: "lindm-directory", DirectoryClientSecretFile: "directory-secret", AdministratorGroups: []string{"/mdm-admins"}},
		TrustedCaFile:  "transport-ca.crt",
	}
	files["server.json"], err = (protojson.MarshalOptions{Indent: "  "}).Marshal(cfg)
	if err != nil {
		return err
	}
	m := manifest{Version: fixtureVersion, Directory: dir, Files: make(map[string]string)}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0600); err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		m.Files[name] = hex.EncodeToString(digest[:])
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, dir)
}

func validateFixture(dir string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	if m.Version != fixtureVersion || m.Directory != dir {
		return fmt.Errorf("fixture version or absolute directory changed; preserve its data or explicitly reset -confirm-delete before regenerating")
	}
	for _, name := range []string{"transport-ca.crt", "transport-ca.key", "device-ca.crt", "device-ca.key", "server.crt", "server.key", "postgres-password", "runtime-password", "migrator-password", "console-secret", "directory-secret", "lab-admin-secret", "owner-password", "administrator-password", "database-url", "migration-database-url", "database-init.sql", "realm.json", "server.json"} {
		path := filepath.Join(dir, name)
		if err := protected(path, false); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if m.Files[name] != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("fixture file %s changed; refusing to overwrite credentials: restore it or explicitly reset -confirm-delete (destroys lab data)", path)
		}
	}
	return validateCertificates(dir)
}

func readManifest(dir string) (*manifest, error) {
	if err := protected(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "manifest.json")
	if err := protected(path, false); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
