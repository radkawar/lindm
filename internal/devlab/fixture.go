package devlab

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"io"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/custody"
)

const fixtureVersion = 2

type manifest struct {
	Version   int               `json:"version"`
	Directory string            `json:"directory"`
	Files     map[string]string `json:"files"`
}

// FixturePath returns the sole directory managed by the local harness.
func FixturePath(repoRoot string) string { return filepath.Join(repoRoot, ".cache", "dev") }

// maxFixtureFile bounds every fixture file read.
const maxFixtureFile = 1 << 20

// readOwned reads a fixture file that custody.Owned admits, within maxFixtureFile.
func readOwned(path string) (_ []byte, err error) {
	if _, err := custody.Owned(path, false); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, maxFixtureFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFixtureFile {
		clear(data)
		return nil, fmt.Errorf("%s exceeds fixture file size limit", path)
	}
	return data, nil
}

func initialize(root, authentication string) (err error) {
	if authentication != "local" && authentication != "keycloak" {
		return errors.New("authentication must be local or keycloak")
	}
	dir := FixturePath(root)
	if _, err := os.Lstat(dir); err == nil {
		if err := validateFixture(dir); err != nil {
			return err
		}
		local, err := localFixture(dir)
		if err != nil {
			return err
		}
		if local != (authentication == "local") {
			return errors.New("fixture authentication mode differs; preserve it or explicitly reset -confirm-delete")
		}
		return nil
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
	secretNames := []string{"postgres-password", "runtime-password", "migrator-password"}
	if authentication == "keycloak" {
		secretNames = append(secretNames, "console-secret", "directory-secret", "lab-admin-secret", "owner-password", "administrator-password",
			"broker-directory-secret", "broker-admin-secret", "broker-upstream-directory-secret", "broker-upstream-admin-secret")
	}
	for _, name := range secretNames {
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return err
		}
		secrets[name] = base64.RawURLEncoding.EncodeToString(bytes[:])
		files[name] = []byte(secrets[name])
	}
	for name, data := range rotatedFixtureFiles(dir, secrets) {
		files[name] = data
	}
	if authentication == "keycloak" {
		files["realm.json"], err = realmFile(secrets)
		if err != nil {
			return err
		}
		brokerFiles, err := brokerRealmFiles(secrets)
		if err != nil {
			return err
		}
		for name, data := range brokerFiles {
			files[name] = data
		}
	}
	cfg := &configv1.ServerConfig{
		DeploymentId: uuid.NewString(), PublicUrl: "https://localhost:18444",
		AdminListener:  &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
		DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445},
		Database:       &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("migration-database-url"), MaxConnections: 16},
		Tls:            &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:       &configv1.DeviceCAConfig{CertificateFile: "device-ca.crt", PrivateKeyFile: "device-ca.key"},
		Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{
			Issuer: issuer, ClientId: "lindm-console", ClientSecretFile: "console-secret", DirectoryClientId: "lindm-directory", DirectoryClientSecretFile: "directory-secret",
		}}},
		Authorization:        &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "/mdm-admins", Role: "admin"}}},
		TrustedCaFile:        "transport-ca.crt",
		InventoryBudgetBytes: proto.Uint64(10 << 30),
	}
	if authentication == "local" {
		cfg.Authentication = &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}}
		cfg.Authorization = nil
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

// Both maintained development and dedicated load clusters use identical roles.
// Callers supply only cryptographically generated URL-safe passwords.
func databaseRoleSQL(migrator, runtime string) string {
	return fmt.Sprintf(`CREATE ROLE lindm_migrator LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE lindm_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
`, migrator, runtime)
}

func validateFixture(dir string) error {
	m, err := readManifest(dir)
	if err != nil {
		return err
	}
	if m.Version != fixtureVersion || m.Directory != dir {
		return fmt.Errorf("fixture version or absolute directory changed; preserve its data or explicitly reset -confirm-delete before regenerating")
	}
	local, err := localFixture(dir)
	if err != nil {
		return err
	}
	names := []string{"transport-ca.crt", "transport-ca.key", "device-ca.crt", "device-ca.key", "server.crt", "server.key", "postgres-password", "runtime-password", "migrator-password", "database-url", "migration-database-url", "database-init.sql", "server.json"}
	if !local {
		names = append(names, "console-secret", "directory-secret", "lab-admin-secret", "owner-password", "administrator-password", "realm.json",
			"broker-directory-secret", "broker-admin-secret", "broker-upstream-directory-secret", "broker-upstream-admin-secret", "broker-realm.json", "broker-upstream-realm.json")
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := readOwned(path)
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
	if _, err := custody.Owned(dir, true); err != nil {
		return nil, err
	}
	data, err := readOwned(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func localFixture(dir string) (bool, error) {
	document, err := config.Load(filepath.Join(dir, "server.json"))
	if err != nil {
		return false, err
	}
	return document.Proto.GetAuthentication().GetLocal() != nil, nil
}

func requireKeycloakFixture(dir string) error {
	local, err := localFixture(dir)
	if err != nil {
		return err
	}
	if local {
		return errors.New("this check requires the Keycloak development fixture")
	}
	return nil
}
