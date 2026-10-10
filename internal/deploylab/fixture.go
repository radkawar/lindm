package deploylab

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

// RestrictRuntimeMigrationMetadataSQL removes default DML/sequence grants from
// Goose's bookkeeping after explicit migration in either isolated deployment
// fixture. Runtime startup retains SELECT but cannot forge schema history.
const RestrictRuntimeMigrationMetadataSQL = `REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.goose_db_version FROM lindm_runtime;
DO $$ DECLARE sequence_name text := pg_get_serial_sequence('public.goose_db_version', 'id');
BEGIN IF sequence_name IS NOT NULL THEN
EXECUTE 'REVOKE ALL ON SEQUENCE ' || sequence_name || ' FROM lindm_runtime';
END IF; END $$;`

// writeFixture creates only new files beneath the caller's private temporary
// directory. Roles, grants and protobuf configuration follow devlab's fixture;
// transport identities, credentials and database storage are entirely separate.
func writeFixture(dir string, adminPort, uid, gid int) ([]byte, error) {
	files, err := CertificateFiles()
	if err != nil {
		return nil, err
	}
	secrets := make(map[string]string)
	for _, name := range []string{"postgres-password", "runtime-password", "migrator-password"} {
		var value [32]byte
		if _, err := rand.Read(value[:]); err != nil {
			return nil, err
		}
		secrets[name] = base64.RawURLEncoding.EncodeToString(value[:])
	}
	files["postgres-password"] = []byte(secrets["postgres-password"])
	dsn := func(role, password string) []byte {
		u := url.URL{Scheme: "postgresql", User: url.UserPassword(role, password), Host: "postgres:5432", Path: "/lindm"}
		u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"/etc/lindm/transport-ca.crt"}}.Encode()
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
	cfg := &configv1.ServerConfig{
		DeploymentId: uuid.NewString(), PublicUrl: fmt.Sprintf("https://localhost:%d", adminPort),
		AdminListener:        &configv1.ListenerConfig{Address: "0.0.0.0", Port: 18444},
		DeviceListener:       &configv1.ListenerConfig{Address: "0.0.0.0", Port: 18445},
		Database:             &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 16},
		Tls:                  &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		DeviceCa:             &configv1.DeviceCAConfig{CertificateFile: "device-ca.crt", PrivateKeyFile: "device-ca.key"},
		Authentication:       &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}},
		TrustedCaFile:        "transport-ca.crt",
		InventoryBudgetBytes: proto.Uint64(10 << 30),
	}
	marshal := protojson.MarshalOptions{Indent: "  "}
	files["server.json"], err = marshal.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	// migrate resolves only its own URL/trust root, not any runtime keys. The
	// full protobuf document is still validated by the normal strict loader.
	cfg.Database.MigrationUrlFile = proto.String("migration-database-url")
	files["migrate.json"], err = marshal.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, fmt.Errorf("write deployment fixture: %w", err)
		}
		// Root-operated labs still run lindmd as nonroot. Nonroot labs use
		// their own UID/GID so the unchanged 0600 host files remain readable.
		if os.Geteuid() == 0 {
			if err := os.Chown(path, uid, gid); err != nil {
				return nil, fmt.Errorf("own deployment fixture: %w", err)
			}
		}
	}
	return files["transport-ca.crt"], nil
}
