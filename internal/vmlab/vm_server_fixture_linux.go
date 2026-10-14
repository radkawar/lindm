// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/deploylab"
	"lindm/internal/packaging"
)

func serverAPT(ctx context.Context, vm *guestVM, repo *packaging.APTRepository, artifacts []packaging.Artifact) (_ *guestForward, _ *aptPublicServer, err error) {
	names := []string{"dists/stable/InRelease", "dists/stable/Release", "dists/stable/Release.gpg", "dists/stable/main/binary-amd64/Packages"}
	for _, artifact := range artifacts {
		names = append(names, "pool/main/l/lindmd/"+filepath.Base(artifact.Path))
	}
	public, err := newAPTPublicServer(repo.Root, names)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, public.Close())
		}
	}()
	forward, err := newGuestForward(ctx, vm, "127.0.0.1:0", public.listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, forward.Close())
		}
	}()
	key, err := os.ReadFile(repo.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	if _, err := serverGuestCommand(ctx, vm, "pin APT signer", "cat > /usr/share/keyrings/lindmd-lab.gpg && chmod 0644 /usr/share/keyrings/lindmd-lab.gpg", bytes.NewReader(key)); err != nil {
		return nil, nil, err
	}
	source := "Types: deb\nURIs: http://" + forward.Addr() + "/\nSuites: stable\nComponents: main\nSigned-By: /usr/share/keyrings/lindmd-lab.gpg\n"
	if _, err := serverGuestCommand(ctx, vm, "configure signed APT source", "cat > /etc/apt/sources.list.d/lindmd-lab.sources", strings.NewReader(source)); err != nil {
		return nil, nil, err
	}
	return forward, public, nil
}

func prepareServerGuest(ctx context.Context, vm *guestVM) error {
	files, err := deploylab.CertificateFiles()
	if err != nil {
		return err
	}
	runtimePassword, migratorPassword := rand.Text(), rand.Text()
	dsn := func(role, password, root string) []byte {
		u := &url.URL{Scheme: "postgresql", User: url.UserPassword(role, password), Host: "localhost:5432", Path: "/lindm"}
		u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {root}}.Encode()
		return []byte(u.String())
	}
	files["database-url"] = dsn("lindm_runtime", runtimePassword, "/etc/lindm/transport-ca.crt")
	cfg := &configv1.ServerConfig{DeploymentId: uuid.NewString(), PublicUrl: "https://localhost:18444", AdminListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444}, DeviceListener: &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18445}, Database: &configv1.DatabaseConfig{UrlFile: "database-url", MaxConnections: 16}, Tls: &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"}, DeviceCa: &configv1.DeviceCAConfig{CertificateFile: "device-ca.crt", PrivateKeyFile: "device-ca.key"}, Authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}}, TrustedCaFile: "transport-ca.crt"}
	files["server.json"], err = (protojson.MarshalOptions{Indent: "  "}).Marshal(cfg)
	if err != nil {
		return err
	}
	migration := proto.CloneOf(cfg)
	migration.Database.MigrationUrlFile = proto.String("database-url")
	migrationJSON, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(migration)
	if err != nil {
		return err
	}
	if _, err := serverGuestCommand(ctx, vm, "prepare protected directories", "install -d -m 0755 /etc/lindm; install -d -o root -g lindmd-migrate -m 0750 /etc/lindm/migrate; install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/lindm-tls", nil); err != nil {
		return err
	}
	upload := func(path, owner string, data []byte) error {
		_, err := serverGuestCommand(ctx, vm, "upload protected server resource", "umask 077; cat > "+nativeQuote(path)+"; chown "+nativeQuote(owner)+" "+nativeQuote(path)+"; chmod 0600 "+nativeQuote(path), bytes.NewReader(data))
		return err
	}
	for name, data := range files {
		if strings.HasPrefix(name, "postgres.") {
			if err := upload("/var/lib/postgresql/lindm-tls/"+name, "postgres:postgres", data); err != nil {
				return err
			}
		} else if err := upload("/etc/lindm/"+name, "lindmd:lindmd", data); err != nil {
			return err
		}
	}
	if err := upload("/etc/lindm/migrate/server.json", "lindmd-migrate:lindmd-migrate", migrationJSON); err != nil {
		return err
	}
	if err := upload("/etc/lindm/migrate/database-url", "lindmd-migrate:lindmd-migrate", dsn("lindm_migrator", migratorPassword, "/etc/lindm/migrate/transport-ca.crt")); err != nil {
		return err
	}
	if err := upload("/etc/lindm/migrate/transport-ca.crt", "lindmd-migrate:lindmd-migrate", files["transport-ca.crt"]); err != nil {
		return err
	}
	sql := fmt.Sprintf(`CREATE ROLE lindm_migrator LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE lindm_runtime LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE DATABASE lindm OWNER lindm_migrator;
\connect lindm
REVOKE ALL ON DATABASE lindm FROM PUBLIC;
GRANT CONNECT ON DATABASE lindm TO lindm_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO lindm_migrator;
GRANT USAGE ON SCHEMA public TO lindm_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lindm_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO lindm_runtime;
`, migratorPassword, runtimePassword)
	if _, err := serverGuestCommand(ctx, vm, "create isolated database roles", "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1", strings.NewReader(sql)); err != nil {
		return err
	}
	const configure = `conf=$(runuser -u postgres -- psql -X -At -c 'SHOW config_file')
hba=$(runuser -u postgres -- psql -X -At -c 'SHOW hba_file')
printf "\nssl=on\nssl_cert_file='/var/lib/postgresql/lindm-tls/postgres.crt'\nssl_key_file='/var/lib/postgresql/lindm-tls/postgres.key'\nssl_min_protocol_version='TLSv1.3'\n" >> "$conf"
printf 'local all postgres peer\nhostssl lindm lindm_runtime,lindm_migrator 127.0.0.1/32 scram-sha-256\nhostssl lindm lindm_runtime,lindm_migrator ::1/128 scram-sha-256\n' > "$hba"
systemctl restart postgresql
runuser -u lindmd -- /usr/bin/lindmd check-config -config /etc/lindm/server.json
`
	_, err = serverGuestCommand(ctx, vm, "configure verified PostgreSQL TLS", configure, nil)
	return err
}

func probeServerGuest(ctx context.Context, vm *guestVM) error {
	const command = `attempt=0
until test "$(curl --silent --show-error --cacert /etc/lindm/transport-ca.crt --max-time 3 -o /dev/null -w '%{http_code}' https://localhost:18444/readyz)" = 204; do
 attempt=$((attempt + 1)); test "$attempt" -lt 30; sleep 1
done
test "$(curl --silent --show-error --cacert /etc/lindm/transport-ca.crt --max-time 5 -o /dev/null -w '%{http_code}' https://localhost:18444/healthz)" = 204
test "$(curl --silent --show-error --cacert /etc/lindm/transport-ca.crt --max-time 5 -o /dev/null -w '%{http_code}' https://localhost:18444/)" = 200
curl --silent --show-error --cacert /etc/lindm/transport-ca.crt --max-time 5 https://localhost:18444/auth/options
test "$(curl --silent --show-error --cacert /etc/lindm/transport-ca.crt --max-time 5 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{}' https://localhost:18444/lindm.admin.v1.AdminService/ListDevices)" = 401
test "$(systemctl show lindmd.service -p User --value)" = lindmd
test "$(systemctl show lindmd.service -p CapabilityBoundingSet --value)" = ''
test "$(systemctl show lindmd.service -p NoNewPrivileges --value)" = yes
test "$(systemctl show lindmd.service -p ProtectSystem --value)" = strict
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
test "$(systemctl show lindmd.service -p MemorySwapMax --value)" = 0
test "$(systemctl show lindmd.service -p LimitCORE --value)" = 0
! runuser -u lindmd -- test -r /etc/lindm/migrate/database-url
test "$(runuser -u postgres -- psql -X -At -d lindm -c "SELECT has_schema_privilege('lindm_runtime','public','CREATE')")" = f
test "$(runuser -u postgres -- psql -X -At -d lindm -c "SELECT has_table_privilege('lindm_runtime','public.goose_db_version','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR coalesce(has_sequence_privilege('lindm_runtime',pg_get_serial_sequence('public.goose_db_version','id'),'USAGE,SELECT,UPDATE'),false)")" = f
`
	output, err := serverGuestCommand(ctx, vm, "verify TLS, public and protected surfaces", command, nil)
	if err != nil {
		return err
	}
	// Decode the generated public auth contract rather than matching JSON spelling.
	return checkServerLocalOptions(output)
}

func checkServerLocalOptions(data []byte) error {
	options := new(authv1.AuthenticationOptions)
	if err := protojson.Unmarshal(data, options); err != nil {
		return fmt.Errorf("decode auth options: %w", err)
	}
	if !options.GetLocalLogin() || options.GetExternalLogin() {
		return errors.New("server did not expose local-only authentication")
	}
	return nil
}

func installServerPostgres(ctx context.Context, vm *guestVM) error {
	// This runs before any secret is provisioned. Unlike later private SQL and
	// bootstrap operations, vendor-package diagnostics contain no lab secrets.
	const command = "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c 'apt-get update -q && apt-get install -q -y --no-install-recommends postgresql curl ca-certificates'"
	result, err := vm.runResult(ctx, command, nil, 1<<20, 10*time.Minute)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		log := new(vmLog)
		if _, err := log.Write(result.Stderr); err != nil {
			return err
		}
		return fmt.Errorf("install distribution PostgreSQL: guest exit %d: %s", result.ExitCode, log.diagnostic(vm.dir))
	}
	return nil
}
