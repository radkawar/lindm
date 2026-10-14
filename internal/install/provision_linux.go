// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/platform"
	"lindm/internal/serverops"
)

func provision(ctx context.Context, o Options, release *platform.Release, custody *authorityCustody) error {
	uid, gid, err := account("lindmd")
	if err != nil {
		return err
	}
	muid, mgid, err := account("lindmd-migrate")
	if err != nil {
		return err
	}
	if uid == muid || gid == mgid {
		return errors.New("runtime and migrator identities must differ")
	}
	if err := directory("/etc/lindm/offline", 0, 0, 0700); err != nil {
		return err
	}
	if err := directory("/var/lib/lindmd-operations", 0, 0, 0755); err != nil {
		return err
	}
	if err := directory("/var/lib/lindmd-operations/setup", 0, 0, 0700); err != nil {
		return err
	}
	if err := directory("/var/backups/lindm", 0, 0, 0700); err != nil {
		return err
	}
	var pguid, pggid int
	if o.DatabaseURL == "" {
		pguid, pggid, err = account("postgres")
		if err != nil {
			return err
		}
		if err := directory("/etc/lindm/postgresql", 0, pggid, 0750); err != nil {
			return err
		}
	}
	deployment := uuid.NewString()
	if err := certificates(ctx, o, deployment, uid, gid, pguid, pggid, custody); err != nil {
		return err
	}
	if err := executionAuthority(ctx, o, deployment, uid, gid, custody); err != nil {
		return err
	}
	recipient, err := protected(o.BackupRecipient, false)
	if err != nil {
		return err
	}
	if err := newFile("/etc/lindm/backup-recipient", recipient, 0, 0, 0600); err != nil {
		return err
	}
	if o.DatabaseURL == "" {
		if err := localDatabase(ctx, release, pguid, pggid); err != nil {
			return err
		}
	} else {
		if err := externalDatabaseCredential(o.DatabaseURL, "/etc/lindm", uid, gid); err != nil {
			return err
		}
		if err := externalDatabaseCredential(o.MigrationURL, "/etc/lindm/migrate", muid, mgid); err != nil {
			return err
		}
	}
	if err := ensureIntegrationKey(nativeIntegrationKey, ""); err != nil {
		return err
	}
	deviceOrigin := o.DeviceOrigin
	cfg := &configv1.ServerConfig{DeploymentId: deployment, PublicUrl: o.Origin, DevicePublicUrl: &deviceOrigin,
		AdminListener: &configv1.ListenerConfig{Address: "0.0.0.0", Port: uint32(o.AdminPort)}, DeviceListener: &configv1.ListenerConfig{Address: "0.0.0.0", Port: uint32(o.DevicePort)},
		Database: &configv1.DatabaseConfig{UrlFile: "/etc/lindm/database-url", MaxConnections: 16},
		Tls:      &configv1.TLSConfig{CertificateFile: "/etc/lindm/server.crt", PrivateKeyFile: "/etc/lindm/server.key"}, DeviceCa: &configv1.DeviceCAConfig{CertificateFile: "/etc/lindm/device-ca.crt", PrivateKeyFile: "/etc/lindm/device-ca.key"},
		Authentication:     &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}},
		ExecutionBootstrap: &configv1.ExecutionBootstrapConfig{RootFile: "/etc/lindm/execution-root.json", BootstrapFile: "/etc/lindm/bootstrap.dsse.json", InitialDelegationFile: proto.String("/etc/lindm/execution-delegation.json")},
		Integrations:       &configv1.IntegrationsConfig{EncryptionKeyFile: nativeIntegrationKey},
		ExecutionSigning:   &configv1.ExecutionSigningConfig{PlanKeyFile: "/etc/lindm/plan.key", StartKeyFile: "/etc/lindm/start.key"}}
	if err := writeConfig("/etc/lindm/server.json", cfg, uid, gid); err != nil {
		return err
	}
	migration := proto.CloneOf(cfg)
	migration.Integrations = nil
	migration.Database.UrlFile = "/etc/lindm/migrate/database-url"
	migrationURL := "/etc/lindm/migrate/database-url"
	migration.Database.MigrationUrlFile = &migrationURL
	if err := writeConfig("/etc/lindm/migrate/server.json", migration, muid, mgid); err != nil {
		return err
	}
	if err := serverops.PublishRecoveryCustodyHealth(cfg, len(custody.identities) == 0); err != nil {
		return err
	}
	// Database TLS roots are public but the checked loader requires ownership by
	// the loading account; keep independently owned copies for each identity.
	if o.DatabaseURL == "" {
		ca, err := os.ReadFile("/etc/lindm/database-ca.crt")
		if err != nil {
			return err
		}
		if err := newFile("/etc/lindm/migrate/database-ca.crt", ca, muid, mgid, 0600); err != nil {
			return err
		}
	}
	return validateDatabaseRoles(ctx)
}

func writeConfig(path string, cfg *configv1.ServerConfig, uid, gid int) error {
	data, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(cfg)
	if err != nil {
		return err
	}
	return newFile(path, data, uid, gid, 0600)
}

func localDatabase(ctx context.Context, release *platform.Release, pguid, pggid int) error {
	data, port := release.Server.PostgreSQLDataDirectory, release.Server.PostgreSQLPort
	if err := newFile("/etc/lindm/postgresql/port", []byte(port), 0, 0, 0600); err != nil {
		return err
	}
	if err := directory(data, pguid, pggid, 0700); err != nil {
		return err
	}
	bin := release.Server.PostgreSQLBinDirectory
	if _, err := command(ctx, nil, "runuser", "-u", "postgres", "--", bin+"initdb", "-D", data, "--auth-local=peer", "--auth-host=scram-sha-256", "--encoding=UTF8", "--locale=C"); err != nil {
		return err
	}
	postgresConfig := "listen_addresses = '127.0.0.1,::1'\nport = " + port + "\nunix_socket_directories = '/run/lindm-postgresql'\nssl = on\nssl_min_protocol_version = 'TLSv1.3'\nssl_cert_file = '/etc/lindm/postgresql/server.crt'\nssl_key_file = '/etc/lindm/postgresql/server.key'\npassword_encryption = 'scram-sha-256'\nmax_connections = 64\nshared_buffers = '256MB'\nstatement_timeout = '60s'\nidle_in_transaction_session_timeout = '60s'\n"
	postgresConfig += "log_statement = 'none'\nlog_min_error_statement = 'panic'\nlog_parameter_max_length = 0\nlog_parameter_max_length_on_error = 0\n"
	if err := newFile(data+"/lindm.conf", []byte(postgresConfig), pguid, pggid, 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(data+"/postgresql.conf", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString("\ninclude = 'lindm.conf'\n")
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	hba := "local all postgres peer\nlocal all all reject\nhostssl lindm lindm_runtime 127.0.0.1/32 scram-sha-256\nhostssl lindm lindm_runtime ::1/128 scram-sha-256\nhostssl lindm lindm_migrator 127.0.0.1/32 scram-sha-256\nhostssl lindm lindm_migrator ::1/128 scram-sha-256\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n"
	if err := os.WriteFile(data+"/pg_hba.conf", []byte(hba), 0600); err != nil {
		return err
	}
	if release.Packages.Backend.PackageDB() == platform.PackageDBRPM {
		if _, err := command(ctx, nil, "restorecon", "-R", data, "/etc/lindm/postgresql"); err != nil {
			return err
		}
	}
	unit := "[Unit]\nDescription=Lindm private PostgreSQL cluster\nAfter=network.target\n[Service]\nType=simple\nUser=postgres\nGroup=postgres\nRuntimeDirectory=lindm-postgresql\nRuntimeDirectoryMode=0700\nExecStart=" + bin + "postgres -D " + data + "\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=" + data + " /run/lindm-postgresql\nInaccessiblePaths=/etc/lindm/offline /etc/lindm/migrate\nLimitCORE=0\nMemorySwapMax=0\n[Install]\nWantedBy=multi-user.target\n"
	if err := newFile("/etc/systemd/system/lindm-postgresql.service", []byte(unit), 0, 0, 0644); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := command(ctx, nil, "systemctl", "enable", "--now", "lindm-postgresql.service"); err != nil {
		return err
	}
	startCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		if _, err := command(startCtx, nil, "runuser", "-u", "postgres", "--", bin+"pg_isready", "-h", "/run/lindm-postgresql", "-p", port); err == nil {
			break
		}
		select {
		case <-startCtx.Done():
			return errors.New("local PostgreSQL readiness deadline exceeded")
		case <-time.After(time.Second):
		}
	}
	passwords := make([]string, 2)
	for i := range passwords {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		passwords[i] = base64.RawURLEncoding.EncodeToString(raw[:])
		clear(raw[:])
	}
	sql := fmt.Sprintf("CREATE ROLE lindm_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '%s';\nCREATE ROLE lindm_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '%s';\nCREATE DATABASE lindm OWNER lindm_migrator;\nREVOKE ALL ON DATABASE lindm FROM PUBLIC;\nGRANT CONNECT ON DATABASE lindm TO lindm_runtime;\n", passwords[1], passwords[0])
	if err := sqlLocal(ctx, sql, "postgres"); err != nil {
		return err
	}
	sql = "REVOKE ALL ON SCHEMA public FROM PUBLIC;\nALTER SCHEMA public OWNER TO lindm_migrator;\nGRANT USAGE ON SCHEMA public TO lindm_runtime;\nALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO lindm_runtime;\nALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO lindm_runtime;\n"
	if err := sqlLocal(ctx, sql, "lindm"); err != nil {
		return err
	}
	for i, item := range []struct {
		role, path, ca string
	}{{"lindm_runtime", "/etc/lindm/database-url", "/etc/lindm/database-ca.crt"}, {"lindm_migrator", "/etc/lindm/migrate/database-url", "/etc/lindm/migrate/database-ca.crt"}} {
		if err := newDatabaseURL(item.path, []byte(localDatabaseURL(item.role, passwords[i], port, item.ca))); err != nil {
			return err
		}
	}
	return nil
}

func localDatabaseURL(role, password, port, ca string) string {
	u := &url.URL{Scheme: "postgresql", Host: "localhost:" + port, Path: "/lindm", User: url.UserPassword(role, password)}
	q := url.Values{
		"sslmode": {"verify-full"}, "sslrootcert": {ca},
		"channel_binding": {"require"}, "require_auth": {"scram-sha-256"},
	}
	u.RawQuery = q.Encode()
	return u.String() + "\n"
}

func sqlLocal(ctx context.Context, sql, database string) error {
	port, err := protected("/etc/lindm/postgresql/port", true)
	if err != nil {
		return err
	}
	_, err = command(ctx, []byte(sql), "runuser", "-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", "/run/lindm-postgresql", "-p", string(port), "-d", database)
	return err
}

func migrationPool(ctx context.Context) (pool *pgxpool.Pool, err error) {
	d, cleanup, err := serverops.StageDatabaseConfig("/etc/lindm/migrate/server.json")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			if pool != nil {
				pool.Close()
				pool = nil
			}
			err = errors.Join(err, cleanupErr)
		}
	}()
	cfg, err := d.MigrationDatabase()
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func validateDatabaseRoles(ctx context.Context) (err error) {
	pool, err := migrationPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	var valid bool
	err = pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND current_user = pg_get_userbyid(d.datdba) AND has_schema_privilege(current_user,'public','CREATE') AND pg_has_role(current_user,n.nspowner,'USAGE') FROM pg_roles r JOIN pg_database d ON d.datname=current_database() JOIN pg_namespace n ON n.nspname='public' WHERE r.rolname=current_user`).Scan(&valid)
	if err != nil || !valid {
		return errors.New("migrator must be restricted database owner with schema authority, not superuser")
	}
	// External runtime cannot share migration identity or own the schema.
	d, cleanup, err := serverops.StageRuntimeDatabaseConfig("/etc/lindm/server.json")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	database, err := d.Database()
	if err != nil {
		return err
	}
	migrator := pool.Config().ConnConfig
	if database.ConnConfig.Database != migrator.Database || database.ConnConfig.Host != migrator.Host || database.ConnConfig.Port != migrator.Port || database.ConnConfig.User == migrator.User {
		return errors.New("runtime and migrator must use the same database endpoint with distinct identities")
	}
	runtimePool, err := pgxpool.NewWithConfig(ctx, database)
	if err != nil {
		return err
	}
	defer runtimePool.Close()
	err = runtimePool.QueryRow(ctx, `SELECT NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT has_schema_privilege(current_user,'public','CREATE') AND NOT pg_has_role(current_user,d.datdba,'MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles privileged WHERE pg_has_role(current_user,privileged.oid,'MEMBER') AND (privileged.rolsuper OR privileged.rolcreatedb OR privileged.rolcreaterole OR privileged.rolreplication OR has_schema_privilege(privileged.oid,'public','CREATE') OR privileged.rolname IN ('pg_execute_server_program','pg_write_server_files'))) FROM pg_roles r JOIN pg_database d ON d.datname=current_database() WHERE r.rolname=current_user`).Scan(&valid)
	if err != nil || !valid {
		return errors.New("runtime must be distinct restricted non-owner without schema CREATE")
	}
	return nil
}

func restrictMetadata(ctx context.Context) (err error) {
	pool, err := migrationPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	d, cleanup, err := serverops.StageRuntimeDatabaseConfig("/etc/lindm/server.json")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	database, err := d.Database()
	if err != nil {
		return err
	}
	role := database.ConnConfig.User
	identifier := pgx.Identifier{role}.Sanitize()
	_, err = pool.Exec(ctx, "REVOKE ALL ON public.goose_db_version, public.lindm_schema_compatibility, public.server_recovery_state FROM "+identifier+"; GRANT SELECT ON public.goose_db_version, public.lindm_schema_compatibility, public.server_recovery_state TO "+identifier)
	if err != nil {
		return err
	}
	var schema, sequence string
	err = pool.QueryRow(ctx, `SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_get_serial_sequence('public.goose_db_version','id')::regclass`).Scan(&schema, &sequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, "REVOKE ALL ON SEQUENCE "+pgx.Identifier{schema, sequence}.Sanitize()+" FROM "+identifier)
	return err
}
