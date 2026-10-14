// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type VMDeploySQLGate struct {
	Name     string `json:"name"`
	SQLState string `json:"sqlstate"`
}

// Run on the actual installed guest after install, upgrade and restore. Native
// services may read their systemd credential, never the persistent URL secret.
const deployDatabaseCredentialsCommand = `for path in /etc/lindm/database-url /etc/lindm/migrate/database-url; do
test ! -L "$path"
test -f "$path"
test "$(stat -c %u:%g:%a:%h "$path")" = 0:0:600:1
for account in lindmd lindmd-migrate; do
if runuser -u "$account" -- test -r "$path"; then exit 1; fi
done
done
test "$(systemctl show --value -p LoadCredential lindmd.service)" = database-url:/etc/lindm/database-url
test "$(systemctl show --value -p LoadCredential lindmd-migrate.service)" = database-url:/etc/lindm/migrate/database-url
systemctl is-active --quiet lindmd.service`

func proveDeployDatabaseCredentials(ctx context.Context, guest *guestVM) error {
	_, err := serverGuestCommand(ctx, guest, "prove root-only persistent database URLs and native credential handoff", deployDatabaseCredentialsCommand, nil)
	return err
}

// This is a real PostgreSQL runtime connection with unchanged verify-full
// policy, not a permission query or a migration-user impersonation. Passwords
// travel only over pinned SSH stdin and a short-lived runtime-owned PGPass file.
func proveDeployRuntimePrivileges(ctx context.Context, guest *guestVM) (gates []VMDeploySQLGate, err error) {
	body, err := serverGuestCommand(ctx, guest, "read private runtime DSN for security proof", "cat /etc/lindm/database-url", nil)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	dsn, parseErr := url.Parse(strings.TrimSpace(string(body)))
	if parseErr != nil || dsn.User == nil || (dsn.Scheme != "postgresql" && dsn.Scheme != "postgres") || dsn.Query().Get("sslmode") != "verify-full" || !filepath.IsAbs(dsn.Query().Get("sslrootcert")) {
		return nil, errors.New("deploy runtime proof requires valid private verify-full PostgreSQL DSN")
	}
	password, hasPassword := dsn.User.Password()
	if !hasPassword || strings.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("deploy runtime proof requires protected valid SCRAM password input")
	}
	port := dsn.Port()
	if port == "" {
		port = "5432"
	}
	database := strings.TrimPrefix(dsn.Path, "/")
	if dsn.User.Username() != "lindm_runtime" || database == "" || dsn.Hostname() == "" {
		return nil, errors.New("deploy runtime proof must use the isolated runtime database identity")
	}
	escape := strings.NewReplacer("\\", "\\\\", ":", "\\:").Replace
	pgpass := escape(dsn.Hostname()) + ":" + escape(port) + ":" + escape(database) + ":" + escape(dsn.User.Username()) + ":" + escape(password) + "\n"
	const privatePass = "/run/lindm-deploy-runtime.pgpass"
	if _, err = serverGuestCommand(ctx, guest, "prepare ephemeral runtime PGPass", "test ! -e "+privatePass+"; umask 077; cat > "+privatePass+"; chown lindmd:lindmd "+privatePass, strings.NewReader(pgpass)); err != nil {
		return nil, err
	}
	defer func() {
		_, removeErr := serverGuestCommand(context.WithoutCancel(ctx), guest, "remove ephemeral runtime PGPass", "rm -- "+privatePass, nil)
		err = errors.Join(err, removeErr)
	}()
	command := "sudo -n runuser -u lindmd -- env LC_ALL=C PGPASSFILE=" + nativeQuote(privatePass) + " PGSSLMODE=verify-full PGSSLROOTCERT=" + nativeQuote(dsn.Query().Get("sslrootcert")) + " psql -X -v ON_ERROR_STOP=1 -h " + nativeQuote(dsn.Hostname()) + " -p " + nativeQuote(port) + " -U " + nativeQuote(dsn.User.Username()) + " -d " + nativeQuote(database)
	attempts := []struct{ name, sql string }{
		{"setup code hash immutable", "UPDATE first_run_setup SET code_hash=code_hash WHERE false;"},
		{"setup expiry immutable", "UPDATE first_run_setup SET expires_at=expires_at WHERE false;"},
		{"runtime cannot mint setup code", "INSERT INTO first_run_setup(id,code_hash,expires_at) SELECT true,decode(repeat('00',32),'hex'),clock_timestamp() WHERE false;"},
		{"runtime cannot delete setup authority", "DELETE FROM first_run_setup WHERE false;"},
		{"runtime cannot truncate setup authority", "BEGIN; TRUNCATE first_run_setup; ROLLBACK;"},
		{"runtime cannot DDL", "BEGIN; CREATE TABLE lindm_deploy_ddl_denied(value integer); ROLLBACK;"},
	}
	for _, attempt := range attempts {
		observed, runErr := guest.runResult(ctx, command, strings.NewReader("\\set VERBOSITY sqlstate\n"+attempt.sql+"\n"), 16<<10, time.Minute)
		if runErr != nil {
			return gates, errors.New("deploy runtime SQL transport failed")
		}
		if observed.ExitCode != 3 || strings.TrimSpace(string(observed.Stderr)) != "ERROR: 42501" {
			return gates, errors.New("deploy runtime SQL write did not fail specifically for insufficient privilege")
		}
		gates = append(gates, VMDeploySQLGate{Name: attempt.name, SQLState: "42501"})
	}
	if _, err = serverGuestCommand(ctx, guest, "runtime cannot access separate migration credentials", "! runuser -u lindmd -- test -r /etc/lindm/migrate/database-url", nil); err != nil {
		return gates, err
	}
	return gates, nil
}
