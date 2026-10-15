// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
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
const deployDatabaseCredentialsCommand = `gate=secret_symlink
trap 'status=$?; if test "$status" -ne 0; then printf "%s\n" "$gate"; fi' EXIT
for path in /etc/lindm/database-url /etc/lindm/migrate/database-url /etc/lindm/integrations.key; do
gate=secret_symlink
test ! -L "$path"
gate=secret_regular_file
test -f "$path"
gate=secret_owner_mode_links
test "$(stat -c %u:%g:%a:%h "$path")" = 0:0:600:1
for account in lindmd lindmd-migrate; do
gate=service_can_read_at_rest
if runuser -u "$account" -- test -r "$path"; then exit 1; fi
done
done
gate=integration_key_length
test "$(stat -c %s /etc/lindm/integrations.key)" = 32
gate=runtime_service_inactive
systemctl is-active --quiet lindmd.service`

func proveDeployDatabaseCredentials(ctx context.Context, guest *guestVM) error {
	output, err := guest.runResult(ctx, "sudo -n env LC_ALL=C sh -eu -c "+nativeQuote(deployDatabaseCredentialsCommand), nil, 4096, time.Minute)
	defer clear(output.Stdout)
	defer clear(output.Stderr)
	if err != nil {
		return errors.New("deploy native credential proof transport failed")
	}
	if output.ExitCode != 0 {
		return errors.New("deploy native credential proof failed: " + deployCredentialFailure(output.Stdout))
	}
	for _, handoff := range []struct {
		unit     string
		expected [][2]string
	}{
		{"lindmd_2eservice", [][2]string{{"database-url", "/etc/lindm/database-url"}, {"integrations-key", "/etc/lindm/integrations.key"}}},
		{"lindmd_2dmigrate_2eservice", [][2]string{{"database-url", "/etc/lindm/migrate/database-url"}}},
	} {
		command := "busctl --system --json=short --timeout=5s --auto-start=no get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/" + handoff.unit + " org.freedesktop.systemd1.Service LoadCredential"
		property, propertyErr := guest.runResult(ctx, command, nil, 4096, time.Minute)
		valid := propertyErr == nil && property.ExitCode == 0 && deployCredentialSourcesMatch(property.Stdout, handoff.expected)
		clear(property.Stdout)
		clear(property.Stderr)
		if !valid {
			return errors.New("deploy native credential source property did not match expected handoff")
		}
	}
	return nil
}

func deployCredentialFailure(output []byte) string {
	switch string(output) {
	case "secret_symlink\n":
		return "secret_symlink"
	case "secret_regular_file\n":
		return "secret_regular_file"
	case "secret_owner_mode_links\n":
		return "secret_owner_mode_links"
	case "service_can_read_at_rest\n":
		return "service_can_read_at_rest"
	case "integration_key_length\n":
		return "integration_key_length"
	case "runtime_service_inactive\n":
		return "runtime_service_inactive"
	default:
		return "unclassified"
	}
}

func deployCredentialSourcesMatch(body []byte, expected [][2]string) bool {
	var property struct {
		Type string     `json:"type"`
		Data [][]string `json:"data"`
	}
	if json.Unmarshal(body, &property) != nil || property.Type != "a(ss)" || len(property.Data) != len(expected) {
		return false
	}
	var seen uint8
	for _, credential := range property.Data {
		if len(credential) != 2 {
			return false
		}
		matched := false
		for i, source := range expected {
			bit := uint8(1 << i)
			if credential[0] == source[0] && credential[1] == source[1] && seen&bit == 0 {
				seen |= bit
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// This is a real PostgreSQL runtime connection with unchanged verify-full and
// required SCRAM-PLUS policy, not a permission query or a migration-user
// impersonation. Passwords travel only over pinned SSH stdin and an ephemeral
// runtime-owned PGPass file.
func proveDeployRuntimePrivileges(ctx context.Context, guest *guestVM) (gates []VMDeploySQLGate, err error) {
	body, err := serverGuestCommand(ctx, guest, "read private runtime DSN for security proof", "cat /etc/lindm/database-url", nil)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	dsn, parseErr := url.Parse(strings.TrimSpace(string(body)))
	if parseErr != nil || dsn.User == nil || (dsn.Scheme != "postgresql" && dsn.Scheme != "postgres") ||
		dsn.Query().Get("sslmode") != "verify-full" || !filepath.IsAbs(dsn.Query().Get("sslrootcert")) ||
		dsn.Query().Get("channel_binding") != "require" || dsn.Query().Get("require_auth") != "scram-sha-256" {
		return nil, errors.New("deploy runtime proof requires valid private verify-full SCRAM-PLUS PostgreSQL DSN")
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
	command := "sudo -n runuser -u lindmd -- env LC_ALL=C PGCHANNELBINDING=require PGPASSFILE=" + nativeQuote(privatePass) + " PGSSLMODE=verify-full PGSSLROOTCERT=" + nativeQuote(dsn.Query().Get("sslrootcert")) + " " + nativeQuote(guest.release.Server.PostgreSQLBinDirectory+"psql") + " -X -v ON_ERROR_STOP=1 -h " + nativeQuote(dsn.Hostname()) + " -p " + nativeQuote(port) + " -U " + nativeQuote(dsn.User.Username()) + " -d " + nativeQuote(database)
	handshake, handshakeErr := guest.runResult(ctx, command+" -Atq", strings.NewReader("SELECT 1;\n"), 16<<10, time.Minute)
	if handshakeErr != nil || handshake.ExitCode != 0 || strings.TrimSpace(string(handshake.Stdout)) != "1" || len(handshake.Stderr) != 0 {
		return nil, errors.New("deploy runtime SCRAM-PLUS handshake and query did not complete")
	}
	gates = append(gates, VMDeploySQLGate{Name: "runtime SCRAM-SHA-256-PLUS handshake", SQLState: "00000"})
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
		if !deploySQLPrivilegeDenied(observed.ExitCode, observed.Stderr) {
			return gates, errors.New("deploy runtime SQL privilege rejection did not match: " + attempt.name)
		}
		gates = append(gates, VMDeploySQLGate{Name: attempt.name, SQLState: "42501"})
	}
	if _, err = serverGuestCommand(ctx, guest, "runtime cannot access separate migration credentials", "! runuser -u lindmd -- test -r /etc/lindm/migrate/database-url", nil); err != nil {
		return gates, err
	}
	return gates, nil
}

func deploySQLPrivilegeDenied(exitCode int, stderr []byte) bool {
	state, severity := strings.CutPrefix(strings.TrimSpace(string(stderr)), "ERROR:")
	return exitCode == 3 && severity && strings.TrimSpace(state) == "42501"
}
