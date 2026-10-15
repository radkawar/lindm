// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"

	"lindm/internal/platform"
)

// proveDeployPostgres exercises the installed owned service, not only config or
// database rows. Ubuntu's vendor package must never create/start its default
// unsandboxed main cluster during any of the three signed-install transitions.
func proveDeployPostgres(ctx context.Context, guest *guestVM, release *platform.Release) error {
	if err := release.LabLaneOn(platform.LaneDeploy, "x86_64"); err != nil {
		return err
	}
	_, err := serverGuestCommand(ctx, guest, "prove owned hardened PostgreSQL and no vendor default cluster", deployPostgresProofCommand(release), nil)
	return err
}

func deployPostgresProofCommand(release *platform.Release) string {
	directory := release.Server.PostgreSQLDataDirectory
	command := "systemctl is-active --quiet lindm-postgresql.service; test -s " + nativeQuote(directory+"/PG_VERSION") + "; test \"$(stat -c %U " + nativeQuote(directory) + ")\" = postgres; test \"$(stat -c %a " + nativeQuote(directory) + ")\" = 700; test \"$(stat -c %u /etc/systemd/system/lindm-postgresql.service)\" = 0; test \"$(stat -c %a /etc/systemd/system/lindm-postgresql.service)\" = 644"
	socket := release.Server.PostgreSQLSocketDirectory
	command += "; test -S " + nativeQuote(socket+"/.s.PGSQL."+release.Server.PostgreSQLPort) + "; test \"$(stat -c %U " + nativeQuote(socket) + ")\" = postgres; test \"$(stat -c %a " + nativeQuote(socket) + ")\" = 700"
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		command += "; test \"$(cat /var/lib/postgresql/lindm/PG_VERSION)\" = 16; test ! -e /etc/postgresql/16/main; test ! -e /var/lib/postgresql/16/main; if systemctl is-active --quiet postgresql@16-main.service; then exit 1; fi; test -z \"$(journalctl --quiet --no-pager --output=json --unit=postgresql@16-main.service)\""
	}
	if release.Packages.Backend.PackageDB() == platform.PackageDBRPM {
		command += "; test \"$(getenforce)\" = Enforcing; test \"$(systemctl show --property=NoNewPrivileges --value lindm-postgresql.service)\" = no; pid=$(systemctl show --property=MainPID --value lindm-postgresql.service); test \"$pid\" -gt 0; label=$(cat \"/proc/$pid/attr/current\"); label=${label#*:}; label=${label#*:}; test \"${label%%:*}\" = postgresql_t; nnp=; while read -r key value rest; do if test \"$key\" = NoNewPrivs:; then nnp=$value; fi; done < \"/proc/$pid/status\"; test \"$nnp\" = 0"
		command += "; socket_label=$(stat -c %C " + nativeQuote(socket) + "); socket_label=${socket_label#*:}; socket_label=${socket_label#*:}; test \"${socket_label%%:*}\" = postgresql_var_run_t"
	}
	return command
}
