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
	directory := release.Server.PostgreSQLDataDirectory
	command := "systemctl is-active --quiet lindm-postgresql.service; test -s " + nativeQuote(directory+"/PG_VERSION") + "; test \"$(stat -c %U " + nativeQuote(directory) + ")\" = postgres; test \"$(stat -c %a " + nativeQuote(directory) + ")\" = 700; test \"$(stat -c %u /etc/systemd/system/lindm-postgresql.service)\" = 0; test \"$(stat -c %a /etc/systemd/system/lindm-postgresql.service)\" = 644"
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		command += "; test \"$(cat /var/lib/postgresql/lindm/PG_VERSION)\" = 16; test ! -e /etc/postgresql/16/main; test ! -e /var/lib/postgresql/16/main; if systemctl is-active --quiet postgresql@16-main.service; then exit 1; fi; test -z \"$(journalctl --quiet --no-pager --output=json --unit=postgresql@16-main.service)\""
	}
	_, err := serverGuestCommand(ctx, guest, "prove owned hardened PostgreSQL and no vendor default cluster", command, nil)
	return err
}
