// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"lindm/internal/platform"
)

// proveDeployPostgres exercises the installed owned service, not only config or
// database rows. Debian-family vendor packages must never create/start a default
// unsandboxed main cluster during any of the three signed-install transitions.
func proveDeployPostgres(ctx context.Context, guest *guestVM, release *platform.Release) error {
	if err := release.LabLaneOn(platform.LaneDeploy, "x86_64"); err != nil {
		return err
	}
	_, err := serverGuestCommand(ctx, guest, "prove owned hardened PostgreSQL and no vendor default cluster", deployPostgresProofCommand(release), nil)
	return err
}

// VMDeployStorageEvidence measures the populated server before backup or upgrade.
type VMDeployStorageEvidence struct {
	DatabaseBytes   uint64 `json:"database_bytes"`
	FilesystemBytes uint64 `json:"filesystem_bytes"`
	AvailableBytes  uint64 `json:"available_bytes"`
}

var errDeployStorage = errors.New("deploy storage observation requires bounded database and filesystem byte counts")

func observeDeployStorage(ctx context.Context, guest *guestVM) (*VMDeployStorageEvidence, error) {
	command := "runuser -u postgres -- " + nativeQuote(guest.release.Server.PostgreSQLBinDirectory+"psql") + " -X -Atq -v ON_ERROR_STOP=1 -h " + nativeQuote(guest.release.Server.PostgreSQLSocketDirectory) + " -p " + nativeQuote(guest.release.Server.PostgreSQLPort) + " -d lindm && stat --file-system --format='%S %b %a' /var/backups"
	body, err := serverGuestCommand(ctx, guest, "measure storage after full vendor import", command, strings.NewReader("SELECT pg_database_size(current_database());\n"))
	if err != nil {
		return nil, err
	}
	return parseDeployStorage(body)
}

func parseDeployStorage(body []byte) (*VMDeployStorageEvidence, error) {
	fields := strings.Fields(string(body))
	if len(fields) != 4 {
		return nil, errDeployStorage
	}
	var values [4]uint64
	for index, field := range fields {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, errDeployStorage
		}
		values[index] = value
	}
	database, blockSize, blocks, available := values[0], values[1], values[2], values[3]
	if database == 0 || database > 1<<63-1 || blockSize == 0 || blocks == 0 || available > blocks || blocks > ^uint64(0)/blockSize {
		return nil, errDeployStorage
	}
	return &VMDeployStorageEvidence{DatabaseBytes: database, FilesystemBytes: blockSize * blocks, AvailableBytes: blockSize * available}, nil
}

func deployPostgresProofCommand(release *platform.Release) string {
	directory := release.Server.PostgreSQLDataDirectory
	major := strconv.Itoa(release.Server.PostgreSQLMajor)
	command := "systemctl is-active --quiet lindm-postgresql.service; test \"$(cat " + nativeQuote(directory+"/PG_VERSION") + ")\" = " + major + "; test \"$(stat -c %U " + nativeQuote(directory) + ")\" = postgres; test \"$(stat -c %a " + nativeQuote(directory) + ")\" = 700; test \"$(stat -c %u /etc/systemd/system/lindm-postgresql.service)\" = 0; test \"$(stat -c %a /etc/systemd/system/lindm-postgresql.service)\" = 644"
	socket := release.Server.PostgreSQLSocketDirectory
	command += "; test -S " + nativeQuote(socket+"/.s.PGSQL."+release.Server.PostgreSQLPort) + "; test \"$(stat -c %U " + nativeQuote(socket) + ")\" = postgres; test \"$(stat -c %a " + nativeQuote(socket) + ")\" = 700"
	command += "; test \"$(runuser -u postgres -- " + nativeQuote(release.Server.PostgreSQLBinDirectory+"psql") + " -X -Atq -v ON_ERROR_STOP=1 -h " + nativeQuote(socket) + " -p " + nativeQuote(release.Server.PostgreSQLPort) + " -d postgres -c " + nativeQuote("SELECT current_setting('server_version_num')::integer / 10000") + ")\" = " + major
	if release.Packages.Backend.PackageDB() == platform.PackageDBDpkg {
		unit := "postgresql@" + major + "-main.service"
		command += "; test ! -e /etc/postgresql/" + major + "/main; test ! -e /var/lib/postgresql/" + major + "/main; if systemctl is-active --quiet " + nativeQuote(unit) + "; then exit 1; fi; test -z \"$(journalctl --quiet --no-pager --output=json --unit=" + nativeQuote(unit) + ")\""
		// PGDG installs must not leave a default cluster for another vendor
		// major either; an upgrade must retain the owned service exclusively.
		command += "; for cluster in /etc/postgresql/*/main /var/lib/postgresql/*/main; do test ! -e \"$cluster\"; done; test -z \"$(journalctl --quiet --no-pager --output=json --unit='postgresql@*-main.service')\""
	}
	if release.Packages.Backend.PackageDB() == platform.PackageDBRPM {
		command += "; test \"$(getenforce)\" = Enforcing; test \"$(systemctl show --property=NoNewPrivileges --value lindm-postgresql.service)\" = no; pid=$(systemctl show --property=MainPID --value lindm-postgresql.service); test \"$pid\" -gt 0; label=$(cat \"/proc/$pid/attr/current\"); label=${label#*:}; label=${label#*:}; test \"${label%%:*}\" = postgresql_t; nnp=; while read -r key value rest; do if test \"$key\" = NoNewPrivs:; then nnp=$value; fi; done < \"/proc/$pid/status\"; test \"$nnp\" = 0"
		command += "; socket_label=$(stat -c %C " + nativeQuote(socket) + "); socket_label=${socket_label#*:}; socket_label=${socket_label#*:}; test \"${socket_label%%:*}\" = postgresql_var_run_t"
	}
	return command
}
