// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// Preserve the full least-privilege resource gate before native service startup.
// PID 1 alone opens the persistent root URL, handing the checker the same
// ephemeral credential as serve. command withholds all child diagnostics.
func checkRuntimeConfig(ctx context.Context) error {
	_, err := command(ctx, nil, "systemd-run",
		"--quiet", "--wait", "--collect", "--pipe",
		"--property=User=lindmd", "--property=Group=lindmd",
		"--property=LoadCredential=database-url:/etc/lindm/database-url",
		"--property=UMask=0077", "--property=MemorySwapMax=0", "--property=LimitCORE=0",
		"--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes",
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
		"--property=InaccessiblePaths=-/etc/lindm/migrate",
		"/usr/bin/lindmd", "check-config", "-config", "/etc/lindm/server.json", "-database-url-credential", "database-url")
	return err
}

func databasePreflight(ctx context.Context) error {
	pool, err := migrationPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	var version int64
	var size int64
	if err := pool.QueryRow(ctx, `SELECT current_setting('server_version_num')::bigint,pg_database_size(current_database())`).Scan(&version, &size); err != nil {
		return err
	}
	if version < 130000 {
		return errors.New("PostgreSQL 13 or newer required; use the supported distribution repository version")
	}
	var disk unix.Statfs_t
	if err := unix.Statfs("/var/backups", &disk); err != nil {
		return err
	}
	if size < 0 || uint64(size) > ((^uint64(0))-(4<<30))/2 {
		return errors.New("database size exceeds backup capacity bounds")
	}
	needed := uint64(size)*2 + (4 << 30)
	if disk.Bavail*uint64(disk.Bsize) < needed {
		return errors.New("insufficient backup disk: require twice database size plus 4 GiB before migration")
	}
	return nil
}
