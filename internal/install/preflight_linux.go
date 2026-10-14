// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// Preserve the full least-privilege resource gate before native service startup.
// PID 1 alone opens the persistent root secrets, handing the checker the same
// ephemeral credentials as serve. command withholds all child diagnostics.
func checkRuntimeConfig(ctx context.Context) error {
	return checkRuntimeConfigBinary(ctx, "/usr/bin/lindmd")
}

func checkRuntimeConfigBinary(ctx context.Context, binary string) error {
	_, err := command(ctx, nil, "systemd-run", runtimeConfigArguments(binary)...)
	return err
}

func runtimeConfigArguments(binary string) []string {
	return []string{
		"--quiet", "--wait", "--collect", "--pipe",
		"--property=User=lindmd", "--property=Group=lindmd",
		"--property=LoadCredential=database-url:/etc/lindm/database-url",
		"--property=LoadCredential=integrations-key:" + nativeIntegrationKey,
		"--property=UMask=0077", "--property=MemorySwapMax=0", "--property=LimitCORE=0",
		"--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes",
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
		"--property=InaccessiblePaths=-/etc/lindm/migrate",
		binary, "check-config", "-config", "/etc/lindm/server.json", "-database-url-credential", "database-url",
		"-integrations-key-credential", "integrations-key",
	}
}

// Read only the authenticated target's public flag help before changing any
// package or secret state. Older binaries must not be installed with a unit
// whose explicit credential selection they cannot accept.
func integrationCredentialPreflight(ctx context.Context, binary string) error {
	cmd := exec.CommandContext(ctx, binary, "check-config", "-help")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "LANG=C", "LC_ALL=C"}
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		return fmt.Errorf("target runtime credential capability preflight failed: %w", err)
	}
	for line := range strings.SplitSeq(output.data.String(), "\n") {
		if strings.TrimSpace(line) == "-integrations-key-credential string" {
			return nil
		}
	}
	return errors.New("target binary cannot explicitly select the native integration credential; package and secret state retained")
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
