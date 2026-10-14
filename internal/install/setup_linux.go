// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"lindm/internal/serverops"
)

// The process runs as root, but the staged URL authenticates as the dedicated
// migrator. Its checked root-owned database references preserve the immutable
// loader and keep the final setup code unreadable to both service identities.
func issueSetup(ctx context.Context) (err error) {
	d, cleanup, err := serverops.StageDatabaseConfig("/etc/lindm/migrate/server.json")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	stage, err := os.MkdirTemp("/run", "lindm-setup-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	path := filepath.Join(stage, "server.json")
	if err := writeConfig(path, d.Proto, 0, 0); err != nil {
		return err
	}
	_, err = command(ctx, nil, "/usr/bin/lindmd", "setup-code", "-config", path, "-output", "/var/lib/lindmd-operations/setup/code")
	return err
}
