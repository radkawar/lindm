// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"lindm/internal/platform"
)

type dependencyCommand func(context.Context, []byte, string, ...string) ([]byte, error)

// Never reset a module or adopt a pre-turnkey database. DNF itself rejects a
// conflicting stream; inspecting persistent module state also rejects disabled
// streams rather than silently overriding the operator's policy.
func prepareRHELPostgreSQL(ctx context.Context, release *platform.Release, run dependencyCommand) error {
	return prepareRHELPostgreSQLAt(ctx, release, run, "/")
}

func prepareRHELPostgreSQLAt(ctx context.Context, release *platform.Release, run dependencyCommand, root string) error {
	configuration, err := os.ReadFile(filepath.Join(root, "etc/dnf/modules.d/postgresql.module"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	installed, err := run(ctx, nil, "rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n")
	if err != nil {
		return err
	}
	if err := admitRHELPostgreSQL(string(configuration), string(installed)); err != nil {
		return err
	}
	for _, path := range []string{"/var/lib/pgsql/data", "/var/lib/pgsql/13/data"} {
		entries, err := os.ReadDir(filepath.Join(root, path))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if len(entries) != 0 {
			return errors.New("existing unrelated PostgreSQL cluster; use a fresh supported turnkey host; no database adoption or migration is supported")
		}
	}
	_, err = run(ctx, nil, "dnf", "--assumeyes", "--setopt=*.gpgcheck=True", "--setopt=*.sslverify=True", "module", "enable", release.Server.PostgreSQLModule)
	return err
}

func admitRHELPostgreSQL(configuration, installed string) error {
	refuse := errors.New("existing PostgreSQL module or packages are not a fresh PostgreSQL 16 baseline; use a fresh supported turnkey host; no module reset, stream switch or database migration is supported")
	for line := range strings.SplitSeq(configuration, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if (key == "stream" && value != "16") || (key == "state" && value != "enabled") {
			return refuse
		}
	}
	for line := range strings.SplitSeq(installed, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "postgresql" && fields[0] != "postgresql-server") {
			continue
		}
		if len(fields) != 2 || postgresMajor(fields[1]) != 16 {
			return refuse
		}
	}
	return nil
}

func postgresMajor(version string) int {
	major, _, _ := strings.Cut(version, ".")
	value, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return value
}

func checkPostgreSQLTools(ctx context.Context, release *platform.Release, run dependencyCommand) error {
	if release.Server.PostgreSQLModule == "" {
		return nil
	}
	for _, tool := range []string{"postgres", "psql", "pg_dump", "pg_restore"} {
		output, err := run(ctx, nil, release.Server.PostgreSQLBinDirectory+tool, "--version")
		if err != nil {
			return err
		}
		fields := strings.Fields(string(output))
		if len(fields) < 3 || fields[1] != "(PostgreSQL)" || postgresMajor(fields[2]) != 16 {
			return fmt.Errorf("%s must be distro PostgreSQL 16 before provisioning or backup; libpq must preserve channel_binding=require and require_auth=scram-sha-256", tool)
		}
	}
	return nil
}

func postgresSELinuxEnforcing(ctx context.Context, release *platform.Release, run dependencyCommand) (bool, error) {
	if release.Packages.Backend.PackageDB() != platform.PackageDBRPM {
		return false, nil
	}
	output, err := run(ctx, nil, "getenforce")
	if err != nil {
		return false, fmt.Errorf("determine PostgreSQL SELinux enforcement: %w", err)
	}
	switch strings.TrimSpace(string(output)) {
	case "Enforcing":
		return true, nil
	case "Permissive", "Disabled":
		return false, nil
	default:
		return false, errors.New("unrecognized PostgreSQL SELinux enforcement state")
	}
}

func localPostgresUnit(data, bin, socket string, enforcing bool) string {
	noNewPrivileges := "yes"
	if enforcing {
		// Match the vendor unit: SELinux must transition to postgresql_t.
		// NNP can silently retain init_t, which cannot read the private cluster.
		noNewPrivileges = "no"
	}
	return "[Unit]\nDescription=Lindm private PostgreSQL cluster\nAfter=network.target\n[Service]\nType=simple\nUser=postgres\nGroup=postgres\nRuntimeDirectory=" + strings.TrimPrefix(socket, "/run/") + "\nRuntimeDirectoryMode=0700\nExecStart=" + bin + "postgres -D " + data + "\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=" + noNewPrivileges + "\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=" + data + " " + socket + "\nInaccessiblePaths=/etc/lindm/offline /etc/lindm/migrate\nLimitCORE=0\nMemorySwapMax=0\n[Install]\nWantedBy=multi-user.target\n"
}

func requirePostgresSELinuxDomain(ctx context.Context, run dependencyCommand) error {
	output, err := run(ctx, nil, "systemctl", "show", "--property=MainPID", "--value", "lindm-postgresql.service")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || pid <= 0 {
		return errors.New("private PostgreSQL has no valid service process identity")
	}
	label, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/attr/current")
	if err != nil {
		return errors.New("cannot verify private PostgreSQL SELinux process confinement")
	}
	if !postgresSELinuxDomain(label) {
		return errors.New("private PostgreSQL must run in the enforcing postgresql_t SELinux domain")
	}
	return nil
}

func postgresSELinuxDomain(label []byte) bool {
	for range 2 {
		_, tail, ok := bytes.Cut(label, []byte(":"))
		if !ok {
			return false
		}
		label = tail
	}
	domain, _, ok := bytes.Cut(label, []byte(":"))
	return ok && bytes.Equal(domain, []byte("postgresql_t"))
}
