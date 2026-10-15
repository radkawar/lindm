// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"lindm/internal/platform"
)

func TestPostgreSQL16ServerContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		version int64
		want    bool
	}{
		{"unknown", 0, false},
		{"13", 130022, false},
		{"15", 150015, false},
		{"16 initial", 160000, true},
		{"16 patched", 160011, true},
		{"17", 170007, false},
		{"18", 180006, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkPostgreSQLServerVersion(test.version)
			if (err == nil) != test.want {
				t.Fatalf("server version admission = %v, want %t", err, test.want)
			}
			if err != nil && !strings.Contains(err.Error(), "PostgreSQL 16 is required for local and external databases") {
				t.Fatal("refusal does not name the supported database version")
			}
		})
	}
}

func TestRHELPostgreSQLAdmissionRetainsUnrelatedState(t *testing.T) {
	for _, test := range []struct {
		name, configuration, installed string
		want                           bool
	}{
		{"fresh", "", "systemd 252\n", true},
		{"selected", "[postgresql]\nstream=16\nstate=enabled\n", "postgresql 16.10\npostgresql-server 16.10\n", true},
		{"old stream", "[postgresql]\nstream=13\nstate=enabled\n", "", false},
		{"disabled", "[postgresql]\nstream=16\nstate=disabled\n", "", false},
		{"reset", "[postgresql]\nstream=\nstate=unknown\n", "", false},
		{"old server", "", "postgresql-server 13.20\n", false},
		{"old client", "", "postgresql 13.20\n", false},
		{"future major", "", "postgresql-server 17.6\n", false},
		{"malformed version", "", "postgresql-server invalid\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := admitRHELPostgreSQL(test.configuration, test.installed)
			if (err == nil) != test.want {
				t.Fatalf("admission = %v, want admitted %t", err, test.want)
			}
			if err != nil && !strings.Contains(err.Error(), "fresh supported turnkey host") {
				t.Fatal("refusal lacks non-migration remedy")
			}
		})
	}
}

func TestRHELPostgreSQLClientContractBeforeProvisioning(t *testing.T) {
	release := platform.ForManifest("rhel", "9")
	for _, old := range []string{"", "postgres", "psql", "pg_dump", "pg_restore"} {
		t.Run("old="+old, func(t *testing.T) {
			var calls []string
			run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
				if !slices.Equal(args, []string{"--version"}) {
					t.Fatalf("unexpected mutating command %s %v", name, args)
				}
				tool := strings.TrimPrefix(name, "/usr/bin/")
				calls = append(calls, tool)
				version := "16.10"
				if tool == old {
					version = "13.20"
				}
				return []byte(tool + " (PostgreSQL) " + version + "\n"), nil
			}
			err := checkPostgreSQLTools(t.Context(), release, run)
			if (err == nil) != (old == "") {
				t.Fatalf("client contract = %v", err)
			}
			if old == "" && !slices.Equal(calls, []string{"postgres", "psql", "pg_dump", "pg_restore"}) {
				t.Fatalf("incomplete tool capability gate: %v", calls)
			}
		})
	}
}

func TestRHELAirgapCannotFallbackToPostgreSQL13(t *testing.T) {
	release := platform.ForManifest("rhel", "9")
	if err := requireAirgapAddon(t.TempDir(), release); err == nil || err.Error() != "RHEL offline installation is not available in this release" {
		t.Fatalf("airgap capability refusal = %v", err)
	}
	if err := installDependencies(t.Context(), Options{Airgap: true}, release); err == nil || err.Error() != "RHEL offline installation is not available in this release" {
		t.Fatalf("dependency transaction did not fail closed: %v", err)
	}
}

func TestRHELModuleSelectionFollowsReadOnlyAdmission(t *testing.T) {
	for _, state := range []string{"fresh", "old package", "unrelated cluster"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			if state == "unrelated cluster" {
				data := filepath.Join(root, "var/lib/pgsql/data")
				if err := os.MkdirAll(data, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte("13"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var calls []string
			run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
				calls = append(calls, name)
				switch name {
				case "rpm":
					if !slices.Equal(args, []string{"-qa", "--queryformat", "%{NAME} %{VERSION}\\n"}) {
						t.Fatalf("unexpected inventory query %v", args)
					}
					if state == "old package" {
						return []byte("postgresql-server 13.20\n"), nil
					}
				case "dnf":
					want := []string{"--assumeyes", "--setopt=*.gpgcheck=True", "--setopt=*.sslverify=True", "module", "enable", "postgresql:16"}
					if !slices.Equal(args, want) {
						t.Fatalf("unsafe module selection %v", args)
					}
				default:
					t.Fatalf("unexpected command %s", name)
				}
				return nil, nil
			}
			err := prepareRHELPostgreSQLAt(t.Context(), platform.ForManifest("rhel", "9"), run, root)
			if state == "fresh" {
				if err != nil || !slices.Equal(calls, []string{"rpm", "dnf"}) {
					t.Fatalf("fresh selection order %v: %v", calls, err)
				}
			} else if err == nil || !slices.Equal(calls, []string{"rpm"}) {
				t.Fatalf("unsafe state mutated modules: %v: %v", calls, err)
			}
		})
	}
}

func TestPostgreSQLSELinuxEnforcementControlsOnlyVendorNNPException(t *testing.T) {
	for _, test := range []struct {
		name, distro, release, state  string
		commandError, want, wantError bool
	}{
		{name: "ubuntu", distro: "ubuntu", release: "24.04"},
		{name: "enforcing", distro: "rhel", release: "9", state: "Enforcing", want: true},
		{name: "permissive", distro: "rhel", release: "9", state: "Permissive"},
		{name: "disabled", distro: "rhel", release: "9", state: "Disabled"},
		{name: "unknown", distro: "rhel", release: "9", state: "unrecognized", wantError: true},
		{name: "empty", distro: "rhel", release: "9", wantError: true},
		{name: "command failed", distro: "rhel", release: "9", commandError: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
				calls++
				if name != "getenforce" || len(args) != 0 || len(input) != 0 {
					t.Fatal("enforcement detection executed an unexpected command")
				}
				if test.commandError {
					return nil, errors.New("unavailable")
				}
				return []byte(test.state + "\n"), nil
			}
			got, err := selinuxEnforcing(t.Context(), platform.ForManifest(test.distro, test.release), run)
			if got != test.want || (err != nil) != test.wantError {
				t.Fatalf("enforcement=%t error=%v", got, err)
			}
			if test.distro == "ubuntu" && calls != 0 || test.distro == "rhel" && calls != 1 {
				t.Fatal("SELinux detection escaped its native platform boundary")
			}
		})
	}
}

func TestPostgreSQLVendorNNPExceptionPreservesEveryOtherSandboxDirective(t *testing.T) {
	normal := localPostgresUnit("/var/lib/pgsql/lindm", "/usr/bin/", "/run/postgresql/lindm", false)
	enforcing := localPostgresUnit("/var/lib/pgsql/lindm", "/usr/bin/", "/run/postgresql/lindm", true)
	if !strings.Contains(normal, "\nNoNewPrivileges=yes\n") || !strings.Contains(enforcing, "\nNoNewPrivileges=no\n") ||
		strings.Replace(enforcing, "\nNoNewPrivileges=no\n", "\nNoNewPrivileges=yes\n", 1) != normal {
		t.Fatal("vendor confinement exception changed more than the PostgreSQL NNP directive")
	}
	for _, directive := range []string{"User=postgres", "Group=postgres", "RuntimeDirectoryMode=0700", "UMask=0077", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "InaccessiblePaths=/etc/lindm/offline /etc/lindm/migrate", "LimitCORE=0", "MemorySwapMax=0"} {
		if !strings.Contains(enforcing, "\n"+directive+"\n") {
			t.Fatalf("SELinux-confined unit lost %s", directive)
		}
	}
}

func TestPostgreSQLUnitUsesNativePrivateSocketNamespace(t *testing.T) {
	for _, test := range []struct {
		distro, release, runtime, socket string
	}{
		{"ubuntu", "24.04", "lindm-postgresql", "/run/lindm-postgresql"},
		{"rhel", "9", "postgresql/lindm", "/run/postgresql/lindm"},
	} {
		release := platform.ForManifest(test.distro, test.release)
		unit := localPostgresUnit(release.Server.PostgreSQLDataDirectory, release.Server.PostgreSQLBinDirectory, release.Server.PostgreSQLSocketDirectory, false)
		if !strings.Contains(unit, "\nRuntimeDirectory="+test.runtime+"\n") ||
			!strings.Contains(unit, "\nReadWritePaths="+release.Server.PostgreSQLDataDirectory+" "+test.socket+"\n") {
			t.Fatalf("%s unit escapes the distro's private PostgreSQL socket namespace", test.distro)
		}
	}
}

func TestPostgreSQLSELinuxDomainRejectsTheObservedInitDomain(t *testing.T) {
	for _, label := range []string{"system_u:system_r:postgresql_t:s0", "system_u:system_r:postgresql_t:s0:c0,c1\x00\n"} {
		if !postgresSELinuxDomain([]byte(label)) {
			t.Fatal("expected PostgreSQL confinement was refused")
		}
	}
	for _, label := range []string{"", "postgresql_t", "system_u:system_r:init_t:s0", "system_u:system_r:unconfined_service_t:s0", "system_u:system_r:postgresql_t_extra:s0", "system_u:system_r:postgresql_t"} {
		if postgresSELinuxDomain([]byte(label)) {
			t.Fatal("missing or wrong PostgreSQL confinement was accepted")
		}
	}
}
