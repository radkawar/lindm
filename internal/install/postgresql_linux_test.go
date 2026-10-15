// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"lindm/internal/platform"
)

func TestPostgreSQLServerContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		version int64
		want    bool
	}{
		{"unknown", 0, false},
		{"13", 130022, false},
		{"14", 140019, false},
		{"15", 150015, false},
		{"16 initial", 160000, true},
		{"16 patched", 160011, true},
		{"17", 170007, true},
		{"18", 180006, true},
		{"19", 190000, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkPostgreSQLServerVersion(test.version)
			if (err == nil) != test.want {
				t.Fatalf("server version admission = %v, want %t", err, test.want)
			}
			if err != nil && !strings.Contains(err.Error(), "PostgreSQL 16, 17 or 18") {
				t.Fatal("refusal does not name the supported database version")
			}
		})
	}
}

func TestPostgreSQLSelectedServerContract(t *testing.T) {
	for _, selected := range []int{0, 14, 15, 16, 17, 18, 19} {
		for _, server := range []int{0, 14, 15, 16, 17, 18, 19} {
			err := checkSelectedPostgreSQLServerVersion(int64(server*10000+1), selected)
			want := platform.PostgreSQLMajorSupported(selected) && server == selected
			if (err == nil) != want {
				t.Fatalf("selected=%d server=%d: %v, want admitted %t", selected, server, err, want)
			}
		}
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
			err := admitRHELPostgreSQL(test.configuration, test.installed, 16)
			if (err == nil) != test.want {
				t.Fatalf("admission = %v, want admitted %t", err, test.want)
			}
			if err != nil && !strings.Contains(err.Error(), "fresh supported turnkey host") {
				t.Fatal("refusal lacks non-migration remedy")
			}
		})
	}
}

func TestPostgreSQLClientContractBeforeProvisioning(t *testing.T) {
	for _, major := range []int{16, 17, 18} {
		for _, local := range []bool{false, true} {
			for _, mismatch := range []string{"", "postgres", "psql", "pg_dump", "pg_restore"} {
				for _, version := range []string{"15.15", "16.10", "17.6", "18.2", "19.1", "invalid"} {
					name := fmt.Sprintf("major=%d/local=%t/tool=%s/version=%s", major, local, mismatch, version)
					t.Run(name, func(t *testing.T) {
						// Deliberately no module: native EL10 and Debian-family
						// releases require the same executable capability gate.
						release := &platform.Release{Server: &platform.ServerInstallation{}}
						release.Server.PostgreSQLMajor = major
						release.Server.PostgreSQLBinDirectory = "/selected/bin/"
						var calls []string
						run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
							if !slices.Equal(args, []string{"--version"}) || !strings.HasPrefix(name, "/selected/bin/") {
								t.Fatalf("unexpected tool command %s %v", name, args)
							}
							tool := strings.TrimPrefix(name, "/selected/bin/")
							calls = append(calls, tool)
							value := strconv.Itoa(major) + ".1"
							if tool == mismatch {
								value = version
							}
							return []byte(tool + " (PostgreSQL) " + value + "\n"), nil
						}
						err := checkPostgreSQLClientTools(t.Context(), release, local, run)
						want := mismatch == "" || (!local && mismatch == "postgres") || postgresMajor(version) == major
						if (err == nil) != want {
							t.Fatalf("client contract = %v, want admitted %t", err, want)
						}
						if want {
							tools := []string{"psql", "pg_dump", "pg_restore"}
							if local {
								tools = append([]string{"postgres"}, tools...)
							}
							if !slices.Equal(calls, tools) {
								t.Fatalf("incomplete tool capability gate: %v", calls)
							}
						}
					})
				}
			}
		}
	}
}

func TestRHELPostgreSQLAdmissionUsesSelectedMajor(t *testing.T) {
	for _, major := range []int{16, 17, 18} {
		configuration := fmt.Sprintf("[postgresql]\nstream=%d\nstate=enabled\n", major)
		installed := fmt.Sprintf("postgresql %d.1\npostgresql-server %d.1\n", major, major)
		if err := admitRHELPostgreSQL(configuration, installed, major); err != nil {
			t.Fatal(err)
		}
		if err := admitRHELPostgreSQL(configuration, installed, major+1); err == nil {
			t.Fatal("different selected module/packages admitted")
		}
	}
}

func TestRHELAirgapCannotFallbackToPostgreSQL13(t *testing.T) {
	release := platform.ForManifest("rhel", "9")
	if err := requireAirgapAddon(t.TempDir(), release); err == nil || !strings.Contains(err.Error(), "connected installation only") {
		t.Fatalf("airgap capability refusal = %v", err)
	}
	if err := installDependencies(t.Context(), Options{Airgap: true}, release); err == nil || !strings.Contains(err.Error(), "connected installation only") {
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

func TestRHELNativePostgreSQLAdmissionDoesNotSelectModule(t *testing.T) {
	release := &platform.Release{Server: &platform.ServerInstallation{PostgreSQLMajor: 16}}
	for _, installed := range []string{"postgresql 16.10\npostgresql-server 16.10\n", "postgresql-server 15.15\n"} {
		var calls []string
		run := func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			calls = append(calls, name)
			if name != "rpm" {
				t.Fatalf("native PostgreSQL baseline changed modules: %s %v", name, args)
			}
			return []byte(installed), nil
		}
		err := prepareRHELPostgreSQLAt(t.Context(), release, run, t.TempDir())
		want := strings.Contains(installed, "16.10")
		if (err == nil) != want || !slices.Equal(calls, []string{"rpm"}) {
			t.Fatalf("native admission calls=%v error=%v", calls, err)
		}
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
