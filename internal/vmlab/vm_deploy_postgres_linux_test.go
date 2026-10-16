// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"strconv"
	"strings"
	"testing"

	"lindm/internal/platform"
)

func TestNativeRPMPostgresProofRequiresActualEnforcingDomain(t *testing.T) {
	for _, key := range []string{"rhel-9", "rhel-10", "rocky-9", "rocky-10", "almalinux-9", "almalinux-10"} {
		t.Run(key, func(t *testing.T) {
			release, ok := platform.Lookup(key)
			if !ok || release.Server == nil {
				t.Fatal("native server layout missing")
			}
			command := deployPostgresProofCommand(release)
			for _, required := range []string{"systemctl is-active --quiet lindm-postgresql.service", "$(getenforce)\" = Enforcing", "--property=NoNewPrivileges --value lindm-postgresql.service)\" = no", "--property=MainPID", "/proc/$pid/attr/current", "= postgresql_t", "/proc/$pid/status", "NoNewPrivs:", "test \"$nnp\" = 0", release.Server.PostgreSQLSocketDirectory + "/.s.PGSQL." + release.Server.PostgreSQLPort, "= postgresql_var_run_t", "test \"$(cat " + nativeQuote(release.Server.PostgreSQLDataDirectory+"/PG_VERSION") + ")\" = " + strconv.Itoa(release.Server.PostgreSQLMajor)} {
				if !strings.Contains(command, required) {
					t.Fatalf("native RPM confinement proof omits %s", required)
				}
			}
			if strings.Contains(command, "postgresql@") || strings.Contains(command, "module enable") {
				t.Fatal("Debian cluster or EL9 module assumptions escaped into native RPM proof")
			}
		})
	}
}

func TestNativeDebianPostgresProofRetainsNoVendorClusterGate(t *testing.T) {
	for _, key := range []string{"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13"} {
		t.Run(key, func(t *testing.T) {
			release, ok := platform.Lookup(key)
			if !ok || release.Server == nil {
				t.Fatal("native server layout missing")
			}
			major := strconv.Itoa(release.Server.PostgreSQLMajor)
			command := deployPostgresProofCommand(release)
			for _, required := range []string{"test \"$(cat " + nativeQuote(release.Server.PostgreSQLDataDirectory+"/PG_VERSION") + ")\" = " + major, "test ! -e /etc/postgresql/" + major + "/main", "test ! -e /var/lib/postgresql/" + major + "/main", "postgresql@" + major + "-main.service", release.Server.PostgreSQLSocketDirectory + "/.s.PGSQL." + release.Server.PostgreSQLPort, "/etc/postgresql/*/main /var/lib/postgresql/*/main", "--unit='postgresql@*-main.service'"} {
				if !strings.Contains(command, required) {
					t.Fatalf("native Debian-family proof omits %s", required)
				}
			}
			if strings.Contains(command, "getenforce") || strings.Contains(command, "= postgresql_t") {
				t.Fatal("RPM vendor-domain requirements escaped to Debian-family host")
			}
		})
	}
}

func TestNativePostgresProofUsesSelectedLayout(t *testing.T) {
	release := *platform.ForManifest("ubuntu", "24.04")
	server := *release.Server
	release.Server = &server
	server.PostgreSQLMajor = 42
	server.PostgreSQLDataDirectory = "/owned/custom-data"
	server.PostgreSQLSocketDirectory = "/run/custom-postgres"
	server.PostgreSQLBinDirectory = "/owned/custom-bin/"
	server.PostgreSQLPort = "25432"
	command := deployPostgresProofCommand(&release)
	for _, required := range []string{"test \"$(cat '/owned/custom-data/PG_VERSION')\" = 42", "/etc/postgresql/42/main", "/var/lib/postgresql/42/main", "postgresql@42-main.service", "/run/custom-postgres/.s.PGSQL.25432", "runuser -u postgres -- '/owned/custom-bin/psql'", "server_version_num", "-h '/run/custom-postgres' -p '25432' -d postgres"} {
		if !strings.Contains(command, required) {
			t.Fatalf("selected native layout omitted %s", required)
		}
	}
	for _, obsolete := range []string{"/var/lib/postgresql/lindm", "/run/lindm-postgresql", "postgresql@16-main.service", "/etc/postgresql/16/main"} {
		if strings.Contains(command, obsolete) {
			t.Fatalf("proof retained hardcoded layout %s", obsolete)
		}
	}
}

func TestDeployStorageObservation(t *testing.T) {
	for _, test := range []struct {
		body string
		want *VMDeployStorageEvidence
	}{
		{"8943566848\n4096 33554432 18000000\n", &VMDeployStorageEvidence{DatabaseBytes: 8943566848, FilesystemBytes: 128 << 30, AvailableBytes: 73728000000}},
		{"1\n4096 1 0\n", &VMDeployStorageEvidence{DatabaseBytes: 1, FilesystemBytes: 4096}},
		{"", nil},
		{"0\n4096 1 0\n", nil},
		{"-1\n4096 1 0\n", nil},
		{"9223372036854775808\n4096 1 0\n", nil},
		{"1\n4096 18446744073709551615 0\n", nil},
		{"1\n4096 1 2\n", nil},
		{"1\n0 1 0\n", nil},
		{"8943566848\n4096 33554432 18000000\nprivate diagnostic", nil},
	} {
		got, err := parseDeployStorage([]byte(test.body))
		if test.want == nil {
			if got != nil || err != errDeployStorage {
				t.Fatal("invalid storage observation did not return the secret-safe typed refusal")
			}
		} else if err != nil || got == nil || *got != *test.want {
			t.Errorf("storage=%+v, error=%v; want=%+v", got, err, test.want)
		}
	}
}
