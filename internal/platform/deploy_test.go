// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"slices"
	"strings"
	"testing"
)

func TestDeployServerHostBoundary(t *testing.T) {
	for _, release := range Releases() {
		serverRelease := slices.Contains([]string{"ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13", "rhel-9", "rhel-10", "rocky-9", "rocky-10", "almalinux-9", "almalinux-10"}, release.Key)
		if (release.Server != nil) != serverRelease {
			t.Errorf("server installation facts leaked or missing for %s", release.Key)
		}
		for _, architecture := range []string{"x86_64", "aarch64"} {
			supported := architecture == "x86_64" && serverRelease
			reason := release.LaneGateOn(LaneDeploy, architecture)
			if supported {
				if reason != "" {
					t.Errorf("supported server %s/%s gated: %s", release.Key, architecture, reason)
				}
				if err := release.LabLaneOn(LaneDeploy, architecture); err != nil {
					t.Errorf("supported server %s/%s rejected: %v", release.Key, architecture, err)
				}
			} else if reason == "" {
				t.Errorf("device target %s/%s lacks explicit unsupported server host reason", release.Key, architecture)
			}
		}
	}
}

func TestServerInstallationNativeLayouts(t *testing.T) {
	for _, test := range []struct {
		key, snapshot, data, bin, port, socket, format string
	}{
		{"ubuntu-24.04", "ubuntu24.04.snapshot", "/var/lib/postgresql/lindm", "/usr/lib/postgresql/16/bin/", "15432", "/run/lindm-postgresql", "deb"},
		{"rhel-9", "rhel9.snapshot", "/var/lib/pgsql/lindm", "/usr/bin/", "5432", "/run/postgresql/lindm", "rpm"},
		{"ubuntu-22.04", "ubuntu22.04.snapshot", "/var/lib/postgresql/lindm", "/usr/lib/postgresql/16/bin/", "15432", "/run/lindm-postgresql", "deb"},
		{"ubuntu-26.04", "ubuntu26.04.snapshot", "/var/lib/postgresql/lindm", "/usr/lib/postgresql/18/bin/", "15432", "/run/lindm-postgresql", "deb"},
		{"debian-12", "debian12.snapshot", "/var/lib/postgresql/lindm", "/usr/lib/postgresql/16/bin/", "15432", "/run/lindm-postgresql", "deb"},
		{"debian-13", "debian13.snapshot", "/var/lib/postgresql/lindm", "/usr/lib/postgresql/17/bin/", "15432", "/run/lindm-postgresql", "deb"},
		{"rhel-10", "rhel10.snapshot", "/var/lib/pgsql/lindm", "/usr/bin/", "5432", "/run/postgresql/lindm", "rpm"},
		{"rocky-9", "rocky9.snapshot", "/var/lib/pgsql/lindm", "/usr/bin/", "5432", "/run/postgresql/lindm", "rpm"},
		{"rocky-10", "rocky10.snapshot", "/var/lib/pgsql/lindm", "/usr/bin/", "5432", "/run/postgresql/lindm", "rpm"},
		{"almalinux-9", "almalinux9.snapshot", "/var/lib/pgsql/lindm", "/usr/bin/", "5432", "/run/postgresql/lindm", "rpm"},
		{"almalinux-10", "almalinux10.snapshot", "/var/lib/pgsql/lindm", "/usr/bin/", "5432", "/run/postgresql/lindm", "rpm"},
	} {
		release, ok := Lookup(test.key)
		if !ok || release.Server == nil {
			t.Fatalf("missing server recipe for %s", test.key)
		}
		server := release.Server
		if server.SnapshotName != test.snapshot || server.PostgreSQLDataDirectory != test.data || server.PostgreSQLBinDirectory != test.bin || server.PostgreSQLPort != test.port || server.PostgreSQLSocketDirectory != test.socket || release.Packages.Backend.PackageFormat() != test.format {
			t.Errorf("wrong native server layout for %s: %+v", test.key, server)
		}
	}
}

func TestServerRecipesHaveExplicitDatabaseAndQualificationPolicy(t *testing.T) {
	for _, release := range Releases() {
		server := release.Server
		if server == nil {
			continue
		}
		if !PostgreSQLMajorSupported(server.PostgreSQLMajor) || len(server.Architectures) == 0 || server.Status == "" {
			t.Errorf("%s lacks explicit server policy: %+v", release.Key, server)
		}
		if release.Key == "debian-13" {
			if !server.ConnectedOnly || server.Status != "Qualified" {
				t.Errorf("Debian 13 lost its connected-only native lifecycle qualification")
			}
			continue
		}
		if release.Key != "ubuntu-24.04" && release.Key != "rhel-9" && (!server.ConnectedOnly || server.Status != "Not yet qualified") {
			t.Errorf("unproven platform %s promoted without its full lifecycle proof", release.Key)
		}
	}
}

func TestServerSupportDocsDistinguishRecipeFromQualification(t *testing.T) {
	body, err := serverSupportTable("docs/platforms/")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"PostgreSQL", "Lifecycle", "Not yet qualified", "Ubuntu 24.04", "Debian 13", "17", "18"} {
		if !strings.Contains(body, required) {
			t.Errorf("server table omits %q", required)
		}
	}
	if strings.Contains(body, "Fedora") || strings.Contains(body, "Linux Mint") {
		t.Fatal("device-only release appears as a server recipe")
	}
}
