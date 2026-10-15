// SPDX-License-Identifier: Apache-2.0

package platform

import "testing"

func TestDeployServerHostBoundary(t *testing.T) {
	for _, release := range Releases() {
		serverRelease := release.Key == "ubuntu-24.04" || release.Key == "rhel-9"
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
