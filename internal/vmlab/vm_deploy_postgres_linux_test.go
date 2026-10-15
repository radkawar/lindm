// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"strings"
	"testing"

	"lindm/internal/platform"
)

func TestNativeRHELPostgresProofRequiresActualEnforcingDomain(t *testing.T) {
	command := deployPostgresProofCommand(platform.ForManifest("rhel", "9"))
	for _, required := range []string{"systemctl is-active --quiet lindm-postgresql.service", "$(getenforce)\" = Enforcing", "--property=NoNewPrivileges --value lindm-postgresql.service)\" = no", "--property=MainPID", "/proc/$pid/attr/current", "= postgresql_t", "/proc/$pid/status", "NoNewPrivs:", "test \"$nnp\" = 0"} {
		if !strings.Contains(command, required) {
			t.Fatalf("native RHEL confinement proof omits %s", required)
		}
	}
}

func TestNativeUbuntuPostgresProofRetainsNoVendorClusterGate(t *testing.T) {
	command := deployPostgresProofCommand(platform.ForManifest("ubuntu", "24.04"))
	for _, required := range []string{"test ! -e /etc/postgresql/16/main", "test ! -e /var/lib/postgresql/16/main", "postgresql@16-main.service"} {
		if !strings.Contains(command, required) {
			t.Fatalf("native Ubuntu proof omits %s", required)
		}
	}
	if strings.Contains(command, "getenforce") || strings.Contains(command, "= postgresql_t") {
		t.Fatal("RHEL vendor-domain requirements escaped to Ubuntu")
	}
}
