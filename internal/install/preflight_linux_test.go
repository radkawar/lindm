// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRuntimeConfigPreflightUsesCompleteExplicitNativeCredentials(t *testing.T) {
	binary := "/var/lib/lindm-upgrade-verified/usr/bin/lindmd"
	args := runtimeConfigArguments(binary)
	for _, required := range []string{
		"--quiet", "--wait", "--collect", "--pipe",
		"--property=User=lindmd", "--property=Group=lindmd",
		"--property=LoadCredential=database-url:/etc/lindm/database-url",
		"--property=LoadCredential=integrations-key:/etc/lindm/integrations.key",
		"--property=UMask=0077", "--property=MemorySwapMax=0", "--property=LimitCORE=0",
		"--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes",
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
		"--property=InaccessiblePaths=-/etc/lindm/migrate",
	} {
		if !slices.Contains(args, required) {
			t.Errorf("runtime preflight omitted %s", required)
		}
	}
	wantCommand := []string{binary, "check-config", "-config", "/etc/lindm/server.json", "-database-url-credential", "database-url", "-integrations-key-credential", "integrations-key"}
	if len(args) < len(wantCommand) || !slices.Equal(args[len(args)-len(wantCommand):], wantCommand) {
		t.Fatal("runtime preflight did not explicitly select both credentials on the authenticated candidate")
	}
}

func TestIncapableTargetPreflightRetainsExistingIntegrationKey(t *testing.T) {
	root := rootDatabaseFixture(t)
	path := filepath.Join(root, "integrations.key")
	key := bytes.Repeat([]byte{0x6b}, 32)
	if err := newFile(path, key, 0, 0, 0600); err != nil {
		t.Fatal(err)
	}
	// A successful executable with no credential-selection contract is not
	// sufficient capability evidence; neither package nor key state is touched.
	if err := integrationCredentialPreflight(t.Context(), "/bin/true"); err == nil {
		t.Fatal("incapable target executable passed the rollback preflight")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(key, after) {
		t.Fatal("capability refusal changed the persistent integration key")
	}
}

func TestBackupCapacityRetainsExactMeasuredBoundary(t *testing.T) {
	const database int64 = 5 << 30
	const needed uint64 = 14 << 30
	if err := checkBackupCapacity(database, needed); err != nil {
		t.Fatalf("exact twice-database-plus-4-GiB boundary refused: %v", err)
	}
	err := checkBackupCapacity(database, needed-1)
	want := fmt.Sprintf("insufficient backup disk: database=%d bytes, /var/backups free=%d bytes, required=%d bytes (twice database size plus 4 GiB); if the database shares this filesystem, also allow its database bytes plus operating-system and release files", database, needed-1, needed)
	if err == nil || err.Error() != want {
		t.Fatalf("capacity refusal does not state the measured database and available/required bytes: %v", err)
	}
	if err := checkBackupCapacity(0, 4<<30); err != nil {
		t.Fatalf("empty database lost the existing 4 GiB reserve: %v", err)
	}
	if err := checkBackupCapacity(0, (4<<30)-1); err == nil {
		t.Fatal("accepted an empty database without its existing reserve")
	}
}

func TestBackupCapacityRejectsSignedAndOverflowingDatabaseSizes(t *testing.T) {
	maximum := int64((^uint64(0) - (4 << 30)) / 2)
	for _, size := range []int64{-1, maximum + 1} {
		if err := checkBackupCapacity(size, ^uint64(0)); err == nil || err.Error() != "database size exceeds backup capacity bounds" {
			t.Fatalf("invalid database size was not refused before arithmetic: %v", err)
		}
	}
	if err := checkBackupCapacity(maximum, ^uint64(0)); err != nil {
		t.Fatalf("largest bounded database size refused: %v", err)
	}
}

func TestFreshDiskCapacityRefusesTwentyGiB(t *testing.T) {
	for _, test := range []struct {
		total, available uint64
		passed           bool
	}{
		{24 << 30, 16 << 30, true},
		{32 << 30, 24 << 30, true},
		{20 << 30, 20 << 30, false},
		{(24 << 30) - 1, 16 << 30, false},
		{24 << 30, (16 << 30) - 1, false},
		{24 << 30, 25 << 30, false},
	} {
		err := checkFreshDiskCapacity(test.total, test.available)
		if (err == nil) != test.passed {
			t.Errorf("filesystem=%d available=%d: capacity refusal=%v", test.total, test.available, err)
		}
		if err != nil {
			want := fmt.Sprintf("%s; /var filesystem=%d bytes, free=%d bytes", freshServerDiskRequirements, test.total, test.available)
			if err.Error() != want {
				t.Fatalf("fresh capacity refusal omitted concrete requirements and measured bytes: %v", err)
			}
		}
	}
	const measuredDatabase int64 = 1998378675
	if err := checkBackupCapacity(measuredDatabase, 8<<30); err != nil {
		t.Fatalf("existing installations lost the measured upgrade-only capacity rule: %v", err)
	}
}
