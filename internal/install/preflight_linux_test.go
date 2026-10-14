// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
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
