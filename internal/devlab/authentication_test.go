// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lindm/internal/config"
)

func TestFixtureAuthenticationModes(t *testing.T) {
	for _, mode := range []string{"local", "keycloak"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, ".cache"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := initialize(root, mode); err != nil {
				t.Fatal(err)
			}
			dir := FixturePath(root)
			document, err := config.Load(filepath.Join(dir, "server.json"))
			if err != nil {
				t.Fatal(err)
			}
			local := document.Proto.GetAuthentication().GetLocal() != nil
			if local != (mode == "local") {
				t.Fatalf("local authentication = %t for mode %s", local, mode)
			}
			if mode == "keycloak" && document.Proto.GetAuthentication().GetKeycloak().GetIssuer() != issuer {
				t.Fatal("Keycloak fixture lost its pinned issuer")
			}
			for _, name := range []string{"realm.json", "owner-password", "console-secret", "directory-secret", "lab-admin-secret",
				"broker-realm.json", "broker-upstream-realm.json", "broker-directory-secret", "broker-admin-secret", "broker-upstream-directory-secret", "broker-upstream-admin-secret"} {
				_, err := os.Stat(filepath.Join(dir, name))
				if local && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("local fixture unexpectedly provisioned %s: %v", name, err)
				}
				if !local && err != nil {
					t.Fatalf("Keycloak fixture missing %s: %v", name, err)
				}
			}
			if err := initialize(root, mode); err != nil {
				t.Fatalf("unchanged fixture reuse: %v", err)
			}
			other := "local"
			if local {
				other = "keycloak"
			}
			if err := initialize(root, other); err == nil {
				t.Fatal("changed authentication mode was accepted")
			}
			if err := requireKeycloakFixture(dir); (err != nil) != local {
				t.Fatalf("Keycloak-specific check guard = %v for mode %s", err, mode)
			}
		})
	}
}

func TestFixtureRejectsUnsupportedAuthentication(t *testing.T) {
	root := t.TempDir()
	if err := initialize(root, "entra"); err == nil {
		t.Fatal("unsupported development authentication accepted")
	}
	if _, err := os.Stat(FixturePath(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid mode created a fixture: %v", err)
	}
}
