// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

// This protects isolated lanes from depending on the mutable shared server
// schema or requiring offline signing keys merely to read public provisioning.
func TestAuthorityConfigurationIgnoresSharedServerSchema(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".cache"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "deploy", "dev"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deploy", "dev", "compose.yml"), []byte("services: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initialize(root, "keycloak"); err != nil {
		t.Fatal(err)
	}
	if err := Trust(t.Context(), root); err != nil {
		t.Fatal(err)
	}
	shared := FixturePath(root)
	oldSchema := []byte(`{"intentionally_obsolete_server_schema":true}`)
	if err := os.WriteFile(filepath.Join(shared, "server.json"), oldSchema, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := readManifest(shared)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(oldSchema)
	manifest.Files["server.json"] = hex.EncodeToString(digest[:])
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "manifest.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"execution-key-0.pem", "execution-key-1.pem", "execution-key-2.pem", "release-key.pem"} {
		if err := os.Remove(filepath.Join(shared, "agent-trust", name)); err != nil {
			t.Fatal(err)
		}
	}
	material, err := ReadPublicAgentFixture(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := authorityDocument(t.Context(), filepath.Join(t.TempDir(), "server.json"), shared, material)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Proto.GetDeploymentId() == "" || doc.Proto.GetAuthentication().GetKeycloak().GetIssuer() != issuer || doc.Proto.GetDatabase().GetMaxConnections() != 4 || doc.Proto.GetDatabase().GetAdminConnections() != 2 {
		t.Fatal("isolated configuration lost its fixture binding")
	}
	// The dedicated cluster changes only the generated document's database
	// credential. Resolving it must not consult even a valid shared URL.
	sharedURLPath := filepath.Join(shared, "migration-database-url")
	sharedURL, err := os.ReadFile(sharedURLPath)
	if err != nil {
		t.Fatal(err)
	}
	privateURL, err := url.Parse(string(sharedURL))
	if err != nil {
		t.Fatal(err)
	}
	privateURL.Host = "localhost:35432"
	privateURL.User = url.UserPassword("lindm_migrator", "dedicated-test-password")
	privateURLPath := filepath.Join(t.TempDir(), "migration-database-url")
	if err := os.WriteFile(privateURLPath, []byte(privateURL.String()), 0600); err != nil {
		t.Fatal(err)
	}
	doc.Proto.Database.MigrationUrlFile = proto.String(privateURLPath)
	database, err := doc.MigrationDatabase()
	if err != nil {
		t.Fatal(err)
	}
	if database.ConnConfig.Port != 35432 || database.ConnConfig.User != "lindm_migrator" || database.ConnConfig.Password != "dedicated-test-password" || database.ConnConfig.TLSConfig == nil || database.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("dedicated generated configuration did not isolate its TLS database credential")
	}
	unchanged, err := os.ReadFile(sharedURLPath)
	if err != nil || string(unchanged) != string(sharedURL) {
		t.Fatal("dedicated configuration changed shared credentials")
	}
	if _, err := ReadAgentFixture(t.Context(), root); err == nil {
		t.Fatal("shared-server reader accepted invalid retained configuration")
	}
}
