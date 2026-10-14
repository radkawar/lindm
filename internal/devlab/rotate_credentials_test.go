// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationInstallsDerivedFilesAndManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dev")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old := rotatedFixtureFiles(dir, map[string]string{"postgres-password": "old-p", "migrator-password": "old-m", "runtime-password": "old-r"})
	m := manifest{Version: fixtureVersion, Directory: dir, Files: map[string]string{"server.json": "kept"}}
	for name, data := range old {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		m.Files[name] = "stale"
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}

	files := rotatedFixtureFiles(dir, map[string]string{"postgres-password": "new-p", "migrator-password": "new-m", "runtime-password": "new-r"})
	if len(files) != len(old) {
		t.Fatalf("rotation writes %d files, creation %d", len(files), len(old))
	}
	if !strings.Contains(string(files["migration-database-url"]), "lindm_migrator:new-m@") || !strings.Contains(string(files["database-init.sql"]), "PASSWORD 'new-r'") {
		t.Fatal("derived files do not carry the new passwords")
	}
	staged, err := stageFixtureFiles(dir, files)
	if err != nil {
		t.Fatal(err)
	}
	if err := installFixtureFiles(dir, staged, files); err != nil {
		t.Fatal(err)
	}
	got, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Files["server.json"] != "kept" {
		t.Fatal("rotation dropped an unrelated manifest entry")
	}
	for name, want := range files {
		data, err := readOwned(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if string(data) != string(want) || got.Files[name] != hex.EncodeToString(digest[:]) {
			t.Fatalf("%s not installed with a matching manifest digest", name)
		}
	}
	if entries, err := os.ReadDir(staged); err != nil || len(entries) != 0 {
		t.Fatalf("staging directory retains %d entries: %v", len(entries), err)
	}
}
