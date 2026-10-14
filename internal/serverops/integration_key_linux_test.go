// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestIntegrationKeyInventoryRequiresExactRootCustody(t *testing.T) {
	directory := rootRestoreDirectory(t)
	for _, kind := range []string{"valid", "missing", "short", "long", "readable", "special mode", "service owner", "service group", "hardlink", "symlink", "service ancestry"} {
		t.Run(kind, func(t *testing.T) {
			base := filepath.Join(directory, kind)
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "integrations.key")
			key := bytes.Repeat([]byte{0x31}, 32)
			switch kind {
			case "short":
				key = key[:31]
			case "long":
				key = append(key, 0)
			}
			if kind != "missing" {
				writeRestoreFixture(t, path, key, 0, 0)
			}
			switch kind {
			case "readable":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "special mode":
				if err := os.Chmod(path, 0600|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			case "service owner":
				if err := os.Chown(path, 61001, 0); err != nil {
					t.Fatal(err)
				}
			case "service group":
				if err := os.Chown(path, 0, 61001); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			case "service ancestry":
				if err := os.Chown(base, 61001, 61001); err != nil {
					t.Fatal(err)
				}
			}
			stage := filepath.Join(directory, "stage-"+kind)
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := restoreConfigFixture("database-url", false)
			cfg.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: path}
			r := &resourceSet{config: cfg, files: map[string]string{}, metadata: map[string]os.FileInfo{}, owners: map[uint32]bool{0: true, 61001: true}, base: base, stage: stage}
			err := r.inventory(cfg.Integrations.ProtoReflect())
			if kind != "valid" {
				if err == nil {
					t.Fatal("unsafe integration key inventoried")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := r.read(path, 32)
			if err != nil || !bytes.Equal(data, key) {
				t.Fatal("inventory did not preserve exact key")
			}
			clear(data)
		})
	}
}

func TestArchivedIntegrationKeyCannotBeMissingUnsafeOrCorrupt(t *testing.T) {
	directory := rootRestoreDirectory(t)
	path := filepath.Join(directory, "integrations.key")
	staged := filepath.Join(directory, "archived-key")
	key := bytes.Repeat([]byte{0x32}, 32)
	writeRestoreFixture(t, staged, key, 0, 0)
	cfg := restoreConfigFixture("database-url", false)
	cfg.Integrations = &configv1.IntegrationsConfig{EncryptionKeyFile: path}
	r := &resourceSet{config: cfg, files: map[string]string{path: staged}, owners: map[uint32]bool{0: true}, base: directory, archived: true}
	entry := archiveFile{Path: path, Owner: "root", Group: "root", Mode: 0600, Size: 32}
	for _, kind := range []string{"valid", "missing", "owner", "group", "mode", "size", "truncated", "linked"} {
		t.Run(kind, func(t *testing.T) {
			manifest := archiveManifest{Files: []archiveFile{entry}}
			switch kind {
			case "missing":
				manifest.Files = nil
			case "owner":
				manifest.Files[0].Owner = "nobody"
			case "group":
				manifest.Files[0].Group = "nogroup"
			case "mode":
				manifest.Files[0].Mode = 0644
			case "size":
				manifest.Files[0].Size = 31
			case "truncated":
				writeRestoreFixture(t, staged, key[:31], 0, 0)
				t.Cleanup(func() { writeRestoreFixture(t, staged, key, 0, 0) })
			case "linked":
				if err := os.Link(staged, staged+".link"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Remove(staged + ".link"); err != nil {
						t.Error(err)
					}
				})
			}
			err := r.validateArchivedIntegrationKey(manifest)
			if (err == nil) != (kind == "valid") {
				t.Fatal("incorrect archived integration key admission")
			}
		})
	}
	cfg.Integrations = nil
	if err := r.validateArchivedIntegrationKey(archiveManifest{}); err != nil {
		t.Fatal("old unconfigured archive rejected")
	}
}

func TestIntegrationKeyArchiveRejectsSameLengthCorruption(t *testing.T) {
	manifest, resources, dump := archiveFixture(t)
	key := bytes.Repeat([]byte{0x33}, 32)
	digest := sha256.Sum256(key)
	manifest.Files = append(manifest.Files, archiveFile{Path: "/etc/lindm/integrations.key", SHA256: hex.EncodeToString(digest[:]), Owner: "root", Group: "root", Mode: 0600, Size: 32})
	configData, err := os.ReadFile(resources.files[manifest.ConfigPath])
	if err != nil {
		t.Fatal(err)
	}
	dumpData, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	headers := []*tar.Header{
		{Name: "database.dump", Typeflag: tar.TypeReg, Size: int64(len(dumpData))},
		{Name: "files/etc/lindm/server.json", Typeflag: tar.TypeReg, Size: int64(len(configData))},
		{Name: "files/etc/lindm/integrations.key", Typeflag: tar.TypeReg, Size: 32},
	}
	key[0] ^= 1
	encoded := rawArchive(t, manifest, headers, [][]byte{dumpData, configData, key})
	if _, err := extractArchive(bytes.NewReader(encoded), t.TempDir()); err == nil {
		t.Fatal("corrupted integration key passed archive authentication inventory")
	}
}
