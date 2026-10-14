// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestBackupInventoriesIndependentAdminTLSWithCredentialCustody(t *testing.T) {
	base := rootRestoreDirectory(t)
	stage := filepath.Join(base, "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &configv1.ServerConfig{
		Tls:          &configv1.TLSConfig{CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		AdminTls:     &configv1.TLSConfig{CertificateFile: "admin.crt", PrivateKeyFile: "admin.key"},
		AdminCaFile:  proto.String("console-ca.crt"),
		Database:     &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("migration-url")},
		Integrations: &configv1.IntegrationsConfig{EncryptionKeyFile: "integrations.key"},
	}
	r := &resourceSet{
		config: cfg, base: base, stage: stage,
		files: map[string]string{}, metadata: map[string]os.FileInfo{},
		owners:              map[uint32]bool{0: true, 61001: true},
		databaseCredentials: map[string]bool{filepath.Join(base, "database-url"): true, filepath.Join(base, "migration-url"): true},
	}
	files := []string{"server.crt", "server.key", "admin.crt", "admin.key", "console-ca.crt", "database-url", "migration-url", "integrations.key"}
	for _, name := range files {
		uid, gid := 61001, 61001
		content := []byte("independently retained " + name)
		if name == "database-url" || name == "migration-url" || name == "integrations.key" {
			uid, gid = 0, 0
		}
		if name == "integrations.key" {
			content = bytes.Repeat([]byte{0x41}, 32)
		}
		writeRestoreFixture(t, filepath.Join(base, name), content, uid, gid)
	}
	if err := r.inventory(cfg.ProtoReflect()); err != nil {
		t.Fatal(err)
	}
	if len(r.files) != len(files) {
		t.Fatalf("backup retained %d references, want %d", len(r.files), len(files))
	}
	for _, name := range files {
		path := filepath.Join(base, name)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(r.files[path])
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("backup changed or omitted %s: %v", name, err)
		}
		original, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want, ok := original.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("original file has no native custody metadata: %s", name)
		}
		got, ok := r.metadata[path].Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("backup file has no native custody metadata: %s", name)
		}
		if want.Uid != got.Uid || want.Gid != got.Gid || want.Mode != got.Mode {
			t.Fatalf("backup lost original custody metadata for %s", name)
		}
	}
	cloned := proto.CloneOf(cfg)
	if err := r.rewrite(cloned.ProtoReflect()); err != nil {
		t.Fatal(err)
	}
	if cloned.GetAdminTls().GetCertificateFile() != r.files[filepath.Join(base, "admin.crt")] || cloned.GetAdminTls().GetPrivateKeyFile() != r.files[filepath.Join(base, "admin.key")] || cloned.GetAdminCaFile() != r.files[filepath.Join(base, "console-ca.crt")] {
		t.Fatal("archive validation did not resolve all three console identity resources")
	}
}
