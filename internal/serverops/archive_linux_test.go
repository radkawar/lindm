// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

func archiveFixture(t *testing.T) (archiveManifest, *resourceSet, string) {
	t.Helper()
	directory := t.TempDir()
	config := []byte("protected configuration fixture\n")
	database := []byte("custom PostgreSQL archive parser is exercised separately by the real restore drill\n")
	configPath := filepath.Join(directory, "config.json")
	dump := filepath.Join(directory, "database.dump")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dump, database, 0600); err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(config)
	databaseHash := sha256.Sum256(database)
	manifest := archiveManifest{Format: 1, CapturedAt: time.Now().UTC(), Version: "0.1.1", DeploymentID: "a9dff5b8-966d-4bbd-a568-b613bc0d056e", PublicURL: "https://admin.example.invalid", DevicePublicURL: "https://devices.example.invalid", ConfigPath: "/etc/lindm/server.json", DatabaseSHA256: hex.EncodeToString(databaseHash[:]), SchemaMinimumRuntime: 51, SchemaVersions: []int64{49, 50, 51}, Files: []archiveFile{{Path: "/etc/lindm/server.json", SHA256: hex.EncodeToString(configHash[:]), Owner: "root", Group: "root", Mode: 0600, Size: int64(len(config))}}}
	return manifest, &resourceSet{files: map[string]string{"/etc/lindm/server.json": configPath}}, dump
}

func TestMaintainedAgeStreamRoundTripAndFinalAuthentication(t *testing.T) {
	manifest, resources, dump := archiveFixture(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "backup.tar.age")
	if err = encryptArchive(t.Context(), output, identity.Recipient(), manifest, resources, dump); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("protected configuration fixture")) {
		t.Fatal("plaintext configuration published")
	}
	plain, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		t.Fatal(err)
	}
	got, err := extractArchive(plain, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, plain); err != nil {
		t.Fatal(err)
	}
	if got.DatabaseSHA256 != manifest.DatabaseSHA256 || len(got.Files) != 1 {
		t.Fatal("archive inventory did not round trip")
	}
	for _, kind := range []string{"truncated", "modified"} {
		t.Run(kind, func(t *testing.T) {
			damaged := append([]byte(nil), encrypted...)
			if kind == "truncated" {
				damaged = damaged[:len(damaged)-1]
			} else {
				damaged[len(damaged)-1] ^= 1
			}
			reader, err := age.Decrypt(bytes.NewReader(damaged), identity)
			if err == nil {
				_, err = io.Copy(io.Discard, reader)
			}
			if err == nil {
				t.Fatal("unauthenticated final age chunk accepted")
			}
		})
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = age.Decrypt(bytes.NewReader(encrypted), other); err == nil {
		t.Fatal("wrong operator recipient accepted")
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("encrypted output not root/caller private")
	}
}

func rawArchive(t *testing.T, manifest archiveManifest, headers []*tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(data); err != nil {
		t.Fatal(err)
	}
	for i, header := range headers {
		if err = writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(bodies[i]) > 0 {
			if _, err = writer.Write(bodies[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestArchiveRejectsTraversalSymlinksDuplicateMissingAndBadSchema(t *testing.T) {
	base, _, _ := archiveFixture(t)
	cases := []struct {
		name   string
		change func(*archiveManifest)
		header *tar.Header
		body   []byte
	}{
		{name: "traversal", header: &tar.Header{Name: "files/../../outside", Mode: 0600, Size: 1}, body: []byte("x")},
		{name: "symlink", header: &tar.Header{Name: "files/etc/lindm/server.json", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}},
		{name: "unexpected", header: &tar.Header{Name: "untracked", Mode: 0600, Size: 1}, body: []byte("x")},
		{name: "missing"},
		{name: "duplicate inventory", change: func(m *archiveManifest) { m.Files = append(m.Files, m.Files[0]) }},
		{name: "unreleased legacy schema", change: func(m *archiveManifest) { m.SchemaMinimumRuntime = 50 }},
		{name: "unsorted schema", change: func(m *archiveManifest) { m.SchemaVersions = []int64{51, 50} }},
		{name: "invalid version", change: func(m *archiveManifest) { m.Version = "private-unvalidated-text" }},
		{name: "writable resource", change: func(m *archiveManifest) { m.Files[0].Mode = 0666 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			manifest.Files = append([]archiveFile(nil), base.Files...)
			if test.change != nil {
				test.change(&manifest)
			}
			var headers []*tar.Header
			var bodies [][]byte
			if test.header != nil {
				headers = append(headers, test.header)
				bodies = append(bodies, test.body)
			}
			encoded := rawArchive(t, manifest, headers, bodies)
			if _, err := extractArchive(bytes.NewReader(encoded), t.TempDir()); err == nil {
				t.Fatal("unsafe or incomplete archive accepted")
			}
		})
	}
}

func TestBoundedWriterNeverPublishesBeyondLimit(t *testing.T) {
	var buffer bytes.Buffer
	writer := boundedWriter{&buffer, 3}
	if _, err := writer.Write([]byte("abcd")); err == nil || buffer.Len() != 0 {
		t.Fatal("oversized write partially published")
	}
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("d")); err == nil || buffer.String() != "abc" {
		t.Fatal("capacity overflow")
	}
}
