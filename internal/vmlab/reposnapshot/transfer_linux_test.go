//go:build linux

package reposnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

// This is framing input only, not a signed repository or native closure proof.
func transferFixture(t *testing.T, change func(*labv1.RepositorySnapshotManifest)) (*labv1.RepositorySnapshotManifest, []byte) {
	t.Helper()
	sum := sha256.Sum256([]byte("rpm"))
	manifest := &labv1.RepositorySnapshotManifest{
		MaxBytes: 1024, MaxPackages: 1, TotalBytes: 3,
		Files: []*labv1.RepositorySnapshotFile{{Path: "aarch64/a.rpm", Sha256: hex.EncodeToString(sum[:]), SizeBytes: 3}},
	}
	if change != nil {
		change(manifest)
	}
	digest, err := identity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSha256 = digest
	data, err := protojson.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.BigEndian, uint32(len(data))); err != nil {
		t.Fatal(err)
	}
	wire.Write(data)
	return manifest, wire.Bytes()
}

func TestSnapshotTransferChecksManifestBeforePayload(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*labv1.RepositorySnapshotManifest)
	}{
		{"aggregate-limit", func(m *labv1.RepositorySnapshotManifest) { m.MaxBytes = HardMaxBytes + 1 }},
		{"oversized-file", func(m *labv1.RepositorySnapshotManifest) { m.Files[0].SizeBytes = 1025 }},
		{"outside-root", func(m *labv1.RepositorySnapshotManifest) { m.Files[0].Path = "../a.rpm" }},
		{"duplicate-file", func(m *labv1.RepositorySnapshotManifest) { m.Files = append(m.Files, m.Files[0]) }},
		{"incorrect-total", func(m *labv1.RepositorySnapshotManifest) { m.TotalBytes++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest, header := transferFixture(t, tc.change)
			reader := bytes.NewReader(append(header, []byte("unread payload")...))
			if _, _, err := readTransferManifest(reader, manifest.GetManifestSha256()); err == nil {
				t.Fatal("invalid manifest accepted")
			}
			if reader.Len() != len("unread payload") {
				t.Fatal("payload read before manifest admission")
			}
		})
	}
}

func TestSnapshotTransferManifestLengthIsBounded(t *testing.T) {
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.BigEndian, uint32(maxManifestBytes+1)); err != nil {
		t.Fatal(err)
	}
	wire.WriteString("unread")
	if _, _, err := readTransferManifest(&wire, strings.Repeat("a", 64)); err == nil {
		t.Fatal("unbounded manifest accepted")
	}
	if wire.String() != "unread" {
		t.Fatal("oversized manifest was consumed")
	}
}

func TestSnapshotTransferRejectsExtraTruncatedAndCorruptBytes(t *testing.T) {
	for _, payload := range []string{"rp", "bad", "rpmEXTRA"} {
		t.Run(payload, func(t *testing.T) {
			manifest, header := transferFixture(t, nil)
			reader := bytes.NewReader(append(header, payload...))
			cache := t.TempDir()
			if err := Import(context.Background(), cache, manifest.GetManifestSha256(), reader); err == nil {
				t.Fatal("invalid stream accepted")
			}
			if payload == "rpmEXTRA" && reader.Len() != len("XTRA") {
				t.Fatal("unlisted content was downloaded beyond the one-byte EOF check")
			}
			if _, err := os.Lstat(filepath.Join(cache, "repository-snapshots", "sha256", manifest.GetManifestSha256())); !os.IsNotExist(err) {
				t.Fatalf("invalid stream published: %v", err)
			}
		})
	}
}

func TestSnapshotTransferFramingCannotReplaceVendorAuthentication(t *testing.T) {
	manifest, header := transferFixture(t, nil)
	cache := t.TempDir()
	if err := Import(context.Background(), cache, manifest.GetManifestSha256(), bytes.NewReader(append(header, "rpm"...))); err == nil {
		t.Fatal("content-addressed but unsigned closure accepted")
	}
	if _, err := os.Lstat(filepath.Join(cache, "repository-snapshots", "sha256", manifest.GetManifestSha256())); !os.IsNotExist(err) {
		t.Fatalf("unauthenticated stream published: %v", err)
	}
}
