//go:build linux

package reposnapshot

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
)

func retainedFixture(t *testing.T, root, name string, data []byte) *labv1.RepositorySnapshotFile {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return &labv1.RepositorySnapshotFile{Path: name, Sha256: hex.EncodeToString(sum[:]), SizeBytes: uint64(len(data))}
}

func TestSealedMetadataRejectsMutationAndReplacement(t *testing.T) {
	directory := t.TempDir()
	item := retainedFixture(t, directory, "repodata/primary", []byte("vendor"))
	root, err := openSnapshotRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	original, err := os.OpenFile(filepath.Join(directory, item.Path), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := original.Close(); err != nil {
			t.Error(err)
		}
	}()
	sealed, err := sealRetained(root, item, maxPrimaryBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealed.Close() }()
	// Mutation through a previously opened writer cannot change authenticated
	// bytes used by a later signature/checksum/parser stage.
	if _, err := original.WriteAt([]byte("mutant"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "replacement"), []byte("rogue!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "replacement"), filepath.Join(directory, item.Path)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "vendor" {
		t.Fatalf("sealed authenticated bytes changed: %q", got)
	}
	if _, err := sealed.WriteAt([]byte("evil!!"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("immutable descriptor accepted write: %v", err)
	}
	if _, err := sealRetained(root, item, maxPrimaryBytes); err == nil {
		t.Fatal("replacement pathname passed retained identity")
	}
}

func TestOneStreamBindsManifestAndSignedChecksums(t *testing.T) {
	directory := t.TempDir()
	unauthorized := []byte("rogue!")
	authentic := []byte("vendor")
	item := retainedFixture(t, directory, "aarch64/example.rpm", unauthorized)
	signedDigest := sha512.Sum512(authentic)
	signed := checksum{Type: "sha512", Value: hex.EncodeToString(signedDigest[:])}
	root, err := openSnapshotRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := checkRetained(root, item, &signed, item.SizeBytes); err == nil {
		t.Fatal("manifest-matching unauthorized bytes passed vendor authentication")
	}
	if err := os.WriteFile(filepath.Join(directory, item.Path), authentic, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkRetained(root, item, &signed, item.SizeBytes); err == nil {
		t.Fatal("vendor bytes passed different manifest identity")
	}
}

func TestRepositoryOpensRejectAllSymlinkComponents(t *testing.T) {
	directory := t.TempDir()
	retainedFixture(t, directory, "real/file", []byte("content"))
	if err := os.Symlink("real", filepath.Join(directory, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real/file", filepath.Join(directory, "file-alias")); err != nil {
		t.Fatal(err)
	}
	root, err := openSnapshotRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{"alias/file", "file-alias"} {
		if file, err := openRelative(root, name, false); err == nil {
			_ = file.Close()
			t.Fatalf("symlink accepted: %s", name)
		}
	}
}

func TestRetainedTreeRejectsExtraContent(t *testing.T) {
	directory := t.TempDir()
	item := retainedFixture(t, directory, "aarch64/example.rpm", []byte("vendor"))
	if err := os.Chmod(filepath.Join(directory, item.Path), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unlisted"), []byte("extra"), 0400); err != nil {
		t.Fatal(err)
	}
	root, err := openSnapshotRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := validateRetainedTree(root, &labv1.RepositorySnapshotManifest{Files: []*labv1.RepositorySnapshotFile{item}}); err == nil {
		t.Fatal("unlisted bytes escaped closure bounds")
	}
}

func TestCaptureOpenKeyBindsTransferredBytes(t *testing.T) {
	root := t.TempDir()
	item := retainedFixture(t, root, "repodata/repomd.xml.key", []byte("original-key"))
	capture := Capture{Root: root, Manifest: &labv1.RepositorySnapshotManifest{Files: []*labv1.RepositorySnapshotFile{item}}}
	key, err := capture.OpenKey(item.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = key.Close() }()
	if err := os.WriteFile(filepath.Join(root, item.Path), []byte("replaced-key"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(key)
	if err != nil || string(data) != "original-key" {
		t.Fatalf("transferred key changed: %q, %v", data, err)
	}
	if file, err := capture.OpenKey(item.Path); err == nil {
		_ = file.Close()
		t.Fatal("accepted changed authenticated key")
	}
	if file, err := capture.OpenKey("repodata/unlisted.key"); err == nil {
		_ = file.Close()
		t.Fatal("accepted unlisted trust key")
	}
}
