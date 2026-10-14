// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestImportCacheAuthenticatesAndPreservesPublishedBytes(t *testing.T) {
	fixture := newSigningFixture(t)
	image := []byte("rsync-staged official image fixture\n")
	manifest := testManifest(image, fixture.primary, labv1.ChecksumMode_CHECKSUM_MODE_DETACHED)
	checksums, signature := fixture.signed(t, manifest, checksumText(manifest))
	source := filepath.Join(t.TempDir(), "staged")
	root, err := openCache(context.Background(), source, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(source, "sha256-"+manifest.Sha256)
	if err := os.Mkdir(entry, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"image": image, "checksums": checksums, "key": fixture.key, "signature": signature} {
		if err := os.WriteFile(filepath.Join(entry, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(t.TempDir(), "cache")
	if err := InitializeImageCache(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(destination, "repository-snapshots"), 0700); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 3 {
		group.Go(func() {
			if _, err := ImportCache(context.Background(), manifest, source, destination); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	verified, err := ImportCache(context.Background(), manifest, filepath.Join(t.TempDir(), "absent-source"), destination)
	if err != nil {
		t.Fatalf("reuse verified persistent cache without restaging: %v", err)
	}
	before, err := os.Stat(verified.Path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0444 {
		t.Fatalf("published image remains writable: %v", before.Mode())
	}
	if err := os.Chmod(verified.Path, 0600); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(image)
	corrupt[0] ^= 1
	if err := os.WriteFile(verified.Path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportCache(context.Background(), manifest, source, destination); err == nil {
		t.Fatal("corrupt persistent entry was replaced or trusted")
	}
	observed, err := os.ReadFile(verified.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(observed, corrupt) {
		t.Fatal("import repaired corrupt bytes without operator consent")
	}
	if err := os.WriteFile(filepath.Join(entry, "image"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(t.TempDir(), "fresh")
	if _, err := ImportCache(context.Background(), manifest, source, fresh); err == nil {
		t.Fatal("unauthenticated staged bytes accepted")
	}
	if _, err := os.Stat(filepath.Join(fresh, "sha256-"+manifest.Sha256)); !os.IsNotExist(err) {
		t.Fatalf("failed import published an entry: %v", err)
	}
}

func TestInitializeImageCachePreservesUnmarkedDirectoryBoundary(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "unrelated"), []byte("owner data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeImageCache(context.Background(), directory); err == nil {
		t.Fatal("unmarked nonempty directory adopted")
	}
	if _, err := os.Stat(filepath.Join(directory, ".lindm-images")); !os.IsNotExist(err) {
		t.Fatalf("rejected directory was marked: %v", err)
	}
}
