package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestDigestsCountEveryDigestOfAnySchema(t *testing.T) {
	dir := t.TempDir()
	image, closure, other := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	files := map[string]string{
		// Current schema.
		"current.json": `{"sha256":"` + image + `","repositorySnapshotManifestSha256":"` + closure + `"}`,
		// A stale worktree's manifest with a field this binary's schema rejects
		// still protects its image (upper-case digests included).
		"stale.json": `{"retiredField":true,"sha256":"` + strings.ToUpper(other) + `"}`,
		"notes.txt":  strings.Repeat("d", 64),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	referenced := map[string]bool{}
	if err := manifestDigests(dir, referenced); err != nil {
		t.Fatal(err)
	}
	if len(referenced) != 3 || !referenced[image] || !referenced[closure] || !referenced[other] {
		t.Fatalf("referenced %v", referenced)
	}
	if err := manifestDigests(filepath.Join(dir, "missing"), referenced); err != nil {
		t.Fatalf("a tree without manifests: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "huge.json"), make([]byte, maxManifestBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manifestDigests(dir, referenced); err == nil {
		t.Fatal("an unbounded manifest was read")
	}
}
