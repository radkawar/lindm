//go:build linux

package releasebuild

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceDigestMatchesCapturedTreeAndChanges(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	for _, name := range []string{"a/file.go", "a.c", "a-/file.go", "web/source.js", "web/dist/ignored.js", ".cache/ignored"} {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := SourceDigest(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(capture, 0700); err != nil {
		t.Fatal(err)
	}
	if err := snapshot(t.Context(), source, capture); err != nil {
		t.Fatal(err)
	}
	captured, err := treeDigest(capture)
	if err != nil || captured != digest {
		t.Fatalf("streamed digest %s does not match captured tree %s: %v", digest, captured, err)
	}
	if err := os.WriteFile(filepath.Join(source, "web/dist/ignored.js"), []byte("different generated output"), 0600); err != nil {
		t.Fatal(err)
	}
	ignored, err := SourceDigest(t.Context(), source)
	if err != nil || ignored != digest {
		t.Fatalf("generated output changed source digest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "a/file.go"), []byte("changed source"), 0755); err != nil {
		t.Fatal(err)
	}
	changed, err := SourceDigest(t.Context(), source)
	if err != nil || changed == digest {
		t.Fatalf("source change did not invalidate digest: %v", err)
	}
}

func TestSourceDigestRefusesLinksAndHonorsCancellation(t *testing.T) {
	source := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", source).CombinedOutput(); err != nil {
		t.Fatalf("initialize source: %v: %s", err, output)
	}
	if err := os.Symlink("outside", filepath.Join(source, "source.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := SourceDigest(t.Context(), source); err == nil {
		t.Fatal("accepted a source symlink")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := SourceDigest(ctx, source); err == nil {
		t.Fatal("ignored cancellation")
	}
}
