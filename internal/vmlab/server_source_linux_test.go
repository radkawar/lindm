//go:build linux

package vmlab

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestServerSourceSnapshotRetainsBuildInputs(t *testing.T) {
	source := t.TempDir()
	for _, dir := range []string{"cmd", "internal", "db", "gen", "web/dist"} {
		if err := os.MkdirAll(filepath.Join(source, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"go.mod": "module lindm\n", "go.sum": "", "cmd/server.go": "original source\n", "web/dist/index.html": "embedded console\n"}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(source, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first := filepath.Join(t.TempDir(), "first")
	digest, err := snapshotServerSource(context.Background(), source, first)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(t.TempDir(), "second")
	same, err := snapshotServerSource(context.Background(), source, second)
	if err != nil {
		t.Fatal(err)
	}
	if digest != same {
		t.Fatal("identical working-tree bytes have different digests")
	}
	if err := os.WriteFile(filepath.Join(source, "cmd/server.go"), []byte("later source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("snapshot %s changed after source mutation", name)
		}
	}
	third := filepath.Join(t.TempDir(), "third")
	changed, err := snapshotServerSource(context.Background(), source, third)
	if err != nil {
		t.Fatal(err)
	}
	if changed == digest {
		t.Fatal("changed source retained its digest")
	}
	if err := os.Symlink("server.go", filepath.Join(source, "cmd/linked.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotServerSource(context.Background(), source, filepath.Join(t.TempDir(), "linked")); err == nil {
		t.Fatal("accepted mutable symlink source")
	}
}
