package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDerivedRootsUnionDeclaredOutputs(t *testing.T) {
	write := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	main, landing, bare := t.TempDir(), t.TempDir(), t.TempDir()
	write(main, "buf.gen.yaml", "version: v2\nplugins:\n  - local: a\n    out: gen\n  - local: b\n    out: gen\n  - local: c\n    out: web/gen/\n")
	write(main, "sqlc.yaml", "version: \"2\"\nsql:\n  - engine: postgresql\n    gen:\n      go:\n        out: internal/a/adb\n")
	// The landing adds a query package of its own.
	write(landing, "sqlc.yaml", "version: \"2\"\nsql:\n  - gen:\n      go:\n        out: internal/a/adb\n  - gen:\n      go:\n        out: internal/b/bdb\n")
	roots, err := derivedRoots(main, landing, bare)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"gen", "internal/a/adb", "internal/b/bdb", "web/gen"}; !slices.Equal(roots, want) {
		t.Fatalf("derived roots %v, want %v", roots, want)
	}
	for _, out := range []string{".", "..", "/abs", "../outside", "./"} {
		write(bare, "sqlc.yaml", "sql:\n  - gen:\n      go:\n        out: \""+out+"\"\n")
		if _, err := derivedRoots(bare); err == nil || !strings.Contains(err.Error(), "inside the repository") {
			t.Fatalf("output %q accepted: %v", out, err)
		}
	}
}
