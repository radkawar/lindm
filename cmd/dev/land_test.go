// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDependentsIncludeTransitiveAndTestImporters(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":        "module example.test\n\ngo 1.26\n",
		"a/a.go":        "package a\n\nfunc A() {}\n",
		"b/b.go":        "package b\n\nimport \"example.test/a\"\n\nfunc B() { a.A() }\n",
		"c/c.go":        "package c\n",
		"c/c_test.go":   "package c\n\nimport (\n\t\"testing\"\n\n\t\"example.test/b\"\n)\n\nfunc TestC(t *testing.T) { b.B() }\n",
		"d/d.go":        "package d\n",
		"e/e.go":        "package e\n",
		"e/e_x_test.go": "package e_test\n\nimport (\n\t\"testing\"\n\n\t\"example.test/a\"\n)\n\nfunc TestE(t *testing.T) { a.A() }\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := dependents(t.Context(), root, []string{"./a"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"./a", "./b", "./c", "./e"}; !slices.Equal(got, want) {
		t.Fatalf("dependents = %v, want %v", got, want)
	}
}

func TestMigrationsAheadRefusesStaleVersions(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.email=d@example.invalid", "-c", "user.name=d"}, args...)...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	write := func(name string) {
		t.Helper()
		path := filepath.Join(root, "db", "migrations", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("-- +goose Up\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "--quiet")
	write("00001_base.sql")
	write("00003_later.sql")
	git("add", ".")
	git("commit", "--quiet", "-m", "main")
	write("00002_late.sql")
	write("00003_later.sql") // an edit of a migration main already has
	write("00004_next.sql")
	files := []string{"db/migrations/00002_late.sql", "db/migrations/00003_later.sql", "db/migrations/00004_next.sql"}
	err := migrationsAhead(t.Context(), root, files)
	if err == nil || !strings.Contains(err.Error(), "rename to db/migrations/00005_late.sql") || strings.Contains(err.Error(), "00004_next") || strings.Contains(err.Error(), "00003_later") {
		t.Fatalf("stale migration verdict: %v", err)
	}
	if err := migrationsAhead(t.Context(), root, files[1:]); err != nil {
		t.Fatalf("ordered additions refused: %v", err)
	}
}
