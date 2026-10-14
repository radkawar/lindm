// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// CI's lint:web once failed on a console change the landing gate had only run
// prettier on (a free-text input without data-freeform).
func TestWebLintCoversTouchedConsoleSources(t *testing.T) {
	for _, tc := range []struct {
		files []string
		want  [][]string
	}{
		{[]string{"cmd/dev/land.go", "docs/engineering.md", "web/acceptance/run.mjs"}, nil},
		{[]string{"web/src/features/auth/accounts.tsx", "web/src/lib/time.ts", "web/src/index.html", "docs/x.md"},
			[][]string{{"npx", "eslint", "--max-warnings=0", "--no-warn-ignored", "web/src/features/auth/accounts.tsx", "web/src/lib/time.ts"}}},
		{[]string{"web/src/styles/app.css"}, [][]string{{"node", "web/eslint/scan-css-colours.mjs"}}},
		{[]string{"web/src/app.tsx", "web/eslint/freeform-input.mjs"}, [][]string{{"npm", "run", "--silent", "lint:web"}}},
		{[]string{"eslint.config.mjs"}, [][]string{{"npm", "run", "--silent", "lint:web"}}},
		{[]string{"package.json"}, [][]string{{"npm", "run", "--silent", "lint:web"}}},
	} {
		if got := webLint(tc.files); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("webLint(%q) = %q, want %q", tc.files, got, tc.want)
		}
	}
}

// lab/demo/org.json once changed without the gate racing internal/ctl, whose
// test reads it through a package-relative path.
func TestDataReadersFindEmbedsAndOpenedPaths(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":                         "module example.test\n\ngo 1.26\n",
		"lab/demo/org.json":              "{}\n",
		"lab/other/note.txt":             "x\n",
		"internal/ctl/ctl.go":            "package ctl\n",
		"internal/ctl/ctl_test.go":       "package ctl\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestPlan(t *testing.T) { _, _ = os.ReadFile(\"../../lab/demo/org.json\") }\n",
		"internal/joined/joined_test.go": "package joined\n\nimport (\n\t\"path/filepath\"\n\t\"testing\"\n)\n\nfunc TestJ(t *testing.T) { _ = filepath.Join(\"..\", \"..\", \"lab\", \"demo\", name) }\n\nvar name = \"x\"\n",
		"rooted/rooted.go":               "package rooted\n\nconst Dir = \"lab/demo\"\n",
		"assets/assets.go":               "package assets\n\nimport \"embed\"\n\n//go:embed static\nvar Static embed.FS\n",
		"assets/static/app.css":          "a{}\n",
		"fixture/fixture_test.go":        "package fixture\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestF(t *testing.T) { _, _ = os.ReadFile(\"testdata/case.json\") }\n",
		"fixture/testdata/case.json":     "{}\n",
		"bare/bare.go":                   "package bare\n\nconst Words = \"lab\" + \"/\"\n",
		"unrelated/unrelated.go":         "package unrelated\n\nconst S = \"lab/other/note.txt\"\n",
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
	for _, tc := range []struct {
		changed []string
		want    []string
	}{
		{[]string{"lab/demo/org.json"}, []string{"internal/ctl", "internal/joined", "rooted"}},
		{[]string{"assets/static/app.css", "fixture/testdata/case.json"}, []string{"assets", "fixture"}},
		{[]string{"lab/demo/gone.json", "internal/ctl/ctl.go"}, []string{"internal/joined", "rooted"}},
		{[]string{"internal/ctl/ctl.go"}, nil},
		{[]string{"README.md"}, nil},
	} {
		got, err := dataReaders(t.Context(), root, tc.changed)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("dataReaders(%q) = %q, want %q", tc.changed, got, tc.want)
		}
	}
}
