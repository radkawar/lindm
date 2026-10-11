package main

import (
	"os"
	"path/filepath"
	"slices"
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
