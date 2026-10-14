// SPDX-License-Identifier: Apache-2.0

package repolint

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryInternalPackageHasDoc enforces the AGENTS.md rule that every
// package states its boundaries and non-goals. Generated packages (sqlc) are
// exempt: every non-test file in them carries the standard generated header.
func TestEveryInternalPackageHasDoc(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(dir string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		if name := d.Name(); dir != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata") {
			return filepath.SkipDir
		}
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			return err
		}
		handwritten, documented := false, false
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.PackageClauseOnly|parser.ParseComments)
			if err != nil {
				return err
			}
			if parsed.Doc != nil {
				documented = true
			}
			body, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			if !strings.Contains(string(body), "\n// Code generated ") && !strings.HasPrefix(string(body), "// Code generated ") {
				handwritten = true
			}
		}
		if handwritten && !documented {
			rel, _ := filepath.Rel(filepath.Dir(root), dir)
			t.Errorf("%s has no package doc comment stating its boundaries and non-goals", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
