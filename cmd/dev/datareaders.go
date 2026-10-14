// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// dataReaders returns the directories of the module packages whose builds or
// tests read a changed non-Go file, so the gate races them although none of
// their Go source changed (lab/demo/org.json once broke internal/ctl's
// TestDemoOrganizationPlan that way). A package reads a file when one of its
// embed patterns (including test embeds) matches it, or when one of its
// Go files, tests included, has a string literal, or a filepath.Join or
// path.Join of leading literals, naming the file or a directory above it,
// relative either to the package directory (how tests open fixtures) or to
// the module root. The module root and top-level directories named by a bare
// word never count as such a directory.
// files are module-relative, slash-separated, and may include deletions.
func dataReaders(ctx context.Context, root string, files []string) ([]string, error) {
	var data []string
	for _, file := range files {
		if filepath.Ext(file) != ".go" {
			data = append(data, filepath.ToSlash(filepath.Clean(file)))
		}
	}
	if len(data) == 0 {
		return nil, nil
	}
	listing, err := output(ctx, root, "go", "list", "-e", "-f", "{{.Dir}}|{{join .EmbedFiles \" \"}} {{join .TestEmbedFiles \" \"}} {{join .XTestEmbedFiles \" \"}}|{{join .GoFiles \" \"}} {{join .TestGoFiles \" \"}} {{join .XTestGoFiles \" \"}}", "./...")
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// reads reports whether a module-relative path names a changed file or,
	// unless the path is a single bare name, a directory holding one.
	// Root-relative bare names such as "lab", "web" or "db" are everyday
	// words in code; package-relative ones ("testdata") are resolved through
	// the package directory and so are never bare.
	reads := func(path string) bool {
		path = filepath.ToSlash(filepath.Clean(path))
		if path == "." || path == ".." || strings.HasPrefix(path, "../") || filepath.IsAbs(path) {
			return false
		}
		return slices.ContainsFunc(data, func(file string) bool {
			return file == path || strings.Contains(path, "/") && strings.HasPrefix(file, path+"/")
		})
	}
	var readers []string
	for line := range strings.Lines(listing) {
		fields := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(fields) != 3 {
			continue
		}
		dir, err := filepath.Rel(absolute, fields[0])
		if err != nil || strings.HasPrefix(dir, "..") {
			continue
		}
		hit := slices.ContainsFunc(strings.Fields(fields[1]), func(embedded string) bool { return reads(filepath.Join(dir, embedded)) })
		for _, name := range strings.Fields(fields[2]) {
			if hit {
				break
			}
			for _, literal := range pathLiterals(filepath.Join(fields[0], name)) {
				if reads(filepath.Join(dir, literal)) || reads(literal) {
					hit = true
					break
				}
			}
		}
		if hit {
			readers = append(readers, filepath.ToSlash(dir))
		}
	}
	slices.Sort(readers)
	return readers, nil
}

// pathLiterals returns a Go file's string literals plus the joined leading
// literal arguments of each filepath.Join or path.Join call. An unparsable
// file yields what it has; the build steps report the syntax error.
func pathLiterals(file string) []string {
	parsed, _ := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if parsed == nil {
		return nil
	}
	var literals []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.BasicLit:
			if value, ok := stringLiteral(node); ok {
				literals = append(literals, value)
			}
		case *ast.CallExpr:
			selector, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Join" {
				return true
			}
			if pkg, ok := selector.X.(*ast.Ident); !ok || pkg.Name != "filepath" && pkg.Name != "path" {
				return true
			}
			var parts []string
			for _, arg := range node.Args {
				value, ok := stringLiteral(arg)
				if !ok {
					break
				}
				parts = append(parts, value)
			}
			if len(parts) > 1 {
				literals = append(literals, strings.Join(parts, "/"))
			}
		}
		return true
	})
	return literals
}

func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil && value != ""
}
