package auditkind

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The console shows audit rows by these names; a kind without one would surface
// as a raw code such as "device_action.create" in the Action column.
const consoleNames = "../../web/src/features/audit/action-names.json"

func TestEveryKindHasAConsoleName(t *testing.T) {
	raw, err := os.ReadFile(consoleNames)
	if err != nil {
		t.Fatal(err)
	}
	var names map[string]string
	if err := json.Unmarshal(raw, &names); err != nil {
		t.Fatalf("%s: %v", consoleNames, err)
	}
	known := map[string]bool{}
	for _, k := range All() {
		known[k.String()] = true
		if strings.TrimSpace(names[k.String()]) == "" {
			t.Errorf("%s has no human name in %s", k, consoleNames)
		}
	}
	for code := range names {
		if !known[code] {
			t.Errorf("%s names %q, which the server never records; remove it or register the kind", consoleNames, code)
		}
	}
}

func TestKindsAreUniqueWellFormedCodes(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)
	seen := map[string]bool{}
	for _, k := range All() {
		if !shape.MatchString(k.String()) {
			t.Errorf("malformed audit kind %q", k)
		}
		if seen[k.String()] {
			t.Errorf("audit kind %q registered twice", k)
		}
		seen[k.String()] = true
	}
	for _, k := range HumanActionsExcluded() {
		if !seen[k.String()] {
			t.Errorf("excluded kind %q is not registered", k)
		}
	}
}

// Audit helpers take a Kind; sqlc parameter structs take the code as a string.
// A literal there would record a kind the registry, and so the console's
// names, never learn about.
func TestAuditWriteParamsNeverTakeLiteralKinds(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(src, []byte("Audit")) {
			return err
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !strings.Contains(typeName(lit.Type), "Audit") || !strings.HasSuffix(typeName(lit.Type), "Params") {
				return true
			}
			for _, element := range lit.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if key, isIdent := field.Key.(*ast.Ident); ok && isIdent && key.Name == "Action" && hasStringLiteral(field.Value) {
					t.Errorf("%s: audit Action is a string literal; register an auditkind.Kind and pass its String()", fset.Position(field.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func typeName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

func hasStringLiteral(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			found = true
		}
		return !found
	})
	return found
}
