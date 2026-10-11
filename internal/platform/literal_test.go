package platform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// nonDistroLiterals are uses of a registry ID string that do not name a
// distribution; each needs a reason.
var nonDistroLiterals = map[string]map[string]string{
	"internal/advisory/feed/osv.go":               {"arch": "OSV package-URL qualifier key"},
	"internal/agent/dnf/versionlock.go":           {"arch": "DNF versionlock condition key (RPM architecture)"},
	"internal/agent/packageprovider/pin_linux.go": {"arch": "DNF versionlock condition key (RPM architecture)"},
	"internal/packaging/result.go":                {"arch": "pacman package format name and .PKGINFO architecture field key"},
	"cmd/lab/hosts.go":                            {"arch": "architecture flag name"},
	"cmd/lab/images_redhat.go":                    {"arch": "architecture flag name"},
	"cmd/lab/lifecycle.go":                        {"arch": "pacman package-format flag name"},
	"cmd/lab/packages.go":                         {"arch": "architecture flag name"},
}

// TestNoDistroIDLiteralsOutsideRegistry keeps distribution knowledge in the
// registry: product and lab code ask it for capabilities and native facts
// instead of comparing os-release IDs. Tests may still construct observed
// os-release fixtures.
func TestNoDistroIDLiteralsOutsideRegistry(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if d.IsDir() {
				if rel == filepath.Join("internal", "platform") || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			if ast.IsGenerated(file) {
				return nil
			}
			skip := map[*ast.BasicLit]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.ImportSpec:
					skip[n.Path] = true
				case *ast.Field:
					if n.Tag != nil {
						skip[n.Tag] = true
					}
				case *ast.BasicLit:
					if n.Kind != token.STRING || skip[n] {
						return true
					}
					value, err := strconv.Unquote(n.Value)
					if err == nil && KnownID(value) && nonDistroLiterals[filepath.ToSlash(rel)][value] == "" {
						found = append(found, filepath.ToSlash(rel)+": "+value)
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
	slices.Sort(found)
	for _, f := range slices.Compact(found) {
		t.Errorf("distribution ID literal outside internal/platform: %s", f)
	}
}
