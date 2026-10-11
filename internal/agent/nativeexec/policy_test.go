package nativeexec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// spawnAllowlist names the only agent files that may start a process without
// nativeexec, each with the reason it cannot use the shared policy. Test files
// are excluded wholesale: they re-exec the test binary into namespaces or under
// other credentials, which nativeexec deliberately cannot express.
var spawnAllowlist = map[string]string{}

// spawners are the process-creation entry points nativeexec wraps.
var spawners = map[string]map[string]bool{
	"os/exec":               {"Command": true, "CommandContext": true, "Cmd": true, "LookPath": true},
	"os":                    {"StartProcess": true},
	"syscall":               {"ForkExec": true, "Exec": true, "StartProcess": true},
	"golang.org/x/sys/unix": {"Exec": true},
}

// A native command that bypasses nativeexec silently loses process-group kill,
// the clean environment, executable custody and stderr redaction.
func TestAgentSpawnsOnlyThroughNativeexec(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == self || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, use := range spawnUses(t, path) {
			if _, ok := spawnAllowlist[relative]; ok {
				seen[relative] = true
				continue
			}
			t.Errorf("%s:%s: start native processes with nativeexec.Run/Start", relative, use)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file := range spawnAllowlist {
		if !seen[file] {
			t.Errorf("stale spawn allowlist entry %s", file)
		}
	}
}

func spawnUses(t *testing.T, path string) []string {
	t.Helper()
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]map[string]bool{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		banned, ok := spawners[importPath]
		if !ok {
			continue
		}
		name := filepath.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = banned
	}
	var uses []string
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := selector.X.(*ast.Ident); ok && names[pkg.Name][selector.Sel.Name] {
			uses = append(uses, strconv.Itoa(files.Position(selector.Pos()).Line)+": "+pkg.Name+"."+selector.Sel.Name)
		}
		return true
	})
	return uses
}
