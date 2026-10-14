// SPDX-License-Identifier: Apache-2.0

package update

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Reclamation runs inside the packaged executor's read-only system mount. Unit
// mutation must remain exclusively in the independently owned update helper.
func TestTerminalReclamationUsesIndependentHelper(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "retention_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found, launches := false, false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "reclaimRetired" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if identifier.Name == "removeRecoveryUnit" {
				t.Error("sandboxed executor directly removes the system recovery unit")
			}
			if identifier.Name == "launchHelper" {
				launches = true
			}
			return true
		})
	}
	if !found || !launches {
		t.Fatal("terminal reclamation does not delegate cleanup to the independent helper")
	}
}
