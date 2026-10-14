// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// devtoolPackages are the only module packages cmd/dev may build on. Landing,
// rollback, status and protect run while the shared tree may hold applied
// sources that do not compile; anything product code imports could be among
// them, so none of it may be a dependency here.
var devtoolPackages = []string{
	"lindm/cmd/dev",
	"lindm/internal/devlab/project",
	"lindm/internal/devlab/toolchain",
	"lindm/internal/devlab/worktree",
	"lindm/internal/diskgc",
	"lindm/internal/gendoc",
	"lindm/internal/labexec",
}

func TestDependsOnlyOnDevtoolPackages(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-test", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(out)) {
		// Test variants read "pkg [pkg.test]" and the test main "pkg.test".
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pkg := strings.TrimSuffix(fields[0], ".test")
		if pkg != "lindm" && !strings.HasPrefix(pkg, "lindm/") {
			continue // third-party modules are pinned and never mid-landing
		}
		if !slices.Contains(devtoolPackages, pkg) {
			t.Errorf("cmd/dev depends on %s; keep product code out of the landing tool (move the verb to cmd/devenv)", pkg)
		}
	}
}
