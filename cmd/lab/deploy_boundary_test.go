// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Lab-only encrypted escrow and frozen historical verification must never enter
// customer executable dependency closures. Reuse the maintained go-list guard
// rather than inspecting only a direct source import.
func TestDeployHelpersStayOutsideProductExecutables(t *testing.T) {
	for _, entrypoint := range []string{"../lindmd", "../lindmctl", "../lindm-install"} {
		t.Run(entrypoint, func(t *testing.T) {
			output, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}", entrypoint).Output()
			if err != nil {
				t.Fatal(err)
			}
			for line := range strings.Lines(string(output)) {
				path := strings.TrimSpace(line)
				if path == "lindm/internal/vmlab" || path == "lindm/cmd/lab" {
					t.Errorf("%s imports %s: development helpers must not enter product executables", entrypoint, path)
				}
			}
		})
	}
}
