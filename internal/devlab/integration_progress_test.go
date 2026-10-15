// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the real build command and linker without building the full server.
// These fields must match the signed stock repository used by native fixtures.
func TestBuildIntegrationServerStampsStockReleaseIdentity(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module lindm\n\ngo 1.26\n",
		"internal/agent/buildinfo/buildinfo.go": `package buildinfo

var Version = "dev"
var Revision = "unknown"
`,
		"cmd/lindmd/main.go": `package main

import (
	"fmt"
	"lindm/internal/agent/buildinfo"
)

func main() {
	fmt.Printf("%s\n%s\n", buildinfo.Version, buildinfo.Revision)
}
`,
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "lindmd")
	if err := buildIntegrationServer(t.Context(), root, binary); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
	if err != nil {
		t.Fatalf("read compiled release identity: %v: %s", err, output)
	}
	if string(output) != "0.1.0\nconsole-enrollment-lab\n" {
		t.Fatalf("integration server does not match the stock agent release: %q", output)
	}
}

func TestTestWithProgressReportsEachPackage(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":         "module example.test\n\ngo 1.26\n",
		"good/good.go":   "package good\n",
		"good/a_test.go": "package good\n\nimport \"testing\"\n\nfunc TestGood(t *testing.T) {}\n",
		"bad/bad.go":     "package bad\n",
		"bad/b_test.go":  "package bad\n\nimport \"testing\"\n\nfunc TestBad(t *testing.T) { t.Fatal(\"distinctive failure\") }\n",
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
	var lines []string
	err := testWithProgress(t.Context(), root, os.Environ(), func(line string) { lines = append(lines, line) }, io.Discard, "-count=1", "./...")
	if err == nil || !strings.Contains(err.Error(), "1 of 2 packages failed") {
		t.Fatalf("failing package not reported: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if len(lines) != 2 || !strings.Contains(joined, "FAIL example.test/bad") || !strings.Contains(joined, "ok example.test/good") || !strings.Contains(joined, "[2/2]") {
		t.Fatalf("progress lines %q", lines)
	}
}
