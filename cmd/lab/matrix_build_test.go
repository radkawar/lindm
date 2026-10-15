// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise the real matrix compiler/linker path: a version-only build falls
// back to an unrelated checkout revision and the native fixture refuses it.
func TestMatrixBuildStampedMatchesAuthenticatedNativeFixture(t *testing.T) {
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
	run := &matrixRun{root: root, evidence: t.TempDir()}
	binary, err := run.buildStamped(t.Context(), io.Discard, "lindmd")
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
	if err != nil {
		t.Fatalf("read compiled matrix fixture identity: %v: %s", err, output)
	}
	if string(output) != "0.1.0\nconsole-enrollment-lab\n" {
		t.Fatalf("matrix server does not match the signed native agent artifact: %q", output)
	}
}
