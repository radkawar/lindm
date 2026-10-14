// SPDX-License-Identifier: Apache-2.0

package releasebuild

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These executable fixtures test invocation and environment boundaries only;
// actual license collection is exercised by the maintained native guest lane.
func TestBootstrapInvokesCollectorAfterConsoleWithPinnedGo(t *testing.T) {
	checkout, tools := toolchainShimFixture(t, "go1.26.9", "v24.21.0")
	log := filepath.Join(checkout, "bootstrap.log")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	script := "#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\nset -eu\n" +
		"if [ \"$1\" = " + quote(tools.npmCLI) + " ]; then\n" +
		"  if [ \"$2\" = ci ]; then stage=npm-ci; elif [ \"$2\" = run ] && [ \"$3\" = build:web ]; then stage=console; else exit 21; fi\n" +
		"elif [ \"$1\" = test/tooling/generate-license-notices.mjs ]; then\n" +
		"  stage=collector\n  [ \"$(command -v go)\" = " + quote(tools.goBinary) + " ] || exit 22\n" +
		"else exit 23; fi\nprintf '%s\\n' \"$stage\" >> " + quote(log) + "\n"
	if err := os.WriteFile(tools.nodeBinary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	builder := filepath.Join(checkout, "private-builder")
	if err := os.Mkdir(builder, 0700); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapBuildSource(t.Context(), checkout, builderEnvironment(builder, 1760000000, tools), tools); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "npm-ci\nconsole\ncollector\n" {
		t.Fatalf("private bootstrap order: %q", got)
	}
}
