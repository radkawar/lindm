// SPDX-License-Identifier: Apache-2.0

package releasebuild

import (
	"context"
	"os"
	"path/filepath"
)

// bootstrapBuildSource runs once in each independently captured source tree.
// The source digest describes the input; the console and redistribution texts
// are derived outputs subsequently covered by package and release signatures.
func bootstrapBuildSource(ctx context.Context, checkout string, environment []string, tools buildToolchain) error {
	if _, err := runNPM(ctx, checkout, environment, tools, "ci", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
		return err
	}
	if _, err := runNPM(ctx, checkout, environment, tools, "run", "build:web"); err != nil {
		return err
	}
	// The collector's own Go subprocesses must use the resolved toolchain, not
	// a host shim whose selection can change when the builder isolates HOME.
	collectorEnvironment := append(append([]string{}, environment...), "PATH="+filepath.Dir(tools.goBinary)+":"+filepath.Dir(tools.nodeBinary)+":"+os.Getenv("PATH"))
	_, err := command(ctx, checkout, collectorEnvironment, tools.nodeBinary, "test/tooling/generate-license-notices.mjs")
	return err
}
