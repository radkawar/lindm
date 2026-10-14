// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"lindm/internal/diskgc"
	"lindm/internal/labexec"
)

// raceTestTimeout bounds each race test binary in the land gate: the
// integration lock budget (cmd/devenv integrationLockCap), the bound any one
// suite is held to, instead of go test's 10m default, which loaded hosts
// exceed.
const raceTestTimeout = 45 * time.Minute

// landGCThreshold is the free space below which dev land collects first.
const landGCThreshold = 200 << 30

func output(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Stderr = dir, os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// stream runs a gate with its output streamed (env nil inherits ours);
// cancellation kills its whole process group, so the gate's children cannot
// outlive a failed landing.
func stream(ctx context.Context, dir string, env []string, name string, args ...string) error {
	if err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: env, Dir: dir, Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		return fmt.Errorf("%s %s in %s: %w", name, strings.Join(args, " "), dir, err)
	}
	return nil
}

// collectIfLow runs go run ./cmd/devenv gc from the working directory (the
// lander's worktree, whose code it builds, not the shared tree's) before a
// landing when the shared checkout's filesystem is short of space; gc
// failures are reported, never fatal to the landing.
func collectIfLow(ctx context.Context, shared string) {
	free, err := diskgc.Free(shared)
	if err != nil || free >= landGCThreshold {
		return
	}
	fmt.Printf("land: %s free on %s (under %s); running go run ./cmd/devenv gc first\n", diskgc.Size(free), shared, diskgc.Size(landGCThreshold))
	if err := stream(ctx, ".", nil, "go", "run", "./cmd/devenv", "gc"); err != nil {
		fmt.Fprintf(os.Stderr, "land: gc incomplete (landing continues): %v\n", err)
	}
}
