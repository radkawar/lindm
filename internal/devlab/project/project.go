// SPDX-License-Identifier: Apache-2.0

// Package project names a checkout's development Docker Compose project. It
// is the one definition shared by the fixture lifecycle (devlab), which runs
// the project, and the worktree tooling, which must recognize it running; it
// starts nothing itself.
package project

import (
	"crypto/sha256"
	"fmt"
)

// ComposeName is the Compose project of the checkout at repoRoot: unique per
// checkout path, so checkouts never share containers or volumes.
func ComposeName(repoRoot string) string {
	digest := sha256.Sum256([]byte(repoRoot))
	return fmt.Sprintf("lindm-dev-%x", digest[:6])
}
