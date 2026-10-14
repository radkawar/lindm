// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// legacyRevisionPattern admits commit IDs and plain ref names; never an option
// or a revision expression.
var legacyRevisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,127}$`)

var gitCommitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// exportLegacySource writes the tree of revision, resolved in the git checkout
// rooted at repository, to a new private directory under work. Only read-only
// git plumbing (rev-parse, archive) runs against the repository. It returns the
// resolved commit and the exported source directory.
func exportLegacySource(ctx context.Context, repository, revision, work string) (commit, source string, err error) {
	if !legacyRevisionPattern.MatchString(revision) || strings.Contains(revision, "..") {
		return "", "", fmt.Errorf("legacy agent revision %q is not a commit ID or ref name", revision)
	}
	root, err := filepath.Abs(repository)
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		return "", "", fmt.Errorf("build repository %s: %w", repository, err)
	}
	// A staged source tree without .git would otherwise resolve against an
	// enclosing, unrelated checkout.
	top, err := hostCommand(ctx, work, "git", nil, "-C", root, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", fmt.Errorf("build repository %s is not a git checkout; the legacy agent is exported from its history: %w", repository, err)
	}
	toplevel, err := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
	if err != nil || toplevel != root {
		return "", "", errors.Join(fmt.Errorf("build repository %s is not the root of a git checkout (top level %q)", repository, strings.TrimSpace(string(top))), err)
	}
	resolved, err := hostCommand(ctx, work, "git", nil, "-C", root, "rev-parse", "--verify", "--quiet", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("legacy agent revision %q does not resolve to a commit in %s: %w", revision, repository, err)
	}
	commit = strings.TrimSpace(string(resolved))
	if !gitCommitPattern.MatchString(commit) {
		return "", "", fmt.Errorf("legacy agent revision %q resolved to unexpected object name %q", revision, commit)
	}
	archive := filepath.Join(work, "legacy-source.tar")
	if _, err := hostCommand(ctx, work, "git", nil, "-C", root, "archive", "--format=tar", "-o", archive, commit); err != nil {
		return "", "", fmt.Errorf("export legacy agent revision %s: %w", commit, err)
	}
	defer func() { err = errors.Join(err, os.Remove(archive)) }()
	source = filepath.Join(work, "legacy-source")
	if err := os.Mkdir(source, 0700); err != nil {
		return "", "", err
	}
	if _, err := hostCommand(ctx, work, "tar", nil, "-x", "--no-same-owner", "-f", archive, "-C", source); err != nil {
		return "", "", fmt.Errorf("extract legacy agent revision %s: %w", commit, err)
	}
	return commit, source, nil
}
