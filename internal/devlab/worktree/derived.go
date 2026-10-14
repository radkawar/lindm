// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DerivedChanges lists the main checkout's uncommitted paths under the
// change's derived roots: what the landing's regeneration produced (and the
// derived files it removed). Call it under the landing lock, where the
// checkout was clean before the landing began.
func (r *Repository) DerivedChanges(ctx context.Context, change Change) ([]string, error) {
	tracked, untracked, err := r.derivedStatus(ctx, change.Derivation.Roots)
	return append(tracked, untracked...), err
}

// derivedStatus splits the uncommitted paths under roots into tracked paths
// (modified or deleted) and untracked ones. No roots means none, never the
// whole tree.
func (r *Repository) derivedStatus(ctx context.Context, roots []string) (tracked, untracked []string, err error) {
	if len(roots) == 0 {
		return nil, nil, nil
	}
	status, err := git(ctx, r.Main, append([]string{"status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames", "--"}, roots...)...)
	if err != nil {
		return nil, nil, err
	}
	for record := range strings.SplitSeq(status, "\x00") {
		if len(record) <= 3 {
			continue
		}
		if record[:2] == "??" {
			untracked = append(untracked, record[3:])
		} else {
			tracked = append(tracked, record[3:])
		}
	}
	return tracked, untracked, nil
}

// restoreDerived returns the derived roots to rev, which must be HEAD with a
// matching index: regenerated files are checked out again and files the
// landing created are removed.
func (r *Repository) restoreDerived(ctx context.Context, roots []string, rev string) error {
	tracked, untracked, err := r.derivedStatus(ctx, roots)
	if err != nil {
		return err
	}
	var failures []error
	for _, name := range untracked {
		if err := os.Remove(filepath.Join(r.Main, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if len(tracked) != 0 {
		_, err := gitWith(ctx, r.Main, nil, []byte(strings.Join(tracked, "\x00")), "--literal-pathspecs", "checkout", "--quiet", rev, "--pathspec-from-file=-", "--pathspec-file-nul")
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
