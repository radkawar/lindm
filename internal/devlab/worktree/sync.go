package worktree

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Sync fast-forwards the main checkout's Trunk to its freshly fetched
// upstream and returns the commits before and after. It replaces git pull in
// the main checkout, whose protected directories refuse git's file
// replacement outside a landing: call it holding the landing lock with the
// tree writable (Writable re-protects the files it brings). It refuses unless
// the checkout is on Trunk and has no uncommitted change, and never merges:
// a checkout ahead of or diverged from upstream is reported, not rewritten.
func (r *Repository) Sync(ctx context.Context) (before, after string, err error) {
	branch, err := git(ctx, r.Main, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || strings.TrimSpace(branch) != "refs/heads/"+Trunk {
		return "", "", errors.Join(err, fmt.Errorf("%s is not on %s", r.Main, Trunk))
	}
	dirty, err := git(ctx, r.Main, "status", "--porcelain")
	if err != nil {
		return "", "", err
	}
	if dirty != "" {
		return "", "", r.refuseDirty(ctx, dirty)
	}
	upstream, err := git(ctx, r.Main, "rev-parse", "--abbrev-ref", Trunk+"@{upstream}")
	if err != nil {
		return "", "", err
	}
	upstream = strings.TrimSpace(upstream)
	remote, remoteBranch, ok := strings.Cut(upstream, "/")
	if !ok {
		return "", "", fmt.Errorf("unexpected upstream %q for %s", upstream, Trunk)
	}
	if _, err := git(ctx, r.Main, "fetch", "--quiet", remote, remoteBranch); err != nil {
		return "", "", err
	}
	if before, err = git(ctx, r.Main, "rev-parse", "HEAD"); err != nil {
		return "", "", err
	}
	if _, err := git(ctx, r.Main, "merge", "--quiet", "--ff-only", upstream); err != nil {
		return strings.TrimSpace(before), "", fmt.Errorf("refused: %s cannot fast-forward to %s (local commits not on upstream are landed with the next dev land): %w", Trunk, upstream, err)
	}
	after, err = git(ctx, r.Main, "rev-parse", "HEAD")
	return strings.TrimSpace(before), strings.TrimSpace(after), err
}
