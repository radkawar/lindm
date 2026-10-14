// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncFastForwardsProtectedCheckout(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	other := filepath.Join(t.TempDir(), "other")
	gitT(t, repo.Main, "clone", "--quiet", remote, other)
	writeFixture(t, filepath.Join(other, "README"), "changed elsewhere\n")
	writeFixture(t, filepath.Join(other, "docs", "new.md"), "new\n")
	gitT(t, other, "-c", "user.email=o@example.invalid", "-c", "user.name=o", "commit", "--quiet", "-am", "readme")
	gitT(t, other, "-c", "user.email=o@example.invalid", "-c", "user.name=o", "add", "docs")
	gitT(t, other, "-c", "user.email=o@example.invalid", "-c", "user.name=o", "commit", "--quiet", "-m", "docs")
	gitT(t, other, "push", "--quiet", "origin", "HEAD:"+Trunk)
	if _, err := repo.Protect(ctx); err != nil {
		t.Fatal(err)
	}
	// git pull cannot replace files in protected directories.
	gitT(t, repo.Main, "fetch", "--quiet", "lindm")
	if _, err := git(ctx, repo.Main, "merge", "--quiet", "--ff-only", "lindm/"+Trunk); err == nil && os.Geteuid() != 0 {
		t.Fatal("a plain fast-forward rewrote the protected checkout")
	}
	if head := gitT(t, repo.Main, "rev-parse", "HEAD"); head == gitT(t, other, "rev-parse", "HEAD") {
		t.Fatal("the refused fast-forward moved HEAD")
	}
	var before, after string
	err := repo.Writable(ctx, func() error {
		var err error
		before, after, err = repo.Sync(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if before == after || after != gitT(t, other, "rev-parse", "HEAD") {
		t.Fatalf("synced %s -> %s", before, after)
	}
	if readme := readFixture(t, filepath.Join(repo.Main, "README")); readme != "changed elsewhere\n" {
		t.Fatalf("README %q", readme)
	}
	requireProtected(t, repo)
	// Already up to date, and a dirty or diverged checkout is refused.
	if err := repo.Writable(ctx, func() error { _, _, err := repo.Sync(ctx); return err }); err != nil {
		t.Fatal(err)
	}
	if err := repo.Writable(ctx, func() error {
		gitT(t, repo.Main, "commit", "--quiet", "--allow-empty", "-m", "local")
		gitT(t, other, "-c", "user.email=o@example.invalid", "-c", "user.name=o", "commit", "--quiet", "--allow-empty", "-m", "remote")
		gitT(t, other, "push", "--quiet", "origin", "HEAD:"+Trunk)
		_, _, err := repo.Sync(ctx)
		return err
	}); err == nil || !strings.Contains(err.Error(), "cannot fast-forward") {
		t.Fatalf("diverged sync: %v", err)
	}
}
