package worktree

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := git(context.Background(), dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// fixtureRepository is a real main checkout with one commit on main and the
// archive directed into the test's temporary tree.
func fixtureRepository(t *testing.T) *Repository {
	t.Helper()
	main := filepath.Join(t.TempDir(), "lindm")
	if err := os.Mkdir(main, 0o755); err != nil {
		t.Fatal(err)
	}
	gitT(t, main, "init", "--quiet", "--initial-branch", Trunk)
	gitT(t, main, "config", "user.email", "dev@example.invalid")
	gitT(t, main, "config", "user.name", "dev")
	for _, file := range []string{"package.json", "package-lock.json", "README"} {
		if err := os.WriteFile(filepath.Join(main, file), []byte(file+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(main, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, "Makefile"), []byte("tools:\n\tmkdir -p .tools && touch .tools/installed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, ".git", "info", "exclude"), []byte("/node_modules\n/.tools\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, main, "add", "package.json", "package-lock.json", "README", "Makefile")
	gitT(t, main, "commit", "--quiet", "-m", "initial")
	repo, err := Open(context.Background(), main)
	if err != nil {
		t.Fatal(err)
	}
	repo.Archive = filepath.Join(t.TempDir(), "archive")
	return repo
}

func TestAddSharesMatchingInstall(t *testing.T) {
	repo := fixtureRepository(t)
	path, err := repo.Add(context.Background(), "feature", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(repo.Main+".worktrees", "feature") {
		t.Fatalf("worktree at %s", path)
	}
	if target, err := os.Readlink(filepath.Join(path, "node_modules")); err != nil || target != filepath.Join(repo.Main, "node_modules") {
		t.Fatalf("node_modules link %q: %v", target, err)
	}
	if _, err := os.Stat(filepath.Join(path, ".tools", "installed")); err != nil {
		t.Fatalf("pinned tools not installed in the worktree: %v", err)
	}
	if status := gitT(t, path, "status", "--porcelain"); status != "" {
		t.Fatalf("shared install made the tree dirty: %q", status)
	}
	if _, err := repo.Add(context.Background(), "feature", "HEAD", io.Discard); err == nil {
		t.Fatal("reused an existing worktree path")
	}
	if _, err := repo.Add(context.Background(), "../escape", "HEAD", io.Discard); err == nil {
		t.Fatal("accepted a name outside the worktree area")
	}
}

func TestPruneRemovesOnlyMergedUnusedTreesAndArchivesUnmerged(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	add := func(name string) string {
		path, err := repo.Add(ctx, name, "HEAD", io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	merged, dirty, diverged, busy := add("merged"), add("dirty"), add("diverged"), add("busy")
	if err := os.WriteFile(filepath.Join(dirty, "README"), []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirty, "notes"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, diverged, "commit", "--quiet", "--allow-empty", "-m", "unmerged")
	sleeper := exec.Command("sleep", "60")
	sleeper.Dir = busy
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })

	prune := func(options PruneOptions) map[string]Decision {
		decisions := map[string]Decision{}
		options.Now = time.Now()
		if err := repo.Prune(ctx, nil, options, func(d Decision) error { decisions[filepath.Base(d.Path)] = d; return nil }); err != nil {
			t.Fatal(err)
		}
		return decisions
	}
	planned := prune(PruneOptions{DryRun: true})
	if !planned["merged"].Removed || planned["dirty"].Removed || planned["diverged"].Removed || planned["busy"].Removed {
		t.Fatalf("dry-run plan: %+v", planned)
	}
	if !strings.HasPrefix(planned["busy"].Reason, "in use by pid") {
		t.Fatalf("busy tree reason %q", planned["busy"].Reason)
	}
	if _, err := os.Stat(merged); err != nil {
		t.Fatal("dry run removed a tree")
	}
	if old := prune(PruneOptions{DryRun: true, OlderThan: time.Hour}); old["merged"].Removed {
		t.Fatal("pruned a tree modified within -older-than")
	}

	applied := prune(PruneOptions{ArchiveDirty: true})
	for _, name := range []string{"merged", "dirty", "diverged"} {
		if !applied[name].Removed {
			t.Fatalf("%s kept: %s", name, applied[name].Reason)
		}
	}
	if applied["busy"].Removed {
		t.Fatal("removed a tree a live process uses")
	}
	if _, err := os.Stat(busy); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{merged, dirty, diverged} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still present: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(repo.Main, "node_modules")); err != nil {
		t.Fatal("removal followed the shared node_modules link")
	}
	if applied["merged"].Archive != "" {
		t.Fatal("archived a clean merged tree")
	}
	patch, err := os.ReadFile(filepath.Join(applied["dirty"].Archive, "diff.patch"))
	if err != nil || !strings.Contains(string(patch), "+edited") {
		t.Fatalf("dirty diff %q: %v", patch, err)
	}
	listing, err := exec.Command("tar", "-tf", filepath.Join(applied["dirty"].Archive, "untracked.tar")).Output()
	if err != nil || strings.TrimSpace(string(listing)) != "notes" {
		t.Fatalf("untracked archive %q: %v", listing, err)
	}
	bundle := filepath.Join(applied["diverged"].Archive, "head.bundle")
	if out := gitT(t, repo.Main, "bundle", "list-heads", bundle); !strings.HasPrefix(out, applied["diverged"].Status.Head) {
		t.Fatalf("bundle heads %q, want %s", out, applied["diverged"].Status.Head)
	}
	if head, err := os.ReadFile(filepath.Join(applied["diverged"].Archive, "HEAD")); err != nil || !strings.HasPrefix(string(head), applied["diverged"].Status.Head+"\n") {
		t.Fatalf("HEAD record %q: %v", head, err)
	}
	entries, err := repo.List(ctx)
	if err != nil || len(entries) != 1 || filepath.Base(entries[0].Path) != "busy" {
		t.Fatalf("registered after prune: %+v %v", entries, err)
	}
}
