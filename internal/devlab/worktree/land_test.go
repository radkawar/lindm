package worktree

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestChangeAppliesAtomicallyAndReverses(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	path, err := repo.Add(ctx, "feature", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	write := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(path, "README", "committed edit\n")
	gitT(t, path, "commit", "--quiet", "-am", "edit")
	gitT(t, path, "mv", "package.json", "renamed.json")
	if err := os.Remove(filepath.Join(path, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	write(path, "new.txt", "untracked\n")
	before := gitT(t, path, "status", "--porcelain")

	change, err := repo.Change(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"README", "new.txt", "package-lock.json", "package.json", "renamed.json"}; !slices.Equal(change.Files, want) {
		t.Fatalf("change files %v, want %v", change.Files, want)
	}
	if after := gitT(t, path, "status", "--porcelain"); after != before {
		t.Fatalf("computing the change altered the worktree index: %q -> %q", before, after)
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(repo.Main, name))
		return err == nil
	}
	if err := repo.Apply(ctx, change.Patch, false); err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join(repo.Main, "README"))
	if err != nil || string(readme) != "committed edit\n" || !exists("new.txt") || !exists("renamed.json") || exists("package.json") || exists("package-lock.json") {
		t.Fatalf("applied tree wrong: README=%q err=%v", readme, err)
	}
	write(repo.Main, "README", "concurrent edit\n")
	if err := repo.Apply(ctx, change.Patch, true); err == nil {
		t.Fatal("reversed over a conflicting edit")
	}
	if !exists("new.txt") || !exists("renamed.json") {
		t.Fatal("a refused apply changed part of the tree")
	}
	write(repo.Main, "README", "committed edit\n")
	if err := repo.Apply(ctx, change.Patch, true); err != nil {
		t.Fatal(err)
	}
	if status := gitT(t, repo.Main, "status", "--porcelain"); status != "" {
		t.Fatalf("reverse left %q", status)
	}
	if limited, err := repo.Change(ctx, path, []string{"new.txt"}); err != nil || !slices.Equal(limited.Files, []string{"new.txt"}) {
		t.Fatalf("path-limited change %v: %v", limited.Files, err)
	}
	if _, err := repo.Change(ctx, t.TempDir(), nil); err == nil {
		t.Fatal("computed a change for an unregistered directory")
	}
}

func TestLockIsExclusive(t *testing.T) {
	repo := fixtureRepository(t)
	unlock, err := repo.Lock(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var holder string
	if _, err := repo.Lock(short, func(h string) { holder = h }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second holder admitted: %v", err)
	}
	if !strings.HasPrefix(holder, "pid ") {
		t.Fatalf("holder record %q", holder)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	again, err := repo.Lock(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := again(); err != nil {
		t.Fatal(err)
	}
}
