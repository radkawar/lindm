// SPDX-License-Identifier: Apache-2.0

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

	change, err := repo.Change(ctx, path, nil, Derivation{})
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
	if limited, err := repo.Change(ctx, path, []string{"new.txt"}, Derivation{}); err != nil || !slices.Equal(limited.Files, []string{"new.txt"}) {
		t.Fatalf("path-limited change %v: %v", limited.Files, err)
	}
	if _, err := repo.Change(ctx, t.TempDir(), nil, Derivation{}); err == nil {
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

func TestLandCommitsPushesAndRollsBack(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", "--initial-branch="+Trunk, remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	path, err := repo.Add(ctx, "feature", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "landed.txt"), []byte("work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	change, err := repo.Change(ctx, path, nil, Derivation{})
	if err != nil {
		t.Fatal(err)
	}
	pass := func([]string) error { return nil }
	prior := gitT(t, repo.Main, "rev-parse", "HEAD")
	clean := func() {
		t.Helper()
		if head := gitT(t, repo.Main, "rev-parse", "HEAD"); head != prior {
			t.Fatalf("HEAD moved to %s after a failed landing", head)
		}
		if status := gitT(t, repo.Main, "status", "--porcelain"); status != "" {
			t.Fatalf("failed landing left %q", status)
		}
	}

	if err := repo.Land(ctx, change, "x", func([]string) error { return errors.New("red") }); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("gate failure: %v", err)
	}
	clean()

	// A user-level core.hooksPath would otherwise bypass the remote's hooks.
	gitT(t, repo.Main, "--git-dir", remote, "config", "core.hooksPath", filepath.Join(remote, "hooks"))
	hook := filepath.Join(remote, "hooks", "pre-receive")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := repo.Land(ctx, change, "x", pass); err == nil || !strings.Contains(err.Error(), "push") {
		t.Fatalf("push failure: %v", err)
	}
	clean()
	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo.Main, "stray.txt"), []byte("other agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := repo.Land(ctx, change, "x", pass); err == nil || !strings.Contains(err.Error(), "stray.txt") {
		t.Fatalf("dirty shared checkout accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(repo.Main, "stray.txt")); err != nil {
		t.Fatal(err)
	}

	// Another clone pushed: the shared checkout is behind its upstream.
	other := filepath.Join(t.TempDir(), "other")
	gitT(t, repo.Main, "clone", "--quiet", remote, other)
	gitT(t, other, "-c", "user.email=o@example.invalid", "-c", "user.name=o", "commit", "--quiet", "--allow-empty", "-m", "elsewhere")
	gitT(t, other, "push", "--quiet", "origin", "HEAD:"+Trunk)
	if err := repo.Land(ctx, change, "x", pass); err == nil || !strings.Contains(err.Error(), "does not contain") {
		t.Fatalf("stale shared checkout accepted: %v", err)
	}
	clean()
	gitT(t, repo.Main, "merge", "--quiet", "--ff-only", "lindm/"+Trunk)
	// A local gate-commit ahead of upstream is pushed with the landing.
	gitT(t, repo.Main, "commit", "--quiet", "--allow-empty", "-m", "local gate-commit")
	var during *Landing
	observe := func([]string) error {
		var err error
		during, err = repo.CurrentLanding()
		return err
	}
	unlock, err := repo.Lock(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Land(ctx, change, "land the work", observe); err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if status := gitT(t, repo.Main, "status", "--porcelain"); status != "" {
		t.Fatalf("landing left %q", status)
	}
	if during == nil || during.Worktree != path || during.Message != "land the work" || !slices.Equal(during.Files, change.Files) {
		t.Fatalf("landing marker during the gate: %+v", during)
	}
	if during.Stale {
		t.Fatal("marker reported stale while the lander held the lock")
	}
	if after, err := repo.CurrentLanding(); err != nil || after != nil {
		t.Fatalf("marker left after landing: %+v %v", after, err)
	}
	if pushed := gitT(t, repo.Main, "--git-dir", remote, "log", "-1", "--format=%s", Trunk); pushed != "land the work" {
		t.Fatalf("remote tip %q", pushed)
	}
	if signoff := gitT(t, repo.Main, "show", "-s", "--format=%(trailers:key=Signed-off-by,valueonly)", "HEAD"); signoff != "dev <dev@example.invalid>" {
		t.Fatalf("landing DCO trailer %q", signoff)
	}
	if _, err := os.Stat(filepath.Join(repo.Main, "landed.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestLockFileReportsEachHolderChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := LockFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan string, 8)
	acquired := make(chan error, 1)
	go func() {
		release, err := LockFile(context.Background(), path, func(holder string) { reports <- holder })
		if err == nil {
			err = release()
		}
		acquired <- err
	}()
	if first := <-reports; !strings.HasPrefix(first, "pid ") {
		t.Fatalf("first holder report %q", first)
	}
	if err := os.WriteFile(path, []byte("pid 1 test: [3/9] ok pkg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if progress := <-reports; progress != "pid 1 test: [3/9] ok pkg" {
		t.Fatalf("progress report %q", progress)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := <-acquired; err != nil {
		t.Fatal(err)
	}
}
