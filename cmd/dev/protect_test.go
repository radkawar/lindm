// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"lindm/internal/devlab/worktree"
)

func TestProtectSharedYieldsToALanding(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.email=d@example.invalid", "-c", "user.name=d"}, args...)...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "--quiet")
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	file := filepath.Join(root, "tracked.go")
	if err := os.WriteFile(file, []byte("package tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "--quiet", "-m", "initial")
	repo, err := worktree.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	mode := func() os.FileMode {
		t.Helper()
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}

	unlock, err := repo.Lock(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := protectShared(t.Context(), repo)
	if err != nil || !strings.HasPrefix(report, "skipped while pid ") || mode() != 0o644 {
		t.Fatalf("protected under a landing's lock: %q, %v, mode %v", report, err, mode())
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}

	report, err = protectShared(t.Context(), repo)
	if err != nil || report != "2 tracked files or directories (trailing /) were writable, now read-only: tracked.go ./" || mode() != 0o444 {
		t.Fatalf("first protect: %q, %v, mode %v", report, err, mode())
	}
	if report, err = protectShared(t.Context(), repo); err != nil || report != "all tracked files and their directories read-only" {
		t.Fatalf("repeat protect: %q, %v", report, err)
	}
	release, ok, err := repo.TryLock()
	if err != nil || !ok {
		t.Fatalf("protect kept the landing lock: ok %v, %v", ok, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

// TestProtectHookBuildsNothing runs the post-merge/post-checkout hook body in a
// main checkout whose Go sources do not compile: it protects tracked regular
// files anyway, leaves symlinks, untracked files and private worktrees alone,
// and does nothing while a landing holds the lock.
func TestProtectHookBuildsNothing(t *testing.T) {
	hook, err := filepath.Abs(filepath.Join("..", "..", ".githooks", "protect"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	git := func(dir string, args ...string) {
		t.Helper()
		run(dir, append([]string{"git", "-c", "user.email=d@example.invalid", "-c", "user.name=d"}, args...)...)
	}
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	git(root, "init", "--quiet")
	write("go.mod", "module example.test\n\ngo 1.26\n", 0o644)
	write("broken.go", "package broken\n\nfunc F() int { return }\n", 0o644)
	write("run.sh", "#!/bin/sh\n", 0o755)
	write("with space.txt", "x\n", 0o644)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	git(root, "add", ".")
	git(root, "commit", "--quiet", "-m", "initial")
	write("untracked.txt", "x\n", 0o644)
	other := filepath.Join(t.TempDir(), "private")
	git(root, "worktree", "add", "--quiet", "--detach", other)
	perm := func(path string) os.FileMode {
		t.Helper()
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}

	run(other, hook)
	if perm(filepath.Join(other, "broken.go"))&0o200 == 0 {
		t.Fatal("the hook protected a private worktree")
	}
	repo, err := worktree.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := repo.Lock(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	run(root, hook)
	if perm(filepath.Join(root, "broken.go")) != 0o644 {
		t.Fatal("the hook protected files under a landing's lock")
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	run(root, hook)
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	for name, want := range map[string]os.FileMode{"broken.go": 0o444, "go.mod": 0o444, "run.sh": 0o555, "with space.txt": 0o444, "untracked.txt": 0o644, ".": 0o555} {
		if got := perm(filepath.Join(root, name)); got != want {
			t.Errorf("%s: mode %v, want %v", name, got, want)
		}
	}
	if perm(outside) != 0o644 {
		t.Fatal("the hook followed a tracked symlink out of the checkout")
	}
}
