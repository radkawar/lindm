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
	if err != nil || report != "1 tracked files were writable, now read-only: tracked.go" || mode() != 0o444 {
		t.Fatalf("first protect: %q, %v, mode %v", report, err, mode())
	}
	if report, err = protectShared(t.Context(), repo); err != nil || report != "all tracked files read-only" {
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
