// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// modeOf returns the permission bits of a file in the main checkout.
func modeOf(t *testing.T, repo *Repository, name string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(filepath.Join(repo.Main, name))
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// requireProtected fails unless every tracked regular file of the main
// checkout is read-only and, for an unprivileged user, refuses a write.
func requireProtected(t *testing.T, repo *Repository) {
	t.Helper()
	for name := range strings.SplitSeq(gitT(t, repo.Main, "ls-files"), "\n") {
		info, err := os.Lstat(filepath.Join(repo.Main, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("%s is writable (%v) outside a landing", name, info.Mode().Perm())
		}
		dir := filepath.Dir(filepath.Join(repo.Main, name))
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("directory %s of %s is writable outside a landing: %v", dir, name, err)
		}
	}
	if os.Geteuid() != 0 {
		readme := filepath.Join(repo.Main, "README")
		if err := os.WriteFile(readme, []byte("stray\n"), 0o644); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("stray write into the protected checkout: %v", err)
		}
		// How editors and agents' tools save: a temporary file beside the
		// target, renamed over it.
		if err := os.WriteFile(readme+".tmp", []byte("stray\n"), 0o644); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("temporary file created beside a protected file: %v", err)
		}
		scratch := filepath.Join(t.TempDir(), "edit")
		if err := os.WriteFile(scratch, []byte("stray\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(scratch, readme); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("rename over a protected file: %v", err)
		}
	}
}

func TestProtectIsIdempotentAndUnprotectRestoresOwnerWrite(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(repo.Main, "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("README", filepath.Join(repo.Main, "link")); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo.Main, "add", "run.sh", "link")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "script and link")
	untracked := filepath.Join(repo.Main, "notes.txt")
	if err := os.WriteFile(untracked, []byte("scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := repo.Protect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Makefile", "README", "package-lock.json", "package.json", "run.sh", "./"}; !slices.Equal(changed, want) {
		t.Fatalf("protected %v, want %v (symlinks have no mode of their own)", changed, want)
	}
	requireProtected(t, repo)
	if mode := modeOf(t, repo, "run.sh"); mode != 0o555 {
		t.Fatalf("run.sh protected to %v, want 0555", mode)
	}
	if info, err := os.Stat(untracked); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("untracked file mode changed: %v %v", info, err)
	}
	if status := gitT(t, repo.Main, "status", "--porcelain", "--untracked-files=no"); status != "" {
		t.Fatalf("protection shows as a change: %q", status)
	}
	if again, err := repo.Protect(ctx); err != nil || len(again) != 0 {
		t.Fatalf("second protect changed %v: %v", again, err)
	}

	restored, err := repo.Unprotect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 6 || modeOf(t, repo, "README") != 0o644 || modeOf(t, repo, "run.sh") != 0o755 {
		t.Fatalf("unprotect restored %v; README %v, run.sh %v", restored, modeOf(t, repo, "README"), modeOf(t, repo, "run.sh"))
	}
}

func TestWritableReprotectsAfterEveryLandingOutcome(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	path, err := repo.Add(ctx, "feature", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "README"), []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "landed.txt"), []byte("work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	change, err := repo.Change(ctx, path, nil, Derivation{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Protect(ctx); err != nil {
		t.Fatal(err)
	}
	writableDuringGate := func([]string) error {
		if mode := modeOf(t, repo, "Makefile"); mode&0o200 == 0 {
			t.Errorf("tracked files read-only (%v) during the gate", mode)
		}
		return nil
	}

	// A red gate rolls back; git apply --reverse recreates README writable.
	err = repo.Writable(ctx, func() error {
		return repo.Land(ctx, change, "x", func(files []string) error {
			_ = writableDuringGate(files)
			return errors.New("red")
		})
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("gate failure: %v", err)
	}
	if status := gitT(t, repo.Main, "status", "--porcelain"); status != "" {
		t.Fatalf("failed landing left %q", status)
	}
	requireProtected(t, repo)

	// A refusal (a stray untracked file, from before protection) never
	// reaches the gate.
	if err := os.Chmod(repo.Main, 0o755); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(repo.Main, "stray.txt")
	if err := os.WriteFile(stray, []byte("other agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := repo.Writable(ctx, func() error { return repo.Land(ctx, change, "x", writableDuringGate) }); err == nil {
		t.Fatal("dirty shared checkout accepted")
	}
	requireProtected(t, repo)
	if err := os.Chmod(repo.Main, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}

	// An interrupted run re-protects too.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		_ = repo.Writable(ctx, func() error { panic("interrupted") })
	}()
	requireProtected(t, repo)

	// A landing protects the files it added.
	if err := repo.Writable(ctx, func() error { return repo.Land(ctx, change, "land", writableDuringGate) }); err != nil {
		t.Fatal(err)
	}
	if mode := modeOf(t, repo, "landed.txt"); mode != 0o444 {
		t.Fatalf("landed file left %v", mode)
	}
	requireProtected(t, repo)
}

func TestWritableReprotectsWhenUnprotectFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	repo := fixtureRepository(t)
	ctx := context.Background()
	locked := filepath.Join(repo.Main, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "file"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo.Main, "add", "locked/file")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "locked")
	if _, err := repo.Protect(ctx); err != nil {
		t.Fatal(err)
	}
	// An untraversable directory makes one file's chmod fail mid-way.
	if err := os.Chmod(locked, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	ran := false
	err := repo.Writable(ctx, func() error { ran = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "unprotect") || ran {
		t.Fatalf("partial unprotect: err %v, ran %v", err, ran)
	}
	for _, name := range []string{"Makefile", "README", "package-lock.json", "package.json"} {
		if mode := modeOf(t, repo, name); mode&0o222 != 0 {
			t.Fatalf("%s left writable (%v) after a failed unprotect", name, mode)
		}
	}
}

func TestTryLockYieldsToHolder(t *testing.T) {
	repo := fixtureRepository(t)
	unlock, err := repo.Lock(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if release, ok, err := repo.TryLock(); err != nil || ok || release != nil {
		t.Fatalf("TryLock taken while held: ok %v, err %v", ok, err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	release, ok, err := repo.TryLock()
	if err != nil || !ok {
		t.Fatalf("TryLock of a free lock: ok %v, err %v", ok, err)
	}
	if holder, held, err := LockHolder(repo.LockPath()); err != nil || !held || !strings.HasPrefix(holder, "pid ") {
		t.Fatalf("holder %q held %v: %v", holder, held, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectKeepsBuildOutputsWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	repo := fixtureRepository(t)
	ctx := context.Background()
	writeFixture(t, filepath.Join(repo.Main, ".gitignore"), "# outputs\nartifacts/\n/web/dist/\n!kept/\n*.cache/\n../outside/\nnode_modules\n")
	writeFixture(t, filepath.Join(repo.Main, "web", "index.html"), "<html>\n")
	gitT(t, repo.Main, "add", ".gitignore", "web/index.html")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "web")
	writeFixture(t, filepath.Join(repo.Main, "scratch", "notes"), "untracked directory\n")
	if _, err := repo.Protect(ctx); err != nil {
		t.Fatal(err)
	}
	requireProtected(t, repo)
	// make check, acceptance-build and ui-review write only below these.
	for _, output := range []string{"artifacts/bin/lindmd", "web/dist/assets/app.js", "scratch/more", "node_modules/pkg/new.js"} {
		writeFixture(t, filepath.Join(repo.Main, output), "built\n")
	}
	for _, absent := range []string{"kept", "outside"} {
		if _, err := os.Lstat(filepath.Join(repo.Main, absent)); err == nil {
			t.Fatalf("created %s from a non-directory or negated pattern", absent)
		}
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(repo.Main), "outside")); err == nil {
		t.Fatal("created a directory outside the checkout")
	}
	// Protect is idempotent with outputs present.
	if again, err := repo.Protect(ctx); err != nil || len(again) != 0 {
		t.Fatalf("second protect changed %v: %v", again, err)
	}
}
