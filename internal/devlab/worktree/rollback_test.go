// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRollbackSurvivesUncompilableSourcesAndHooks reproduces a landing whose
// gate failed with applied Go sources that do not compile, in a main
// checkout whose post-checkout hook builds the tree (as the protect hook once
// did): the rollback must not run that hook, and must restore everything.
func TestRollbackSurvivesUncompilableSourcesAndHooks(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	writeFixture(t, filepath.Join(repo.Main, "go.mod"), "module example.test\n\ngo 1.26\n")
	writeFixture(t, filepath.Join(repo.Main, "lib", "lib.go"), "package lib\n\nfunc A() int { return 1 }\n")
	writeFixture(t, filepath.Join(repo.Main, "in", "a.txt"), "a1\n")
	generateFixture(t, repo.Main)
	hooks := filepath.Join(t.TempDir(), "hooks")
	ran := filepath.Join(t.TempDir(), "hook-ran")
	for _, hook := range []string{"post-checkout", "post-merge"} {
		writeFixture(t, filepath.Join(hooks, hook), "#!/bin/sh\ntouch "+ran+"\nexec go build ./...\n")
		if err := os.Chmod(filepath.Join(hooks, hook), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gitT(t, repo.Main, "add", "go.mod", "lib", "in", "out")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "module")
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	path, err := repo.Add(ctx, "broken", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	gitT(t, repo.Main, "config", "core.hooksPath", hooks)
	// The landing edits a source file into one that does not compile, adds
	// another, and changes generator input and output.
	writeFixture(t, filepath.Join(path, "lib", "lib.go"), "package lib\n\nfunc A() int { return }\n")
	writeFixture(t, filepath.Join(path, "lib", "new.go"), "package lib\n\nvar broken = undefined\n")
	writeFixture(t, filepath.Join(path, "in", "a.txt"), "a2\n")
	generateFixture(t, path)
	change, err := repo.Change(ctx, path, nil, Derivation{Roots: []string{"out"}})
	if err != nil {
		t.Fatal(err)
	}
	prior := gitT(t, repo.Main, "rev-parse", "HEAD")
	clean := func(when string) {
		t.Helper()
		if head := gitT(t, repo.Main, "rev-parse", "HEAD"); head != prior {
			t.Fatalf("%s: HEAD moved", when)
		}
		if status := gitT(t, repo.Main, "status", "--porcelain", "--untracked-files=all"); status != "" {
			t.Fatalf("%s: rollback left %q", when, status)
		}
		if _, err := os.Stat(ran); err == nil {
			t.Fatalf("%s: a repository hook ran during the landing", when)
		}
	}
	regenerateRed := func([]string) error {
		generateFixture(t, repo.Main)
		return errors.New("go build: lib/lib.go: not enough return values")
	}
	err = repo.Land(ctx, change, "x", regenerateRed)
	if err == nil || !strings.Contains(err.Error(), "rolled back") || strings.Contains(err.Error(), "ROLLBACK FAILED") {
		t.Fatalf("gate failure: %v", err)
	}
	clean("failed gate")

	// A gate that also rewrote a patched file leaves the patch unreversible;
	// the rollback restores the patch's files directly instead.
	err = repo.Land(ctx, change, "x", func(files []string) error {
		writeFixture(t, filepath.Join(repo.Main, "lib", "lib.go"), "package lib\n\n// formatter output\nfunc A() int { return }\n")
		return regenerateRed(files)
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") || strings.Contains(err.Error(), "ROLLBACK FAILED") {
		t.Fatalf("unreversible gate failure: %v", err)
	}
	clean("unreversible patch")
}
