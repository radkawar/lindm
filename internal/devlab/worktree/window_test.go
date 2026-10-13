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

// A process writing into the shared checkout while a landing holds it
// writable (here, during the gate) must never be committed: a new file, an
// edit of a tracked file outside the change, and an edit of a file the change
// itself touched all refuse the landing, name the file and roll back.
func TestLandNeverCommitsThirdPartyWritesDuringTheWindow(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	writeFixture(t, filepath.Join(repo.Main, "docs", "guide.md"), "# Guide\n")
	gitT(t, repo.Main, "add", "docs")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "docs")
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	path, err := repo.Add(ctx, "feature", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(path, "README"), "feature\n")
	change, err := repo.Change(ctx, path, nil, Derivation{})
	if err != nil {
		t.Fatal(err)
	}
	prior := gitT(t, repo.Main, "rev-parse", "HEAD")
	for _, tc := range []struct{ name, file, content string }{
		{"new docs file", "docs/stray.md", "written by another agent\n"},
		{"tracked file outside the change", "docs/guide.md", "# Guide\nedited by another agent\n"},
		{"file the change touched", "README", "feature\nand another agent's line\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.Land(ctx, change, "x", func([]string) error {
				writeFixture(t, filepath.Join(repo.Main, tc.file), tc.content)
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "by something other than the landing") || !strings.Contains(err.Error(), tc.file) || !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("landing accepted a third-party write: %v", err)
			}
			if head := gitT(t, repo.Main, "rev-parse", "HEAD"); head != prior {
				t.Fatal("committed")
			}
			if status := gitT(t, repo.Main, "status", "--porcelain", "--untracked-files=all"); status != "" {
				t.Fatalf("rollback left %q", status)
			}
		})
	}
	if err := repo.Land(ctx, change, "feature", func([]string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if files := gitT(t, repo.Main, "show", "--name-only", "--format=", "HEAD"); files != "README" {
		t.Fatalf("committed %q", files)
	}
}

func TestGateCommitCommitsOnlyWhatTheGateVerified(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	writeFixture(t, filepath.Join(repo.Main, "README"), "verified edit\n")
	writeFixture(t, filepath.Join(repo.Main, "new.txt"), "verified new file\n")
	prior := gitT(t, repo.Main, "rev-parse", "HEAD")
	for _, tc := range []struct{ name, file, content string }{
		{"new file", "docs/stray.md", "written by another agent\n"},
		{"tracked file", "package.json", "edited by another agent\n"},
		{"verified file", "README", "rewritten by another agent\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.GateCommit(ctx, "x", func() error {
				writeFixture(t, filepath.Join(repo.Main, tc.file), tc.content)
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.file) || !strings.Contains(err.Error(), "nothing committed") {
				t.Fatalf("gate-commit accepted a third-party write: %v", err)
			}
			if head := gitT(t, repo.Main, "rev-parse", "HEAD"); head != prior {
				t.Fatal("committed")
			}
			// The verified change is back, the stray write gone.
			if status := gitT(t, repo.Main, "status", "--porcelain", "--untracked-files=all"); status != "M README\n?? new.txt" && status != " M README\n?? new.txt" {
				t.Fatalf("state after refusal %q", status)
			}
			if readme := readFixture(t, filepath.Join(repo.Main, "README")); readme != "verified edit\n" {
				t.Fatalf("README %q", readme)
			}
		})
	}
	if err := repo.GateCommit(ctx, "x", func() error { return errors.New("red") }); err == nil || !strings.Contains(err.Error(), "nothing committed") {
		t.Fatalf("red gate: %v", err)
	}
	if err := repo.GateCommit(ctx, "verified", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if files := gitT(t, repo.Main, "show", "--name-only", "--format=", "HEAD"); files != "README\nnew.txt" {
		t.Fatalf("committed %q", files)
	}
	if err := repo.GateCommit(ctx, "x", func() error { return nil }); err == nil || !strings.Contains(err.Error(), "nothing to commit") {
		t.Fatalf("empty gate-commit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo.Main, "docs")); err == nil {
		entries, _ := os.ReadDir(filepath.Join(repo.Main, "docs"))
		if len(entries) != 0 {
			t.Fatalf("stray files survived: %v", entries)
		}
	}
}
