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
)

// generateFixture is a stand-in for buf/sqlc: out/all.txt joins every input
// (one output every input change touches, like a shared generated package),
// and out/NAME.gen mirrors in/NAME.txt but is never deleted when its input is
// (sqlc keeps stale files).
func generateFixture(t *testing.T, dir string) {
	t.Helper()
	inputs, err := filepath.Glob(filepath.Join(dir, "in", "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(inputs)
	if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, input := range inputs {
		content, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(content)
		name := strings.TrimSuffix(filepath.Base(input), ".txt") + ".gen"
		writeFixture(t, filepath.Join(dir, "out", name), "generated from "+string(content))
	}
	writeFixture(t, filepath.Join(dir, "out", "all.txt"), all.String())
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestLandsRegenerateDerivedOutputAndCompose(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	writeFixture(t, filepath.Join(repo.Main, "in", "a.txt"), "a1\n")
	writeFixture(t, filepath.Join(repo.Main, "in", "c.txt"), "c1\n")
	generateFixture(t, repo.Main)
	gitT(t, repo.Main, "add", "in", "out")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "generated")
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	roots := []string{"out"}
	add := func(name string) string {
		t.Helper()
		path, err := repo.Add(ctx, name, "HEAD", io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Both trees branch from the same main and regenerate out/all.txt.
	first, second := add("first"), add("second")
	writeFixture(t, filepath.Join(first, "in", "a.txt"), "a2\n")
	generateFixture(t, first)
	writeFixture(t, filepath.Join(second, "in", "b.txt"), "b1\n")
	for _, name := range []string{"in/c.txt", "out/c.gen"} {
		if err := os.Remove(filepath.Join(second, name)); err != nil {
			t.Fatal(err)
		}
	}
	generateFixture(t, second)
	var gated [][]string
	regenerating := func(files []string) error {
		generateFixture(t, repo.Main)
		gated = append(gated, files)
		return nil
	}

	land := func(path, message string) {
		t.Helper()
		change, err := repo.Change(ctx, path, nil, Derivation{Roots: roots})
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Land(ctx, change, message, regenerating); err != nil {
			t.Fatal(err)
		}
	}
	land(first, "first")
	// Applied whole, the second tree's output conflicts with the first's.
	whole, err := repo.Change(ctx, second, nil, Derivation{})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Land(ctx, whole, "whole", regenerating); err == nil || !strings.Contains(err.Error(), "nothing applied") {
		t.Fatalf("conflicting generated output applied: %v", err)
	}
	change, err := repo.Change(ctx, second, nil, Derivation{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(change.Files, []string{"in/b.txt", "in/c.txt"}) || !slices.Equal(change.Derived, []string{"out/all.txt", "out/b.gen", "out/c.gen"}) || !slices.Equal(change.DerivedDeleted, []string{"out/c.gen"}) {
		t.Fatalf("change files %v, derived %v, deleted %v", change.Files, change.Derived, change.DerivedDeleted)
	}
	land(second, "second")

	if all := readFixture(t, filepath.Join(repo.Main, "out", "all.txt")); all != "a2\nb1\n" {
		t.Fatalf("composed output %q", all)
	}
	if _, err := os.Stat(filepath.Join(repo.Main, "out", "c.gen")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale output the worktree deleted survived regeneration: %v", err)
	}
	committed := strings.Fields(gitT(t, repo.Main, "show", "--name-only", "--format=", "HEAD"))
	if want := []string{"in/b.txt", "in/c.txt", "out/all.txt", "out/b.gen", "out/c.gen"}; !slices.Equal(committed, want) {
		t.Fatalf("committed %v, want %v", committed, want)
	}
	if !slices.Equal(gated[len(gated)-1], change.Files) {
		t.Fatalf("gate saw %v", gated[len(gated)-1])
	}
	if status := gitT(t, repo.Main, "status", "--porcelain"); status != "" {
		t.Fatalf("landing left %q", status)
	}
	if pushed := gitT(t, repo.Main, "--git-dir", remote, "rev-parse", Trunk); pushed != gitT(t, repo.Main, "rev-parse", "HEAD") {
		t.Fatal("composed landing not pushed")
	}
}

func TestFailedLandingRestoresDerivedRoots(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	writeFixture(t, filepath.Join(repo.Main, "in", "a.txt"), "a1\n")
	writeFixture(t, filepath.Join(repo.Main, "in", "b.txt"), "b1\n")
	generateFixture(t, repo.Main)
	gitT(t, repo.Main, "add", "in", "out")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "generated")
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	prior := gitT(t, repo.Main, "rev-parse", "HEAD")
	path, err := repo.Add(ctx, "feature", "HEAD", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(path, "in", "a.txt"), "a2\n")
	writeFixture(t, filepath.Join(path, "in", "d.txt"), "d1\n")
	for _, name := range []string{"in/b.txt", "out/b.gen"} {
		if err := os.Remove(filepath.Join(path, name)); err != nil {
			t.Fatal(err)
		}
	}
	generateFixture(t, path)
	change, err := repo.Change(ctx, path, nil, Derivation{Roots: []string{"out"}})
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func(when string) {
		t.Helper()
		if head := gitT(t, repo.Main, "rev-parse", "HEAD"); head != prior {
			t.Fatalf("%s: HEAD moved to %s", when, head)
		}
		if status := gitT(t, repo.Main, "status", "--porcelain", "--untracked-files=all"); status != "" {
			t.Fatalf("%s: rollback left %q", when, status)
		}
		if all := readFixture(t, filepath.Join(repo.Main, "out", "all.txt")); all != "a1\nb1\n" {
			t.Fatalf("%s: derived output not restored: %q", when, all)
		}
	}
	err = repo.Land(ctx, change, "x", func([]string) error {
		generateFixture(t, repo.Main)
		return errors.New("red")
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("gate failure: %v", err)
	}
	unchanged("failed gate")

	// A tree whose only change is generated output it never regenerated
	// lands nothing: regeneration from main reproduces main.
	if err := os.WriteFile(filepath.Join(path, "out", "all.txt"), []byte("hand edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	only, err := repo.Change(ctx, path, []string{"out"}, Derivation{Roots: []string{"out"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(only.Files) != 0 || len(only.Patch) != 0 {
		t.Fatalf("generated output reached the patch: %v", only.Files)
	}
	err = repo.Land(ctx, only, "x", func([]string) error {
		generateFixture(t, repo.Main)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "nothing to land") {
		t.Fatalf("derived-only landing: %v", err)
	}
	unchanged("derived-only landing")
}
