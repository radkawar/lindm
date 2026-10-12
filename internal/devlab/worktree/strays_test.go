package worktree

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLandRefusalTracesStraysToTheirWorktree(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	add := func(name string) string {
		t.Helper()
		path, err := repo.Add(ctx, name, "HEAD", io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	write := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(dir, name string) {
		t.Helper()
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	culprit, partial, bystander := add("Culprit"), add("Partial"), add("Bystander")
	// The culprit's edits also went into the shared checkout.
	for _, dir := range []string{culprit, repo.Main} {
		write(dir, "README", "README\nadded by the culprit agent\n")
		write(dir, "notes.txt", "notes from the culprit agent\n")
		remove(dir, "package.json")
	}
	// Another tree holds the same README hunk among further work.
	write(partial, "README", "README\nadded by the culprit agent\nand further work\n")
	write(repo.Main, "orphan.txt", "nobody's worktree has this\n")
	write(bystander, "feature.txt", "the work being landed\n")
	change, err := repo.Change(ctx, bystander, nil, Derivation{})
	if err != nil {
		t.Fatal(err)
	}

	err = repo.Land(ctx, change, "land the feature", func([]string) error {
		t.Fatal("gated over a dirty shared checkout")
		return nil
	})
	if err == nil {
		t.Fatal("dirty shared checkout accepted")
	}
	t.Logf("refusal:\n%v", err)
	lines := map[string]string{}
	for line := range strings.Lines(err.Error()) {
		if fields := strings.Fields(line); len(fields) >= 2 {
			lines[fields[1]] = line
		}
	}
	expect := func(path string, parts ...string) {
		t.Helper()
		line, ok := lines[path]
		if !ok {
			t.Fatalf("refusal does not list %s:\n%v", path, err)
		}
		for _, part := range parts {
			if !strings.Contains(line, part) {
				t.Fatalf("refusal line for %s lacks %q: %s", path, part, line)
			}
		}
	}
	culpritSource := "likely from " + culprit + " (owner Culprit, identical file)"
	expect("README", "modified ", culpritSource, "also held by "+partial+" (owner Partial, same hunks)")
	expect("notes.txt", "modified ", culpritSource)
	expect("package.json", "(deleted)", culpritSource)
	expect("orphan.txt", "modified ", "no private worktree holds this change")
	if strings.Contains(err.Error(), bystander) {
		t.Fatalf("refusal blames the untouched tree:\n%v", err)
	}
	if status := gitT(t, repo.Main, "status", "--porcelain", "--", "feature.txt"); status != "" {
		t.Fatalf("refused landing applied %q", status)
	}
}
