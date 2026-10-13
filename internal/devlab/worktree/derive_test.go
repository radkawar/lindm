package worktree

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"lindm/internal/gendoc"
)

// mergeLines is a stand-in for a structural ledger merge: one record per line,
// theirs' additions appended and removals dropped.
func mergeLines(current, base, theirs []byte) ([]byte, error) {
	lines := func(data []byte) []string { return strings.Fields(string(data)) }
	merged, before, after := lines(current), lines(base), lines(theirs)
	for _, line := range before {
		if !slices.Contains(after, line) {
			merged = slices.DeleteFunc(merged, func(l string) bool { return l == line })
		}
	}
	for _, line := range after {
		if !slices.Contains(before, line) && !slices.Contains(merged, line) {
			merged = append(merged, line)
		}
	}
	return []byte(strings.Join(merged, "\n") + "\n"), nil
}

// renderDoc is a stand-in for generate-docs: the generated table in doc.md
// lists the ledger padded to its widest record, so every new record can
// rewrite every row.
func renderDoc(t *testing.T, dir string) {
	t.Helper()
	ledger, err := os.ReadFile(filepath.Join(dir, "ledger.txt"))
	if err != nil {
		t.Fatal(err)
	}
	records := strings.Fields(string(ledger))
	width := 0
	for _, r := range records {
		width = max(width, len(r))
	}
	var table strings.Builder
	for _, r := range records {
		table.WriteString("| " + r + strings.Repeat(" ", width-len(r)) + " |\n")
	}
	path := filepath.Join(dir, "doc.md")
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	next, err := gendoc.Replace(doc, "table", table.String())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, path, string(next))
}

func TestLandsMergeLedgersAndRegenerateDocuments(t *testing.T) {
	repo := fixtureRepository(t)
	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitT(t, repo.Main, "init", "--quiet", "--bare", remote)
	gitT(t, repo.Main, "remote", "add", "lindm", remote)
	writeFixture(t, filepath.Join(repo.Main, "ledger.txt"), "x\ny\n")
	writeFixture(t, filepath.Join(repo.Main, "doc.md"), "intro\n\n<!-- BEGIN GENERATED table -->\n<!-- END GENERATED table -->\n\noutro\n")
	renderDoc(t, repo.Main)
	gitT(t, repo.Main, "add", "ledger.txt", "doc.md")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "ledger")
	gitT(t, repo.Main, "push", "--quiet", "--set-upstream", "lindm", Trunk)
	derivation := Derivation{Merge: map[string]func(current, base, theirs []byte) ([]byte, error){"ledger.txt": mergeLines}, Blank: func(_ string, content []byte) []byte { return gendoc.Blank(content) }}
	tree := func(name, record, from, to string) string {
		t.Helper()
		path, err := repo.Add(ctx, name, "HEAD", io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		ledger := readFixture(t, filepath.Join(path, "ledger.txt"))
		writeFixture(t, filepath.Join(path, "ledger.txt"), ledger+record+"\n")
		doc := readFixture(t, filepath.Join(path, "doc.md"))
		writeFixture(t, filepath.Join(path, "doc.md"), strings.Replace(doc, from, to, 1))
		renderDoc(t, path)
		return path
	}
	// Both record a run and edit the document's prose; each record widens
	// every row of the generated table.
	first := tree("first", "longer-record", "intro\n", "intro by first\n")
	second := tree("second", "the-longest-record", "outro\n", "outro by second\n")
	regenerate := func([]string) error { renderDoc(t, repo.Main); return nil }

	change, err := repo.Change(ctx, first, nil, derivation)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(change.Files, []string{"doc.md"}) || len(change.Merged) != 1 || change.Merged[0].Path != "ledger.txt" {
		t.Fatalf("change files %v, merged %v", change.Files, change.Merged)
	}
	if bytes.Contains(change.Patch, []byte("longer-record")) {
		t.Fatalf("the patch carries generated content:\n%s", change.Patch)
	}
	if err := repo.Land(ctx, change, "first", regenerate); err != nil {
		t.Fatal(err)
	}
	// Without derivation the second landing conflicts on both files.
	whole, err := repo.Change(ctx, second, nil, Derivation{})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Land(ctx, whole, "whole", regenerate); err == nil || !strings.Contains(err.Error(), "nothing applied") {
		t.Fatalf("conflicting ledger and table applied: %v", err)
	}
	change, err = repo.Change(ctx, second, nil, derivation)
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
	}
	err = repo.Land(ctx, change, "x", func(files []string) error {
		renderDoc(t, repo.Main)
		return errors.New("red")
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") || strings.Contains(err.Error(), "ROLLBACK FAILED") {
		t.Fatalf("gate failure: %v", err)
	}
	clean("failed gate")
	err = repo.Land(ctx, change, "x", func(files []string) error {
		renderDoc(t, repo.Main)
		writeFixture(t, filepath.Join(repo.Main, "README"), "edited by the gate\n")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "by something other than the landing") {
		t.Fatalf("gate edit accepted: %v", err)
	}
	clean("gate edit")

	var gated []string
	if err := repo.Land(ctx, change, "second", func(files []string) error {
		gated = files
		return regenerate(files)
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gated, []string{"doc.md", "ledger.txt"}) {
		t.Fatalf("gate saw %v", gated)
	}
	if ledger := readFixture(t, filepath.Join(repo.Main, "ledger.txt")); ledger != "x\ny\nlonger-record\nthe-longest-record\n" {
		t.Fatalf("merged ledger %q", ledger)
	}
	doc := readFixture(t, filepath.Join(repo.Main, "doc.md"))
	if !strings.Contains(doc, "intro by first\n") || !strings.Contains(doc, "outro by second\n") || !strings.Contains(doc, "| longer-record      |") {
		t.Fatalf("composed document:\n%s", doc)
	}
	if status := gitT(t, repo.Main, "status", "--porcelain"); status != "" {
		t.Fatalf("landing left %q", status)
	}
}
