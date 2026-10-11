package worktree

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestAuditRecognizesCopyLandedWork(t *testing.T) {
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
	snapshot, copied, partial, unlanded, superseded, snapshotMidEdit := add("snapshot"), add("copied"), add("partial"), add("unlanded"), add("superseded"), add("midedit")
	// copied: a committed edit and an untracked file, both later copied into main by hand.
	write(copied, "README", "shared edit\n")
	gitT(t, copied, "commit", "--quiet", "-am", "private commit")
	write(copied, "added.txt", "new file\n")
	write(partial, "README", "shared edit\n")
	write(partial, "private.txt", "only here\n")
	write(unlanded, "package.json", "private change\n")
	write(superseded, "package-lock.json", "copied then rewritten\n")
	write(snapshotMidEdit, "README", "line one landed\nline two landed\n")
	write(repo.Main, "README", "shared edit\n")
	write(repo.Main, "added.txt", "new file\n")
	write(repo.Main, "later.txt", "main moved on\n")
	gitT(t, repo.Main, "add", "README", "added.txt", "later.txt")
	gitT(t, repo.Main, "commit", "--quiet", "-m", "copy-landed")
	write(repo.Main, "package-lock.json", "copied then rewritten\n")
	gitT(t, repo.Main, "commit", "--quiet", "-am", "lane snapshot landed")
	write(repo.Main, "package-lock.json", "main refactored it later\n")
	write(repo.Main, "README", "header added by main\nline one landed\nline two landed\nfooter\n")
	gitT(t, repo.Main, "commit", "--quiet", "-am", "later refactor")

	verdicts := map[string]Audit{}
	if err := repo.AuditAll(ctx, []string{t.TempDir()}, func(a Audit) error { verdicts[filepath.Base(a.Path)] = a; return nil }); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]Verdict{"snapshot": Snapshot, "copied": Landed, "partial": Partial, "unlanded": Unlanded, "superseded": Landed, "midedit": Landed} {
		if got := verdicts[name]; got.Verdict != want {
			t.Fatalf("%s: %+v, want %s", name, got, want)
		}
	}
	if got := verdicts["partial"].Unlanded; !slices.Equal(got, []string{"private.txt"}) {
		t.Fatalf("partial unlanded files %v", got)
	}
	unregistered := 0
	for _, audit := range verdicts {
		if audit.Verdict == Unregistered {
			unregistered++
		}
	}
	if unregistered != 1 {
		t.Fatalf("extra directory not reported as unregistered: %+v", verdicts)
	}

	decisions := map[string]Decision{}
	if err := repo.Prune(ctx, nil, PruneOptions{Now: time.Now()}, func(d Decision) error { decisions[filepath.Base(d.Path)] = d; return nil }); err != nil {
		t.Fatal(err)
	}
	if !decisions["copied"].Removed || decisions["copied"].Archive == "" {
		t.Fatalf("copy-landed dirty tree not archived and removed: %+v", decisions["copied"])
	}
	if !decisions["snapshot"].Removed || decisions["partial"].Removed || decisions["unlanded"].Removed {
		t.Fatalf("prune decisions %+v", decisions)
	}
	for _, path := range []string{partial, unlanded} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unlanded work removed: %v", err)
		}
	}
	_ = snapshot
}

func TestOwnerStripsTaskNoise(t *testing.T) {
	for path, want := range map[string]string{
		"/c/lindm-ospatch":                "ospatch",
		"/w/ParityResources-land":         "ParityResources",
		"/c/lindm-labhosts-20261010":      "labhosts",
		"/c/lindm-desksess-snap1":         "desksess",
		"/w/U26CloudLanes-pin2":           "U26CloudLanes",
		"/c/lindm-recovery-init.pristine": "recovery-init",
		"/c/ospatch-lane-s3":              "ospatch-lane",
	} {
		if got := owner(path); got != want {
			t.Errorf("owner(%s) = %q, want %q", path, got, want)
		}
	}
}
