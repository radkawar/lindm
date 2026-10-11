package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/worktree"
)

const landUsage = `Usage: go run ./cmd/dev land -from WORKTREE [-paths a,b,...] [-timeout D]
       go run ./cmd/dev gate-commit -m MESSAGE [-timeout D]

The only way to change the shared main checkout. Both commands hold the
exclusive lock <main>/.git/lindm-landing.lock, so no landing interleaves with
another landing or with a gated commit.

  land         Apply WORKTREE's complete change against main (commits since
               its merge base, staged, unstaged and untracked files, renames
               and deletions; -paths limits it) to the shared tree. A conflict
               refuses with nothing applied. Then run the quick gate on the
               touched files in the shared tree: go build ./..., golangci-lint
               run (default and integration tags) and fmt on touched packages,
               buf format/lint when protos changed, prettier and markdownlint on
               touched docs/web files, and race tests of touched packages. On
               any gate failure the change is reversed automatically.
  gate-commit  Run make check in the shared tree and, only if green, commit
               every change with MESSAGE.
`

func lockedRepository(ctx context.Context) (*worktree.Repository, func() error, error) {
	repo, err := worktree.Open(ctx, ".")
	if err != nil {
		return nil, nil, err
	}
	unlock, err := repo.Lock(ctx, func(holder string) {
		fmt.Fprintf(os.Stderr, "waiting for %s (held by %s)\n", repo.LockPath(), holder)
	})
	if err != nil {
		return nil, nil, err
	}
	return repo, unlock, nil
}

func runLand(args []string) (resultErr error) {
	flags := flag.NewFlagSet("land", flag.ContinueOnError)
	from := flags.String("from", "", "private worktree to land")
	paths := flags.String("paths", "", "comma-separated paths limiting the change")
	timeout := flags.Duration("timeout", time.Hour, "overall deadline, including waiting for the lock")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), landUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if *from == "" || flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("land requires -from WORKTREE, no positional arguments and a positive timeout")
	}
	var limit []string
	if *paths != "" {
		limit = strings.Split(*paths, ",")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	repo, unlock, err := lockedRepository(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	change, err := repo.Change(ctx, *from, limit)
	if err != nil {
		return err
	}
	if len(change.Files) == 0 {
		return fmt.Errorf("%s has no change against %s", *from, worktree.Trunk)
	}
	if err := repo.Apply(ctx, change.Patch, false); err != nil {
		return fmt.Errorf("refused, nothing applied (rebase %s onto %s): %w", *from, worktree.Trunk, err)
	}
	fmt.Printf("land: applied %d files from %s (base %.12s); gating in %s\n", len(change.Files), *from, change.Base, repo.Main)
	if err := quickGate(ctx, repo.Main, change.Files); err != nil {
		// Rollback outlives an interrupted or expired gate.
		rollback, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if reverseErr := repo.Apply(rollback, change.Patch, true); reverseErr != nil {
			return fmt.Errorf("gate failed: %w; ROLLBACK FAILED, the shared tree still holds the change: %w", err, reverseErr)
		}
		return fmt.Errorf("gate failed, change rolled back: %w", err)
	}
	fmt.Printf("land: %d files landed from %s\n", len(change.Files), *from)
	return nil
}

func runGateCommit(args []string) (resultErr error) {
	flags := flag.NewFlagSet("gate-commit", flag.ContinueOnError)
	message := flags.String("m", "", "commit message")
	timeout := flags.Duration("timeout", time.Hour, "overall deadline, including waiting for the lock")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), landUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if strings.TrimSpace(*message) == "" || flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("gate-commit requires -m MESSAGE, no positional arguments and a positive timeout")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	repo, unlock, err := lockedRepository(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if err := stream(ctx, repo.Main, nil, "make", "check", "GOLANGCI_RUN_FLAGS=--allow-parallel-runners"); err != nil {
		return fmt.Errorf("make check failed, nothing committed: %w", err)
	}
	if err := stream(ctx, repo.Main, nil, "git", "add", "--all"); err != nil {
		return err
	}
	return stream(ctx, repo.Main, nil, "git", "commit", "--quiet", "-m", *message)
}

// quickGate is the AGENTS.md pre-landing gate scoped to the touched files.
func quickGate(ctx context.Context, root string, files []string) error {
	var packages, goDirs, protos, docs, markdown []string
	for _, file := range files {
		switch filepath.Ext(file) {
		case ".go":
			dir := filepath.Dir(file)
			if hasGo(filepath.Join(root, dir)) && !slices.Contains(goDirs, dir) {
				goDirs = append(goDirs, dir)
				packages = append(packages, "./"+dir)
			}
		case ".proto":
			protos = append(protos, file)
		case ".md":
			markdown = append(markdown, file)
			docs = append(docs, file)
		case ".ts", ".tsx", ".js", ".mjs", ".json", ".css", ".html", ".yaml", ".yml":
			docs = append(docs, file)
		}
	}
	existing := func(files []string) []string {
		return slices.DeleteFunc(slices.Clone(files), func(file string) bool {
			_, err := os.Stat(filepath.Join(root, file))
			return err != nil
		})
	}
	docs, markdown = existing(docs), existing(markdown)
	lint := filepath.Join(root, ".tools", "bin", "golangci-lint")
	steps := [][]string{{"go", "build", "./..."}}
	if len(packages) != 0 {
		steps = append(steps,
			append([]string{lint, "run", "--allow-parallel-runners"}, packages...),
			append([]string{lint, "run", "--allow-parallel-runners", "--build-tags", "integration"}, packages...),
		)
	}
	if len(protos) != 0 {
		buf := filepath.Join(root, ".tools", "bin", "buf")
		steps = append(steps, []string{buf, "format", "--diff", "--exit-code"}, []string{buf, "lint"})
	}
	if len(docs) != 0 {
		steps = append(steps, append([]string{"npx", "prettier", "--check", "--ignore-unknown"}, docs...))
	}
	if len(markdown) != 0 {
		steps = append(steps, append([]string{"npx", "markdownlint"}, markdown...))
	}
	for _, step := range steps {
		if err := stream(ctx, root, nil, step[0], step[1:]...); err != nil {
			return err
		}
	}
	if len(goDirs) != 0 {
		if err := formatted(ctx, root, lint, goDirs); err != nil {
			return err
		}
		return stream(ctx, root, nil, "go", append([]string{"test", "-race", "-count=1"}, packages...)...)
	}
	return nil
}

// formatted fails when golangci-lint fmt would change a touched package.
func formatted(ctx context.Context, root, lint string, dirs []string) error {
	diff, err := output(ctx, root, lint, append([]string{"fmt", "--diff"}, dirs...)...)
	if err != nil {
		return err
	}
	if diff != "" {
		return fmt.Errorf("golangci-lint fmt would change touched packages:\n%s", diff)
	}
	return nil
}

func hasGo(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		return !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go")
	})
}
