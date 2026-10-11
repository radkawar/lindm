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
	"lindm/internal/labexec"
)

const landUsage = `Usage: go run ./cmd/dev land -from WORKTREE -m MESSAGE [-paths a,b,...] [-timeout D]
       go run ./cmd/dev gate-commit -m MESSAGE [-timeout D]

The only way to change the shared main checkout. Both commands hold the
exclusive lock <main>/.git/lindm-landing.lock, so no landing interleaves with
another landing or with a gated commit.

  land         Refuse unless the shared checkout is on main, clean and
               contains its freshly fetched upstream (local commits ahead of
               it are pushed too). Apply WORKTREE's complete change
               against main (commits since its merge base, staged, unstaged and
               untracked files, renames and deletions; -paths limits it). A
               conflict refuses with nothing applied. Run the quick gate on the
               touched files: go build ./..., golangci-lint run (default and
               integration tags) and fmt on touched packages, buf format/lint
               when protos changed, prettier and markdownlint on touched
               docs/web files, generate-docs -check, and race tests of the
               touched packages and every module package whose build or
               tests import them, directly or transitively. Then commit
               exactly those files with MESSAGE and push to main's upstream
               (hooks skipped: the gate just ran). Any failure rolls back.
  gate-commit  Run the full make check in the shared tree and, only if green,
               commit every change with MESSAGE (post-hoc gate).
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
	message := flags.String("m", "", "descriptive commit message for the landing")
	timeout := flags.Duration("timeout", time.Hour, "overall deadline, including waiting for the lock")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), landUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if *from == "" || strings.TrimSpace(*message) == "" || flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("land requires -from WORKTREE, -m MESSAGE, no positional arguments and a positive timeout")
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
	// Every worktree links the shared install, so it must match the lock the
	// gate runs against: repair drift first, reinstall when this landing
	// changes the manifests.
	if err := syncNodeModules(ctx, repo.Main, false); err != nil {
		return err
	}
	fmt.Printf("land: %d files from %s (base %.12s); gating in %s\n", len(change.Files), *from, change.Base, repo.Main)
	manifests := slices.ContainsFunc(change.Files, func(file string) bool { return file == "package.json" || file == "package-lock.json" })
	if err := repo.Land(ctx, change, *message, func(files []string) error {
		if manifests {
			if err := syncNodeModules(ctx, repo.Main, true); err != nil {
				return err
			}
		}
		return quickGate(ctx, repo.Main, files)
	}); err != nil {
		if manifests {
			// The rollback restored the previous manifests; match them again.
			return errors.Join(err, syncNodeModules(context.WithoutCancel(ctx), repo.Main, false))
		}
		return err
	}
	head, err := output(ctx, repo.Main, "git", "log", "--oneline", "-1")
	if err != nil {
		return err
	}
	_, err = fmt.Printf("land: committed and pushed %s\n", head)
	return err
}

// syncNodeModules makes the shared checkout's node_modules match its
// package-lock.json: npm ci when forced or when npm ls finds the install
// missing, extraneous or mismatched against the lock.
func syncNodeModules(ctx context.Context, root string, force bool) error {
	if !force {
		if err := labexec.Run(ctx, labexec.Command{Path: "npm", Args: []string{"ls", "--all", "--silent"}, Dir: root}); err == nil {
			return nil
		}
		fmt.Printf("land: %s/node_modules does not match package-lock.json; reinstalling\n", root)
	}
	if err := stream(ctx, root, nil, "npm", "ci", "--ignore-scripts"); err != nil {
		return fmt.Errorf("sync shared node_modules: %w", err)
	}
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
	// Generated docs read state many landings change; check them every time.
	steps := [][]string{{"go", "build", "./..."}, {"go", "run", "./cmd/dev", "generate-docs", "-check"}}
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
		affected, err := dependents(ctx, root, packages)
		if err != nil {
			return err
		}
		fmt.Printf("land: race tests for %d touched and %d dependent packages\n", len(packages), len(affected)-len(packages))
		return stream(ctx, root, nil, "go", append([]string{"test", "-race", "-count=1"}, affected...)...)
	}
	return nil
}

// dependents returns the touched packages plus every module package whose
// build or tests reach one of them (directly or transitively, through its own
// imports or its test files' imports), so a change is tested where it is used.
func dependents(ctx context.Context, root string, touched []string) ([]string, error) {
	module, err := output(ctx, root, "go", "list", "-m")
	if err != nil {
		return nil, err
	}
	listing, err := output(ctx, root, "go", "list", "-e", "-f", "{{.ImportPath}}|{{join .Deps \" \"}}|{{join .TestImports \" \"}} {{join .XTestImports \" \"}}", "./...")
	if err != nil {
		return nil, err
	}
	deps := map[string]map[string]bool{}
	tests := map[string][]string{}
	for line := range strings.Lines(listing) {
		fields := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(fields) != 3 {
			continue
		}
		set := map[string]bool{fields[0]: true}
		for _, dep := range strings.Fields(fields[1]) {
			set[dep] = true
		}
		deps[fields[0]], tests[fields[0]] = set, strings.Fields(fields[2])
	}
	targets := map[string]bool{}
	for _, pkg := range touched {
		if dir := filepath.ToSlash(filepath.Clean(pkg)); dir == "." {
			targets[module] = true
		} else {
			targets[module+"/"+dir] = true
		}
	}
	reaches := func(pkg string) bool {
		for target := range targets {
			if deps[pkg][target] {
				return true
			}
		}
		return false
	}
	var affected []string
	for pkg := range deps {
		hit := reaches(pkg)
		for _, imported := range tests[pkg] {
			hit = hit || reaches(imported)
		}
		if hit {
			affected = append(affected, "./"+strings.TrimPrefix(strings.TrimPrefix(pkg, module), "/"))
		}
	}
	slices.Sort(affected)
	return affected, nil
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
