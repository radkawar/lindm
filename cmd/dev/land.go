// SPDX-License-Identifier: Apache-2.0

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
	"strconv"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/toolchain"
	"lindm/internal/devlab/worktree"
	"lindm/internal/gendoc"
	"lindm/internal/labexec"
)

const landUsage = `Usage: go run ./cmd/dev land -from WORKTREE -m MESSAGE [-paths a,b,...] [-timeout D]
       go run ./cmd/dev gate-commit -m MESSAGE [-timeout D]

The only way to change the shared main checkout. Both commands hold the
exclusive lock <main>/.git/lindm-landing.lock, so no landing interleaves with
another landing or with a gated commit. Outside them the checkout's tracked
files are read-only (dev protect); under the lock both restore u+w, then
protect again however they end (commit, refusal, rollback, interrupt).

  land         Refuse unless the shared checkout is on main, clean and
               contains its freshly fetched upstream (local commits ahead of
               it are pushed too); a dirty refusal lists each file with its
               mtime and the private worktree whose copy holds the same
               change. Apply WORKTREE's complete change
               against main (commits since its merge base, staged, unstaged and
               untracked files, renames and deletions; -paths limits it). A
               conflict refuses with nothing applied. Generator output (the
               out directories of buf.gen.yaml and sqlc.yaml) is derived: it
               is left out of the patch and regenerated in the shared tree by
               make generate-code; generate-docs blocks are emptied in the
               patch and refilled by generate-docs, and lab/ledger.json is
               merged record by record, so proto/SQL and ledger landings
               compose. Run the quick gate on the
               touched files: go build ./..., golangci-lint run (default and
               integration,production_signing tags) and fmt on touched packages, buf format/lint
               when protos changed, prettier and markdownlint on touched
               docs/web files, generate-docs -check, and race tests of the
               touched packages and every module package whose build or
               tests import them, directly or transitively (each test binary
               bounded by the 45m integration lock budget). Then commit
               exactly those files with MESSAGE and push to main's upstream
               (hooks skipped: the gate just ran). Any failure rolls back.
  gate-commit  Run the full make check in the shared tree and, only if green,
               commit exactly the change it checked with MESSAGE (post-hoc
               gate). Both commit by explicit path only, and refuse, naming
               the files, if anything else in the tree changed meanwhile.
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
	shared, err := worktree.Open(ctx, ".")
	if err != nil {
		return err
	}
	// The gate runs the shared checkout's pinned Node and Go, whatever the
	// lander's PATH puts first; resolved before queueing for the lock.
	if err := toolchain.Apply(ctx, shared.Main); err != nil {
		return err
	}
	// Collect before queueing for the lock, so a short disk never fails a
	// gate halfway and no landing waits behind a collection.
	collectIfLow(ctx, shared.Main)
	repo, unlock, err := lockedRepository(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	// Tracked files are read-only outside landings (dev protect); Writable
	// re-protects them whether the landing commits, rolls back or is refused.
	return repo.Writable(ctx, func() error { return land(ctx, repo, *from, limit, *message) })
}

// land applies, gates, commits and pushes the worktree's change; the caller
// holds the landing lock with the tracked files writable.
func land(ctx context.Context, repo *worktree.Repository, from string, limit []string, message string) error {
	// Derived content is produced in the shared checkout rather than applied,
	// so concurrent landings compose instead of conflicting on it: generator
	// output is regenerated from main plus the change, the matrix ledger is
	// merged record by record, and generated document regions (the lab
	// matrix table and every generate-docs block) are regenerated.
	roots, err := derivedRoots(repo.Main, from)
	if err != nil {
		return err
	}
	derivation := worktree.Derivation{
		Roots: roots,
		Merge: map[string]func(current, base, theirs []byte) ([]byte, error){ledgerFile: mergeLedger},
		Blank: func(_ string, content []byte) []byte { return gendoc.Blank(content) },
	}
	change, err := repo.Change(ctx, from, limit, derivation)
	if err != nil {
		return err
	}
	if len(change.Files) == 0 && len(change.Derived) == 0 && len(change.Merged) == 0 {
		return fmt.Errorf("%s has no change against %s", from, worktree.Trunk)
	}
	// Every worktree links the shared install, so it must match the lock the
	// gate runs against: repair drift first, reinstall when this landing
	// changes the manifests.
	if err := syncNodeModules(ctx, repo.Main, false); err != nil {
		return err
	}
	fmt.Printf("land: %d files from %s (base %.12s), %d generated files there held out for regeneration, %d merged; gating in %s\n", len(change.Files), from, change.Base, len(change.Derived), len(change.Merged), repo.Main)
	manifests := slices.ContainsFunc(change.Files, func(file string) bool { return file == "package.json" || file == "package-lock.json" })
	if err := repo.Land(ctx, change, message, func(files []string) error {
		if manifests {
			if err := syncNodeModules(ctx, repo.Main, true); err != nil {
				return err
			}
		}
		regenerated, err := regenerate(ctx, repo, change)
		if err != nil {
			return err
		}
		// After code generation and the ledger merge: generated documents
		// derive from both. The quick gate's generate-docs -check verifies.
		if err := stream(ctx, repo.Main, nil, "go", "run", "./cmd/devenv", "generate-docs"); err != nil {
			return fmt.Errorf("regenerate documents: %w", err)
		}
		return quickGate(ctx, repo.Main, slices.Concat(files, regenerated))
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
// package-lock.json: a staged npm ci, published atomically, when forced or
// when npm ls finds the install missing, extraneous or mismatched.
func syncNodeModules(ctx context.Context, root string, force bool) error {
	if !force {
		if err := labexec.Run(ctx, labexec.Command{Path: "npm", Args: []string{"ls", "--all", "--silent"}, Dir: root}); err == nil {
			return nil
		}
		fmt.Printf("land: %s/node_modules does not match package-lock.json; reinstalling\n", root)
	}
	// Staged and exchanged atomically: readers never see a partial tree and a
	// failed install keeps the previous one.
	if err := worktree.SyncNodeModules(ctx, root, os.Stdout); err != nil {
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
	shared, err := worktree.Open(ctx, ".")
	if err != nil {
		return err
	}
	if err := toolchain.Apply(ctx, shared.Main); err != nil {
		return err
	}
	repo, unlock, err := lockedRepository(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	// Writable re-protects the tree however the gate ends; GateCommit commits
	// exactly the change make check verified, refusing anything written into
	// the tree meanwhile.
	return repo.Writable(ctx, func() error {
		return repo.GateCommit(ctx, *message, func() error {
			return stream(ctx, repo.Main, nil, "make", "check", "GOLANGCI_RUN_FLAGS=--allow-parallel-runners")
		})
	})
}

// quickGate is the AGENTS.md pre-landing gate scoped to the touched files.
func quickGate(ctx context.Context, root string, files []string) error {
	if err := migrationsAhead(ctx, root, files); err != nil {
		return err
	}
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
	steps := [][]string{{"go", "build", "./..."}, {"go", "run", "./cmd/devenv", "generate-docs", "-check"}}
	if len(packages) != 0 {
		steps = append(steps,
			append([]string{lint, "run", "--allow-parallel-runners"}, packages...),
			append([]string{lint, "run", "--allow-parallel-runners", "--build-tags", "integration,production_signing"}, packages...),
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
	steps = append(steps, webLint(existing(files))...)
	for _, step := range steps {
		if err := stream(ctx, root, nil, step[0], step[1:]...); err != nil {
			return err
		}
	}
	if len(goDirs) != 0 {
		if err := formatted(ctx, root, lint, goDirs); err != nil {
			return err
		}
	}
	// Packages that embed or open a changed data file are raced like touched
	// ones, together with everything that imports them.
	readers, err := dataReaders(ctx, root, files)
	if err != nil {
		return err
	}
	raced := slices.Clone(packages)
	for _, dir := range readers {
		if !slices.Contains(goDirs, dir) {
			raced = append(raced, "./"+dir)
		}
	}
	if len(raced) != 0 {
		affected, err := dependents(ctx, root, raced)
		if err != nil {
			return err
		}
		fmt.Printf("land: race tests for %d touched, %d data-reading and %d dependent packages\n", len(packages), len(raced)-len(packages), len(affected)-len(raced))
		// A loaded host stretches race suites far past go test's default 10m
		// per-binary deadline (internal/agent/executor has taken ~15m: every
		// journal load re-verifies its signed trust chain, CPU-bound under
		// -race), so a test binary gets the integration lock's budget, the
		// bound any one suite is held to; the landing's -timeout still bounds
		// the gate.
		if err := stream(ctx, root, nil, "go", append([]string{"test", "-race", "-count=1", "-timeout=" + raceTestTimeout.String()}, affected...)...); err != nil {
			return err
		}
	}
	if touchesConsole(files) {
		return checkWeb(ctx, root)
	}
	return nil
}

// webLint is npm run lint:web (CI's console lint) scoped like the rest of the
// gate: ESLint on the touched console sources, and the CSS colour scan when
// stylesheets change. The rules are syntactic (no type-aware rules), so a
// file's verdict does not depend on untouched files; a change to the rules or
// their configuration relints the whole console instead.
func webLint(files []string) [][]string {
	var sources []string
	stylesheets, rules := false, false
	for _, file := range files {
		switch {
		case file == "eslint.config.mjs" || file == "package.json" || file == "package-lock.json" || strings.HasPrefix(file, "web/eslint/"):
			rules = true
		case !strings.HasPrefix(file, "web/src/"):
		case filepath.Ext(file) == ".css":
			stylesheets = true
		case slices.Contains([]string{".ts", ".tsx", ".js", ".mjs"}, filepath.Ext(file)):
			sources = append(sources, file)
		}
	}
	if rules {
		return [][]string{{"npm", "run", "--silent", "lint:web"}}
	}
	var steps [][]string
	if len(sources) != 0 {
		steps = append(steps, append([]string{"npx", "eslint", "--max-warnings=0", "--no-warn-ignored"}, sources...))
	}
	if stylesheets {
		steps = append(steps, []string{"node", "web/eslint/scan-css-colours.mjs"})
	}
	return steps
}

// touchesConsole reports whether a landing changes the console or its
// browser acceptance journey.
func touchesConsole(files []string) bool {
	return slices.ContainsFunc(files, func(file string) bool {
		return strings.HasPrefix(file, "web/src/") || strings.HasPrefix(file, "web/acceptance/")
	})
}

// checkWeb runs the real browser journey against a freshly built server with
// the embedded console (make check-web), in Chromium only to keep the landing
// gate bounded; release acceptance still covers every engine. Its evidence
// goes to an ignored artifacts directory, so the shared checkout stays clean.
func checkWeb(ctx context.Context, root string) error {
	fmt.Println("land: console changed; running make check-web (Chromium, web-only)")
	evidence := filepath.Join(root, "artifacts", "land-check-web-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := stream(ctx, root, nil, "make", "--no-print-directory", "check-web", "ACCEPTANCE_EVIDENCE="+evidence, "ACCEPTANCE_FLAGS=-engines chromium"); err != nil {
		return fmt.Errorf("check-web (evidence %s): %w", evidence, err)
	}
	return nil
}

// migrationVersion parses the goose version of db/migrations/NNNNN_name.sql.
func migrationVersion(name string) (int, bool) {
	digits, _, ok := strings.Cut(filepath.Base(name), "_")
	version, err := strconv.Atoi(digits)
	return version, ok && err == nil && strings.HasSuffix(name, ".sql")
}

// migrationsAhead refuses a landing that adds a migration whose version is not
// above every migration already on main (HEAD, before the landing commits):
// goose would apply it out of order, or two landings would claim one number.
func migrationsAhead(ctx context.Context, root string, files []string) error {
	const dir = "db/migrations/"
	var added []string
	for _, file := range files {
		if !strings.HasPrefix(file, dir) || strings.Contains(strings.TrimPrefix(file, dir), "/") {
			continue
		}
		if _, ok := migrationVersion(file); !ok {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, file)); err != nil {
			continue // deleted by the landing
		}
		if _, err := output(ctx, root, "git", "cat-file", "-e", "HEAD:"+file); err == nil {
			continue // already on main: an edit, not an addition
		}
		added = append(added, file)
	}
	if len(added) == 0 {
		return nil
	}
	listing, err := output(ctx, root, "git", "ls-tree", "--name-only", "HEAD", dir)
	if err != nil {
		return err
	}
	highest := 0
	for name := range strings.Lines(listing) {
		if version, ok := migrationVersion(strings.TrimSpace(name)); ok {
			highest = max(highest, version)
		}
	}
	// Suggested numbers follow main and every migration this landing adds, so
	// no suggestion collides with an accepted addition.
	next := highest + 1
	for _, file := range added {
		version, _ := migrationVersion(file)
		next = max(next, version+1)
	}
	slices.Sort(added)
	var refused []string
	for _, file := range added {
		version, _ := migrationVersion(file)
		if version > highest {
			continue
		}
		_, name, _ := strings.Cut(filepath.Base(file), "_")
		refused = append(refused, fmt.Sprintf("%s: version %05d is not above main's highest %05d; rename to %s%05d_%s", file, version, highest, dir, next, name))
		next++
	}
	if len(refused) != 0 {
		return errors.New("migration numbering:\n" + strings.Join(refused, "\n"))
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
