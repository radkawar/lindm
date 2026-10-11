package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"lindm/internal/devlab/worktree"
)

const worktreeUsage = `Usage: go run ./cmd/dev worktree <add|list|audit|prune> [options]

  add NAME [-base REV]  Create <main>.worktrees/NAME detached at REV (default
        HEAD), link the main checkout's node_modules when package.json and
        package-lock.json match (otherwise npm ci there), print the path.
  list  Registered worktrees: path, HEAD, ahead/behind main, dirty, last
        modified (newest file outside node_modules), allocated size.
  audit [-all] [PATH...]  Classify every registered worktree (and extra PATHs)
        by whether main already holds its work, by content rather than commits:
        its change set (base..HEAD, staged, unstaged, untracked) per file is
        LANDED when main has that content or the change reverse-applies to
        main; trees are LANDED, PARTIAL (unlanded files listed), UNLANDED,
        SNAPSHOT (no change), MISSING or UNREGISTERED, with an owner inferred
        from the name. PARTIAL/UNLANDED trees a live owner is working in (a
        process uses the tree, or a file changed within 2h) are work in
        progress and hidden from the table unless -all. Writes every tree to
        ~/.cache/lindm-worktree-audit/<ts>.json.
  prune [-older-than D] [-dry-run] [-archive-dirty] [PATH...]
        Remove worktrees (default: every one under <main>.worktrees) that are
        clean and whose HEAD is an ancestor of main, or dirty/diverged but
        audited LANDED or SNAPSHOT. Other dirty or diverged trees
        are kept unless -archive-dirty. Every dirty/diverged removal first saves git diff --binary
        HEAD, the untracked files (tar), the HEAD SHA and a bundle of commits
        main lacks to ~/.cache/lindm-worktree-archive/<name>-<ts>/. A tree that
        any process uses (cwd, root, executable or open file beneath it) or
        whose dev fixture is running is never touched. Ends with git worktree
        prune.

Options: -root <checkout> (default .), -timeout <duration> (default 30m).
`

func runWorktree(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, worktreeUsage)
		return errors.New("a worktree command is required")
	}
	verb := args[0]
	if verb != "add" && verb != "list" && verb != "audit" && verb != "prune" {
		return fmt.Errorf("unknown worktree command %q; use worktree add|list|audit|prune", verb)
	}
	flags := flag.NewFlagSet("worktree "+verb, flag.ContinueOnError)
	root := flags.String("root", ".", "any checkout of the repository")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall command deadline")
	base := flags.String("base", "HEAD", "revision for add")
	olderThan := flags.Duration("older-than", 0, "prune only trees unmodified for this long")
	dryRun := flags.Bool("dry-run", false, "prune: report decisions without archiving or removing")
	archiveDirty := flags.Bool("archive-dirty", false, "prune: archive, then remove, dirty or diverged trees")
	all := flags.Bool("all", false, "audit: also list PARTIAL/UNLANDED trees that are in progress")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), worktreeUsage) }
	positional, err := parseInterspersed(flags, args[1:])
	if err != nil {
		return errors.Join(err, usageErr)
	}
	if *timeout <= 0 || *olderThan < 0 {
		return errors.New("timeout must be positive and older-than non-negative")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	repo, err := worktree.Open(ctx, *root)
	if err != nil {
		return err
	}
	switch verb {
	case "add":
		if len(positional) != 1 {
			return errors.New("worktree add requires exactly one NAME")
		}
		path, err := repo.Add(ctx, positional[0], *base, os.Stderr)
		if err != nil {
			return err
		}
		_, err = fmt.Println(path)
		return err
	case "list":
		if len(positional) != 0 {
			return errors.New("worktree list takes no arguments")
		}
		return listWorktrees(ctx, repo)
	case "audit":
		return auditWorktrees(ctx, repo, positional, *all)
	}
	return pruneWorktrees(ctx, repo, positional, worktree.PruneOptions{OlderThan: *olderThan, DryRun: *dryRun, ArchiveDirty: *archiveDirty, Now: time.Now()})
}

func listWorktrees(ctx context.Context, repo *worktree.Repository) error {
	entries, err := repo.List(ctx)
	if err != nil {
		return err
	}
	table := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "PATH\tHEAD\tAHEAD\tBEHIND\tDIRTY\tMODIFIED\tSIZE"); err != nil {
		return err
	}
	for _, entry := range entries {
		row := fmt.Sprintf("%s\t%.12s\t-\t-\tmissing\t-\t-", entry.Path, entry.Head)
		if !entry.Missing {
			status, err := repo.Inspect(ctx, entry)
			if err != nil {
				row = fmt.Sprintf("%s\t%.12s\t-\t-\terror: %v\t-\t-", entry.Path, entry.Head, err)
			} else {
				row = fmt.Sprintf("%s\t%.12s\t%d\t%d\t%t\t%s\t%s", entry.Path, entry.Head, status.Ahead, status.Behind, status.Dirty, status.Modified.Format(time.DateTime), size(status.Bytes))
			}
		}
		if _, err := fmt.Fprintln(table, row); err != nil {
			return err
		}
	}
	return table.Flush()
}

func pruneWorktrees(ctx context.Context, repo *worktree.Repository, targets []string, options worktree.PruneOptions) error {
	removed := "removed"
	if options.DryRun {
		removed = "would remove"
	}
	var count, kept int
	var reclaimed int64
	table := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "ACTION\tPATH\tSIZE\tREASON"); err != nil {
		return err
	}
	err := repo.Prune(ctx, targets, options, func(decision worktree.Decision) error {
		action, bytes := "kept", "-"
		if decision.Status != nil {
			bytes = size(decision.Status.Bytes)
		}
		if decision.Removed {
			action, count, reclaimed = removed, count+1, reclaimed+decision.Status.Bytes
		} else {
			kept++
		}
		reason := decision.Reason
		if decision.Archive != "" {
			reason += " to " + decision.Archive
		}
		_, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", action, decision.Path, bytes, reason)
		return err
	})
	if err := errors.Join(err, table.Flush()); err != nil {
		return err
	}
	_, err = fmt.Printf("%s %d, kept %d, reclaimed %s (archives: %s)\n", removed, count, kept, size(reclaimed), filepath.Clean(repo.Archive))
	return err
}

// parseInterspersed parses flags that may follow positional arguments.
func parseInterspersed(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		if flags.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, flags.Arg(0))
		args = flags.Args()[1:]
	}
}

func size(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value, suffix := float64(bytes)/unit, 0
	for value >= unit && suffix < 3 {
		value, suffix = value/unit, suffix+1
	}
	return fmt.Sprintf("%.1f%ciB", value, "KMGT"[suffix])
}

func auditWorktrees(ctx context.Context, repo *worktree.Repository, extra []string, all bool) error {
	// A landing in progress explains files that look stray in the shared checkout.
	if err := printLanding(repo); err != nil {
		return err
	}
	var audits []worktree.Audit
	table := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "VERDICT\tOWNER\tPATH\tCHANGED\tUNLANDED"); err != nil {
		return err
	}
	counts := map[worktree.Verdict]int{}
	err := repo.AuditAll(ctx, extra, func(audit worktree.Audit) error {
		audits = append(audits, audit)
		inProgress := audit.Active != "" && (audit.Verdict == worktree.Partial || audit.Verdict == worktree.Unlanded)
		if inProgress {
			counts["IN PROGRESS"]++
			if !all {
				return nil
			}
		}
		counts[audit.Verdict]++
		detail := strings.Join(audit.Unlanded, " ")
		if audit.Note != "" {
			detail = strings.TrimSpace(detail + " (" + audit.Note + ")")
		}
		if inProgress {
			detail = strings.TrimSpace(detail + " [in progress: " + audit.Active + "]")
		}
		_, err := fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\n", audit.Verdict, audit.Owner, audit.Path, audit.Changed, detail)
		return err
	})
	if err := errors.Join(err, table.Flush()); err != nil {
		return err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(cache, "lindm-worktree-audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	head, err := output(ctx, repo.Main, "git", "rev-parse", worktree.Trunk)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		AuditedAt time.Time        `json:"audited_at"`
		Main      string           `json:"main"`
		Trunk     string           `json:"trunk_sha"`
		Worktrees []worktree.Audit `json:"worktrees"`
	}{time.Now().UTC(), repo.Main, head, audits}, "", "  ")
	if err != nil {
		return err
	}
	record := filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+".json")
	if err := os.WriteFile(record, append(data, '\n'), 0o600); err != nil {
		return err
	}
	var summary []string
	for _, verdict := range []worktree.Verdict{worktree.Landed, worktree.Snapshot, worktree.Partial, worktree.Unlanded, worktree.Missing, worktree.Unregistered} {
		summary = append(summary, fmt.Sprintf("%s %d", verdict, counts[verdict]))
	}
	hidden := ""
	if !all {
		hidden = fmt.Sprintf(" (%d in-progress PARTIAL/UNLANDED trees not listed; -all shows them)", counts["IN PROGRESS"])
	}
	_, err = fmt.Printf("%s%s against %s %.12s; record %s\n", strings.Join(summary, ", "), hidden, worktree.Trunk, head, record)
	return err
}
