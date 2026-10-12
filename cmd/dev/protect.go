package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/worktree"
)

const protectUsage = `Usage: go run ./cmd/dev protect

Make the shared main checkout's tracked files and the directories holding
them read-only (a-w), so a tool that writes into it (in place, or a temporary
file renamed over the target) instead of a private worktree fails at once with EACCES rather
than dirtying it and blocking every landing. Idempotent. While a landing or
gate-commit holds the landing lock it does nothing and succeeds: that run
re-protects when it ends. dev status runs it when it finds writable tracked
files. After git rewrites the main checkout's files, the post-merge and
post-checkout hooks run the equivalent .githooks/protect, which builds
nothing.
`

func runProtect(args []string) error {
	flags := flag.NewFlagSet("protect", flag.ContinueOnError)
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), protectUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if flags.NArg() != 0 {
		return errors.New("protect takes no arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	repo, err := worktree.Open(ctx, ".")
	if err != nil {
		return err
	}
	report, err := protectShared(ctx, repo)
	if err != nil {
		return err
	}
	_, err = fmt.Printf("protect %s: %s\n", repo.Main, report)
	return err
}

// maxReportedFiles bounds the paths a protection report names.
const maxReportedFiles = 20

// protectShared protects the shared checkout's tracked files unless a landing
// or gated commit holds the landing lock (that run needs them writable and
// re-protects them itself), and describes the outcome.
func protectShared(ctx context.Context, repo *worktree.Repository) (string, error) {
	unlock, ok, err := repo.TryLock()
	if err != nil {
		return "", err
	}
	if !ok {
		holder, held, err := worktree.LockHolder(repo.LockPath())
		if err != nil {
			return "", err
		}
		if !held {
			holder = "a landing"
		}
		return fmt.Sprintf("skipped while %s holds the landing lock; it re-protects when it ends", holder), nil
	}
	changed, err := repo.Protect(ctx)
	if err := errors.Join(err, unlock()); err != nil {
		return "", fmt.Errorf("protect %s: %w", repo.Main, err)
	}
	if len(changed) == 0 {
		return "all tracked files and their directories read-only", nil
	}
	named := changed[:min(len(changed), maxReportedFiles)]
	report := fmt.Sprintf("%d tracked files or directories (trailing /) were writable, now read-only: %s", len(changed), strings.Join(named, " "))
	if extra := len(changed) - len(named); extra > 0 {
		report += fmt.Sprintf(" … and %d more", extra)
	}
	return report, nil
}
