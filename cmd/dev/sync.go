// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lindm/internal/devlab/worktree"
)

const syncUsage = `Usage: go run ./cmd/dev sync [-timeout D]

Fast-forward the shared main checkout to its freshly fetched upstream under
the landing lock, then protect it again. Use it instead of git pull there:
the checkout's tracked files and their directories are read-only outside
landings, so git cannot replace files in it. Refuses a dirty checkout (naming
the stray files) and never merges: local commits not yet on upstream are
pushed by the next dev land.
`

func runSync(args []string) (resultErr error) {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	timeout := flags.Duration("timeout", 30*time.Minute, "overall deadline, including waiting for the lock")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), syncUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("sync takes no positional arguments and a positive timeout")
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
	var before, after string
	if err := repo.Writable(ctx, func() error {
		var err error
		before, after, err = repo.Sync(ctx)
		return err
	}); err != nil {
		return err
	}
	if before == after {
		_, err = fmt.Printf("sync: %s already at its upstream (%.12s)\n", worktree.Trunk, after)
		return err
	}
	_, err = fmt.Printf("sync: %s fast-forwarded %.12s..%.12s and protected\n", worktree.Trunk, before, after)
	return err
}
