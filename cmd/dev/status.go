// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/worktree"
)

// runStatus prints the shared checkout's landing state: HEAD against its
// upstream, the landing in progress (whose applied files explain a dirty tree),
// the landing and integration lock holders, and uncommitted files. Tracked
// files it finds writable outside a landing it protects again and names.
func runStatus(args []string) error {
	if len(args) != 0 {
		return errors.New("status takes no arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	repo, err := worktree.Open(ctx, ".")
	if err != nil {
		return err
	}
	head, err := output(ctx, repo.Main, "git", "log", "--oneline", "-1", "HEAD")
	if err != nil {
		return err
	}
	counts, err := output(ctx, repo.Main, "git", "rev-list", "--left-right", "--count", worktree.Trunk+"@{upstream}...HEAD")
	if err != nil {
		return err
	}
	behind, ahead, _ := strings.Cut(counts, "\t")
	fmt.Printf("shared checkout %s\nHEAD %s (%s ahead, %s behind %s@{upstream}, as last fetched)\n", repo.Main, head, ahead, behind, worktree.Trunk)
	if err := printLanding(repo); err != nil {
		return err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	for _, lock := range []string{repo.LockPath(), filepath.Join(cache, "lindm-integration.lock")} {
		holders, err := worktree.LockHolders(lock)
		if err != nil {
			return err
		}
		state := "free"
		var waiting int
		for _, h := range holders {
			if h.Waiting {
				waiting++
				continue
			}
			state = fmt.Sprintf("held by pid %d (%s)", h.PID, h.Command)
		}
		fmt.Printf("lock %s %s; %d blocked waiters\n", lock, state, waiting)
		for _, h := range holders {
			if h.Waiting {
				fmt.Printf("  waiting: pid %d (%s)\n", h.PID, h.Command)
			}
		}
	}
	protection, err := protectShared(ctx, repo)
	if err != nil {
		return err
	}
	fmt.Printf("protection: %s\n", protection)
	dirty, err := output(ctx, repo.Main, "git", "status", "--porcelain")
	if err != nil {
		return err
	}
	if dirty == "" {
		fmt.Println("uncommitted: none")
		return nil
	}
	_, err = fmt.Printf("uncommitted (a landing's applied files, or stray edits that block dev land):\n%s\n", dirty)
	return err
}

// printLanding prints the landing in progress, if any.
func printLanding(repo *worktree.Repository) error {
	landing, err := repo.CurrentLanding()
	if err != nil {
		return err
	}
	if landing == nil {
		_, err = fmt.Println("landing: none in progress")
		return err
	}
	_, err = fmt.Println(landing)
	return err
}
