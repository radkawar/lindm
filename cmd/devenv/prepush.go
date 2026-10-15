// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/worktree"
)

const prePushUsage = `Usage: go run ./cmd/devenv pre-push [-root DIR] [-timeout D] < git pre-push refs

Git pre-push hook body (make pre-push). For each commit being pushed, as read
from git's "<local ref> <local sha> <remote ref> <remote sha>" lines on stdin,
it skips a SHA whose GitHub status already has a green signoff/unit, and
otherwise runs make check in a temporary clean worktree of exactly that SHA,
never the shared dirty tree. Annotated tags are peeled to their commit before
checking status or building. Deletions push nothing and are skipped.
`

func runPrePush(args []string) error {
	flags := flag.NewFlagSet("pre-push", flag.ContinueOnError)
	root := flags.String("root", ".", "checkout being pushed from")
	timeout := flags.Duration("timeout", 90*time.Minute, "overall deadline")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), prePushUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	// Git passes the remote name and URL as positional arguments.
	if flags.NArg() > 2 || *timeout <= 0 {
		return errors.New("pre-push takes at most git's remote name and URL, and a positive timeout")
	}
	// Git exports repository-local variables to hooks. They must not redirect
	// worktree commands or the temporary repositories created by gate tests.
	if err := clearPrePushGitEnvironment(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	shas, err := pushedCommitTips(ctx, *root, os.Stdin)
	if err != nil {
		return err
	}
	repo, err := worktree.Open(ctx, *root)
	if err != nil {
		return err
	}
	for _, sha := range shas {
		if signedOff(ctx, *root, sha, "unit") {
			fmt.Printf("pre-push: %s already has a green signoff/unit; skipping make check\n", sha)
			continue
		}
		if err := inClean(ctx, repo, "prepush", sha, func(clean string) error {
			fmt.Printf("pre-push: make check for %s in clean worktree %s\n", sha, clean)
			return makeCheck(ctx, clean)
		}); err != nil {
			return fmt.Errorf("pre-push gate for %s: %w", sha, err)
		}
	}
	return nil
}

func clearPrePushGitEnvironment() error {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "GIT_") {
			if err := os.Unsetenv(name); err != nil {
				return err
			}
		}
	}
	return nil
}

func pushedCommitTips(ctx context.Context, root string, input io.Reader) ([]string, error) {
	objects, err := pushedCommits(input)
	if err != nil {
		return nil, err
	}
	var commits []string
	seen := make(map[string]bool, len(objects))
	for _, object := range objects {
		commit, err := output(ctx, root, "git", "rev-parse", "--verify", "--end-of-options", object+"^{commit}")
		if err != nil {
			return nil, fmt.Errorf("resolve pushed commit %s: %w", object, err)
		}
		if !seen[commit] {
			seen[commit] = true
			commits = append(commits, commit)
		}
	}
	return commits, nil
}

// pushedCommits returns the distinct local SHAs of git's pre-push lines,
// excluding deletions (an all-zero local SHA).
func pushedCommits(input io.Reader) ([]string, error) {
	var shas []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(io.LimitReader(input, 1<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 4 {
			return nil, fmt.Errorf("malformed pre-push line %q", scanner.Text())
		}
		sha := fields[1]
		if strings.Trim(sha, "0") == "" || seen[sha] {
			continue
		}
		seen[sha] = true
		shas = append(shas, sha)
	}
	return shas, scanner.Err()
}

// signedOff reports whether GitHub's combined status for sha has a successful
// signoff/<name>. Any failure to ask (an unpushed SHA, no network, no gh)
// means not signed off, so the gate runs.
func signedOff(ctx context.Context, dir, sha, name string) bool {
	query, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(query, "gh", "api", "repos/{owner}/{repo}/commits/"+sha+"/status", "--jq", `.statuses[] | select(.context == "signoff/`+name+`") | .state`)
	cmd.Dir = dir
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "success"
}
