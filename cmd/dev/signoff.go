package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/devlab/worktree"
)

const signoffUsage = `Usage: go run ./cmd/dev signoff [-acceptance] [options]

Local CI (gh-signoff) for the pushed HEAD of -root, never the shared dirty
tree: it refuses an unpushed HEAD, qualifies a temporary clean worktree of
that SHA, then posts statuses with gh signoff create --commit SHA from -root.

  default      make check (context unit), then test-integration with the clean
               worktree as code under test and -root's running dev fixture
               (context integration). Run make dev-up first.
  -acceptance  make acceptance in the clean worktree against -root's fixture,
               image and golden caches (context acceptance); evidence goes to
               -root/artifacts/acceptance-<ts>. -acceptance-flags appends
               lab acceptance flags.

Options: -root <checkout> (default .), -timeout <duration> (default 2h; 5h
with -acceptance).
`

func runSignoff(args []string) (resultErr error) {
	flags := flag.NewFlagSet("signoff", flag.ContinueOnError)
	root := flags.String("root", ".", "checkout whose pushed HEAD and dev fixture are used")
	acceptance := flags.Bool("acceptance", false, "run make acceptance instead of check and integration")
	acceptanceFlags := flags.String("acceptance-flags", "", "extra lab acceptance flags")
	timeout := flags.Duration("timeout", 0, "overall deadline (default 2h; 5h with -acceptance)")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), signoffUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if flags.NArg() != 0 {
		return errors.New("signoff takes no positional arguments")
	}
	if *timeout == 0 {
		*timeout = 2 * time.Hour
		if *acceptance {
			*timeout = 5 * time.Hour
		}
	}
	if *timeout < 0 {
		return errors.New("timeout must be positive")
	}
	checkout, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	if checkout, err = filepath.EvalSymlinks(checkout); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	repo, err := worktree.Open(ctx, checkout)
	if err != nil {
		return err
	}
	sha, err := output(ctx, checkout, "git", "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	remotes, err := output(ctx, checkout, "git", "branch", "--remotes", "--contains", sha)
	if err != nil {
		return err
	}
	if remotes == "" {
		return fmt.Errorf("HEAD %s is not pushed (no remote-tracking branch contains it); push, or fetch if it was pushed elsewhere", sha)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	clean, err := repo.Add(ctx, "signoff-"+sha[:12]+"-"+stamp, sha, os.Stderr)
	if clean != "" {
		defer func() {
			// Removal must outlive an interrupted or expired run.
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			resultErr = errors.Join(resultErr, repo.Remove(cleanup, clean))
		}()
	}
	if err != nil {
		return err
	}
	fmt.Printf("Signoff %s in clean worktree %s; fixture %s\n", sha, clean, devlab.FixturePath(checkout))
	contexts := []string{"unit", "integration"}
	if *acceptance {
		contexts = []string{"acceptance"}
		evidence := filepath.Join(checkout, "artifacts", "acceptance-"+stamp)
		labFlags := strings.TrimSpace(fmt.Sprintf("-fixture %s -cache %s -golden-cache %s %s", checkout, filepath.Join(checkout, ".cache/lab/images"), filepath.Join(checkout, ".cache/lab/encrypted"), *acceptanceFlags))
		if err := stream(ctx, clean, "make", "acceptance", "ACCEPTANCE_EVIDENCE="+evidence, "ACCEPTANCE_FLAGS="+labFlags); err != nil {
			return err
		}
	} else {
		if err := stream(ctx, clean, "make", "check"); err != nil {
			return err
		}
		if err := devlab.TestIntegration(ctx, checkout, clean); err != nil {
			return err
		}
	}
	if err := stream(ctx, checkout, "gh", append([]string{"signoff", "create", "--commit", sha}, contexts...)...); err != nil {
		return err
	}
	return stream(ctx, checkout, "gh", "signoff", "status", "--commit", sha)
}

func output(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Stderr = dir, os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// stream runs a gate's output; cancellation kills its whole process group so
// make's test and build children cannot outlive a failed signoff.
func stream(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s in %s: %w", name, strings.Join(args, " "), dir, err)
	}
	return nil
}
