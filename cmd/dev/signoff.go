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
	"lindm/internal/labexec"
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

Options: -root <checkout> (default .), -timeout <duration> (default 5h: make
check, up to 3h queued for the integration lock and its 45m run; 5h with
-acceptance).
`

func runSignoff(args []string) (resultErr error) {
	flags := flag.NewFlagSet("signoff", flag.ContinueOnError)
	root := flags.String("root", ".", "checkout whose pushed HEAD and dev fixture are used")
	acceptance := flags.Bool("acceptance", false, "run make acceptance instead of check and integration")
	acceptanceFlags := flags.String("acceptance-flags", "", "extra lab acceptance flags")
	timeout := flags.Duration("timeout", 0, "overall deadline (default 5h, covering the bounded integration queue)")
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), signoffUsage) }
	if err := flags.Parse(args); err != nil {
		return errors.Join(err, usageErr)
	}
	if flags.NArg() != 0 {
		return errors.New("signoff takes no positional arguments")
	}
	// The integration queue (integrationQueueLimit) and run (integrationLockCap)
	// are bounded on their own; the overall default must not cut them short.
	if *timeout == 0 {
		*timeout = 5 * time.Hour
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
	contexts := []string{"unit", "integration"}
	if *acceptance {
		contexts = []string{"acceptance"}
	}
	if err := inClean(ctx, repo, "signoff", sha, func(clean string) error {
		fmt.Printf("Signoff %s in clean worktree %s; fixture %s\n", sha, clean, devlab.FixturePath(checkout))
		if *acceptance {
			evidence := filepath.Join(checkout, "artifacts", "acceptance-"+stamp)
			labFlags := strings.TrimSpace(fmt.Sprintf("-fixture %s -cache %s -golden-cache %s %s", checkout, filepath.Join(checkout, ".cache/lab/images"), filepath.Join(checkout, ".cache/lab/encrypted"), *acceptanceFlags))
			return stream(ctx, clean, nil, "make", "acceptance", "ACCEPTANCE_EVIDENCE="+evidence, "ACCEPTANCE_FLAGS="+labFlags)
		}
		if err := makeCheck(ctx, clean); err != nil {
			return err
		}
		return testIntegration(ctx, checkout, clean, integrationLockCap)
	}); err != nil {
		return err
	}
	if err := stream(ctx, checkout, nil, "gh", append([]string{"signoff", "create", "--commit", sha}, contexts...)...); err != nil {
		return err
	}
	return stream(ctx, checkout, nil, "gh", "signoff", "status", "--commit", sha)
}

// inClean runs gates in a temporary clean worktree of sha, removing it
// afterwards even when the gates fail or the run is interrupted.
func inClean(ctx context.Context, repo *worktree.Repository, purpose, sha string, gates func(clean string) error) (resultErr error) {
	name := purpose + "-" + sha[:12] + "-" + time.Now().UTC().Format("20060102T150405Z")
	clean, err := repo.Add(ctx, name, sha, os.Stderr)
	if clean != "" {
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			resultErr = errors.Join(resultErr, repo.Remove(cleanup, clean))
		}()
	}
	if err != nil {
		return err
	}
	return gates(clean)
}

// makeCheck runs make check in a clean worktree after heavy-job admission
// (local memory guard, nice 10), without golangci-lint's
// machine-wide runner lock, using a cache reserved for clean-worktree gates, so
// agents linting concurrently neither block nor fail the gate. golangci-lint's
// cache, like Go's build cache, tolerates concurrent writers.
func makeCheck(ctx context.Context, clean string) error {
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	if err := admitHeavyJob(ctx, "make check", os.Stderr); err != nil {
		return err
	}
	env := append(os.Environ(), "GOLANGCI_LINT_CACHE="+filepath.Join(cache, "lindm-clean-golangci"))
	return stream(ctx, clean, env, "make", "check", "GOLANGCI_RUN_FLAGS=--allow-parallel-runners")
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

// stream runs a gate with its output streamed (env nil inherits ours); cancellation kills its whole process group so
// make's test and build children cannot outlive a failed signoff.
func stream(ctx context.Context, dir string, env []string, name string, args ...string) error {
	if err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Env: env, Dir: dir, Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		return fmt.Errorf("%s %s in %s: %w", name, strings.Join(args, " "), dir, err)
	}
	return nil
}

// integrationLockCap bounds how long one run may hold the integration lock.
const integrationLockCap = 45 * time.Minute

// integrationQueueLimit bounds how long a run waits for the integration lock;
// it is separate from the run's own deadline.
const integrationQueueLimit = 3 * time.Hour

// testIntegration runs the integration suite exclusively among integration
// runs on this host, which share the one fixed-port dev PostgreSQL. Heavy-job
// admission (local memory guard, nice 10) comes first, so a run never holds
// the lock while waiting on the host; the run under the lock is bounded by
// limit (at most integrationLockCap), and its per-package progress replaces
// the lock's holder record so waiters and dev status see how far it is.
func testIntegration(ctx context.Context, fixtureRoot, codeRoot string, limit time.Duration) (resultErr error) {
	if err := admitHeavyJob(ctx, "test-integration", os.Stderr); err != nil {
		return err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	lock := filepath.Join(cache, "lindm-integration.lock")
	queued := time.Now()
	queue, stopQueue := context.WithTimeout(ctx, integrationQueueLimit)
	defer stopQueue()
	var lastHolder string
	unlock, err := worktree.LockFile(queue, lock, func(holder string) {
		lastHolder = holder
		fmt.Fprintf(os.Stderr, "test-integration: queued %s for %s; the dev PostgreSQL is held by %s\n", time.Since(queued).Round(time.Second), lock, holder)
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return fmt.Errorf("gave up after queueing %s for %s (held by %s)", integrationQueueLimit, lock, lastHolder)
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	if err := devlab.AwaitIntegrationCapacity(queue, fixtureRoot, os.Stderr); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, min(limit, integrationLockCap))
	defer cancel()
	started := time.Now()
	holder := fmt.Sprintf("pid %d test-integration of %s since %s", os.Getpid(), codeRoot, started.UTC().Format(time.RFC3339))
	return devlab.TestIntegration(ctx, fixtureRoot, codeRoot, func(line string) {
		// Diagnostic only: the flock, not this record, is the lock.
		_ = os.WriteFile(lock, []byte(holder+": "+line+"\n"), 0o600)
	})
}
