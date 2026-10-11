package worktree

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// LockPath is the shared-tree landing lock; landings and gated commits of the
// main checkout serialize on it.
func (r *Repository) LockPath() string {
	return filepath.Join(r.Main, ".git", "lindm-landing.lock")
}

// Lock takes the exclusive landing lock; see LockFile.
func (r *Repository) Lock(ctx context.Context, waiting func(holder string)) (unlock func() error, err error) {
	return LockFile(ctx, r.LockPath(), waiting)
}

// LockFile takes an exclusive flock on path, waiting until ctx ends. waiting
// is called once with the recorded holder when the lock is busy. The flock is
// the authority; the holder record is diagnostic. The returned unlock
// releases it; a crashed holder releases it implicitly.
func LockFile(ctx context.Context, path string, waiting func(holder string)) (unlock func() error, err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(file.Fd())
	for notified := false; ; {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(fmt.Errorf("lock %s: %w", path, err), file.Close())
		}
		if !notified && waiting != nil {
			holder, _ := os.ReadFile(path)
			waiting(strings.TrimSpace(string(holder)))
			notified = true
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-time.After(200 * time.Millisecond):
		}
	}
	holder := "pid " + strconv.Itoa(os.Getpid()) + " " + strings.Join(os.Args, " ") + "\n"
	if err := file.Truncate(0); err == nil {
		_, _ = file.WriteAt([]byte(holder), 0)
	}
	return func() error {
		return errors.Join(file.Truncate(0), syscall.Flock(fd, syscall.LOCK_UN), file.Close())
	}, nil
}

// Change is a worktree's complete change against Trunk: commits since its
// merge base plus staged, unstaged and untracked non-ignored files.
type Change struct {
	Base  string   // merge base with Trunk
	Patch []byte   // binary patch with rename detection
	Files []string // every path the patch creates, modifies or deletes
}

// Change computes the change of the worktree at path, limited to paths when
// any are given. The worktree's own index is never modified.
func (r *Repository) Change(ctx context.Context, path string, paths []string) (Change, error) {
	var change Change
	if _, ok, err := r.registered(ctx, path); err != nil || !ok {
		return change, errors.Join(err, fmt.Errorf("%s is not a registered worktree of %s", path, r.Main))
	}
	err := r.snapshot(ctx, path, paths, func(base string, git gitFunc, scope []string) error {
		change.Base = base
		patch, err := git(append([]string{"diff", "--cached", "--binary", "--find-renames", base}, scope...)...)
		if err != nil {
			return err
		}
		names, err := git(append([]string{"diff", "--cached", "--name-only", "--no-renames", "-z", base}, scope...)...)
		if err != nil {
			return err
		}
		change.Patch = []byte(patch)
		for name := range strings.SplitSeq(names, "\x00") {
			if name != "" {
				change.Files = append(change.Files, name)
			}
		}
		return nil
	})
	return change, err
}

// gitFunc runs git in a worktree against its scratch snapshot index.
type gitFunc func(args ...string) (string, error)

// snapshot stages the worktree's complete state (HEAD plus every staged,
// unstaged and untracked non-ignored file in scope) into a scratch index and
// calls use with the merge base against Trunk, a git runner bound to that
// index, and the pathspec scope. The worktree's own index is never modified.
func (r *Repository) snapshot(ctx context.Context, path string, paths []string, use func(base string, git gitFunc, scope []string) error) error {
	head, err := git(ctx, path, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	base, err := git(ctx, r.Main, "merge-base", Trunk, strings.TrimSpace(head))
	if err != nil {
		return err
	}
	scratch, err := os.MkdirTemp("", "lindm-snapshot-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(scratch, "index")}
	run := func(args ...string) (string, error) { return gitWith(ctx, path, env, nil, args...) }
	scope := append([]string{"--"}, paths...)
	if len(paths) == 0 {
		scope = []string{"--", "."}
	}
	if _, err := run("read-tree", "HEAD"); err != nil {
		return err
	}
	if _, err := run(append([]string{"add", "--all"}, scope...)...); err != nil {
		return err
	}
	return use(strings.TrimSpace(base), run, scope)
}

// Apply applies patch to the main checkout's working tree, or reverses it.
// git apply is atomic: on any conflict nothing is written.
func (r *Repository) Apply(ctx context.Context, patch []byte, reverse bool) error {
	args := []string{"apply", "--whitespace=nowarn"}
	if reverse {
		args = append(args, "--reverse")
	}
	if _, err := gitWith(ctx, r.Main, nil, patch, append(args, "--check", "-")...); err != nil {
		return err
	}
	_, err := gitWith(ctx, r.Main, nil, patch, append(args, "-")...)
	return err
}

func (r *Repository) registered(ctx context.Context, path string) (Entry, bool, error) {
	entries, err := r.List(ctx)
	if err != nil {
		return Entry{}, false, err
	}
	for _, entry := range entries {
		if canonical(entry.Path) == canonical(path) {
			return entry, true, nil
		}
	}
	return Entry{}, false, nil
}
