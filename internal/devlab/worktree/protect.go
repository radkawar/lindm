package worktree

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The main checkout's tracked files are read-only outside landings, so an edit
// that a relative path aims at the shared tree instead of a private worktree
// fails at once with EACCES rather than dirtying it and blocking every
// landing. Only tracked regular files are protected: directories stay
// writable, so builds write their untracked outputs and git replaces files
// (it unlinks and recreates them, which leaves them writable until the next
// Protect). Symlinks have no permissions of their own and are skipped.

// Protect clears every write bit of the main checkout's tracked regular files
// and returns those it changed; it is idempotent and keeps going past a file
// it cannot change. Call it holding the landing lock, or after TryLock found
// it free: a landing in progress needs its tree writable and re-protects it
// itself.
func (r *Repository) Protect(ctx context.Context) ([]string, error) {
	return r.chmodTracked(ctx, func(mode fs.FileMode) fs.FileMode { return mode &^ 0o222 })
}

// Unprotect gives the main checkout's tracked regular files back their
// owner's write permission (u+w) and returns those it changed.
func (r *Repository) Unprotect(ctx context.Context) ([]string, error) {
	return r.chmodTracked(ctx, func(mode fs.FileMode) fs.FileMode { return mode | 0o200 })
}

// Writable runs fn with the main checkout's tracked files writable and
// protects them again however fn ends (success, failure, rollback,
// interruption or panic), including the files fn added. Call it holding the
// landing lock.
func (r *Repository) Writable(ctx context.Context, fn func() error) (err error) {
	defer func() {
		// Protection outlives an interrupted or expired run.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if _, protectErr := r.Protect(cleanup); protectErr != nil {
			err = errors.Join(err, fmt.Errorf("re-protect %s: %w", r.Main, protectErr))
		}
	}()
	if _, err := r.Unprotect(ctx); err != nil {
		return fmt.Errorf("unprotect %s: %w", r.Main, err)
	}
	return fn()
}

// chmodTracked applies change to the permission bits of each tracked regular
// file in the main checkout and returns the paths whose mode changed.
func (r *Repository) chmodTracked(ctx context.Context, change func(fs.FileMode) fs.FileMode) ([]string, error) {
	listing, err := git(ctx, r.Main, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	var changed []string
	var failures []error
	for name := range strings.SplitSeq(listing, "\x00") {
		if name == "" {
			continue
		}
		path := filepath.Join(r.Main, name)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue // deleted in the working tree
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		mode := info.Mode().Perm()
		if next := change(mode); next != mode {
			if err := os.Chmod(path, next); err != nil {
				failures = append(failures, err)
				continue
			}
			changed = append(changed, name)
		}
	}
	return changed, errors.Join(failures...)
}
