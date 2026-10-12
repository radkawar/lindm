package worktree

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The main checkout's tracked files, and every directory that directly holds
// one, are read-only outside landings, so an edit that a relative path aims
// at the shared tree instead of a private worktree fails at once with EACCES
// rather than dirtying it and blocking every landing: writing a file in place
// needs the file writable, and writing a temporary file and renaming it over
// (how editors and agents' tools save) needs its directory writable.
// Directories holding no tracked file (.git, build outputs, caches) stay
// writable. Build outputs that live in a protected directory (artifacts/,
// web/dist/, .cache/ at the root) are created before it is protected, from
// the root .gitignore's plain directory patterns, so builds keep writing into
// them. Symlinks have no permissions of their own and are skipped.

// Protect clears every write bit of the main checkout's tracked regular files
// and of the directories holding them, and returns the paths it changed
// (directories with a trailing slash); it is idempotent and keeps going past
// a path it cannot change. Call it holding the landing lock, or after TryLock
// found it free: a landing in progress needs its tree writable and
// re-protects it itself.
func (r *Repository) Protect(ctx context.Context) ([]string, error) {
	if err := r.createOutputDirectories(); err != nil {
		return nil, err
	}
	return r.chmodTracked(ctx, func(mode fs.FileMode) fs.FileMode { return mode &^ 0o222 })
}

// Unprotect gives the main checkout's tracked regular files and the
// directories holding them back their owner's write permission (u+w) and
// returns the paths it changed.
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
// file in the main checkout and of each directory holding one (the checkout
// root included), and returns the paths whose mode changed.
func (r *Repository) chmodTracked(ctx context.Context, change func(fs.FileMode) fs.FileMode) ([]string, error) {
	listing, err := git(ctx, r.Main, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	var changed []string
	var failures []error
	apply := func(name string, directory bool) {
		info, err := os.Lstat(filepath.Join(r.Main, name))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return // deleted in the working tree
		}
		if err != nil {
			failures = append(failures, err)
			return
		}
		if directory != info.IsDir() || (!directory && !info.Mode().IsRegular()) {
			return
		}
		mode := info.Mode().Perm()
		if next := change(mode); next != mode {
			if err := os.Chmod(filepath.Join(r.Main, name), next); err != nil {
				failures = append(failures, err)
				return
			}
			if directory {
				name += "/"
			}
			changed = append(changed, name)
		}
	}
	directories := map[string]bool{}
	for name := range strings.SplitSeq(listing, "\x00") {
		if name == "" {
			continue
		}
		apply(name, false)
		directories[path.Dir(name)] = true
	}
	for _, directory := range slices.Sorted(maps.Keys(directories)) {
		apply(directory, true)
	}
	return changed, errors.Join(failures...)
}

// createOutputDirectories creates the build output directories the root
// .gitignore names as plain directory paths (artifacts/, web/dist/, ...) that
// are missing, so builds can still write into them once their parent
// directory is protected.
func (r *Repository) createOutputDirectories() error {
	ignore, err := os.ReadFile(filepath.Join(r.Main, ".gitignore"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var failures []error
	for line := range strings.Lines(string(ignore)) {
		pattern := strings.TrimSpace(line)
		directory, ok := strings.CutSuffix(strings.TrimPrefix(pattern, "/"), "/")
		if !ok || directory == "" || strings.HasPrefix(pattern, "#") || strings.HasPrefix(pattern, "!") || strings.ContainsAny(directory, "*?[\\") || path.Clean(directory) != directory || strings.HasPrefix(directory, "..") {
			continue
		}
		target := filepath.Join(r.Main, filepath.FromSlash(directory))
		if _, err := os.Lstat(target); err == nil {
			continue
		}
		// The parent may already be protected (a directory added since).
		parent := filepath.Dir(target)
		if info, err := os.Stat(parent); err == nil && info.IsDir() && info.Mode().Perm()&0o200 == 0 {
			if err := os.Chmod(parent, info.Mode().Perm()|0o200); err != nil {
				failures = append(failures, err)
				continue
			}
			defer func() { _ = os.Chmod(parent, info.Mode().Perm()) }()
		}
		failures = append(failures, os.MkdirAll(target, 0o755))
	}
	return errors.Join(failures...)
}
