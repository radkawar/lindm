//go:build linux

// Package diskgc reclaims disk space that lindm development and the lab leave
// behind: Go build cache entries nothing has used for hours, the inputs of
// finished lab matrix runs, stale lab run directories and cached lab images
// that no manifest references. Every class removes only what no live process
// uses (cwd, root, executable or open file beneath it, or a path beneath it on
// its command line) and, where a writer could still come back, what has been
// quiet for a while; cache entries are removed under the same per-entry flock
// their users take. Each run is idempotent and safe beside concurrent runs and
// builds. It never touches source trees, evidence records, persistent demos or
// anything outside the directories it is given. Deciding which worktrees are
// disposable belongs to devlab/worktree, and what a lane needs to the lab.
package diskgc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// DefaultQuiet is how long a run directory must go unchanged before it is
	// stale: lanes and matrix runs touch their directories continually.
	DefaultQuiet = time.Hour
	// DefaultBuildCacheAge keeps Go build cache entries any build used within
	// it. Go refreshes an entry's mtime when it uses one older than an hour.
	DefaultBuildCacheAge = 6 * time.Hour
	// maxNotes bounds the kept-item explanations a Result carries.
	maxNotes = 20
	// trashPrefix marks a directory gc has claimed by renaming and is
	// removing; a later run finishes one an interrupted run left.
	trashPrefix = ".gc-"
)

// Result is one class's outcome.
type Result struct {
	Class     string
	Reclaimed int64 // allocated bytes removed (or that a dry run would remove)
	Removed   int
	Kept      int
	Notes     []string // why notable items were kept, bounded
}

func (r Result) String() string {
	line := fmt.Sprintf("%-16s reclaimed %s (%d removed, %d kept)", r.Class, Size(r.Reclaimed), r.Removed, r.Kept)
	for _, note := range r.Notes {
		line += "\n  kept " + note
	}
	return line
}

func (r *Result) keep(note string) {
	r.Kept++
	if note != "" && len(r.Notes) < maxNotes {
		r.Notes = append(r.Notes, note)
	}
}

// Size renders a byte count in binary units.
func Size(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value, suffix := float64(bytes)/unit, 0
	for value >= unit && suffix < 4 {
		value, suffix = value/unit, suffix+1
	}
	return fmt.Sprintf("%.1f%ciB", value, "KMGTP"[suffix])
}

// Free returns the bytes available to unprivileged users on the filesystem
// holding path.
func Free(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return int64(stat.Bavail) * stat.Bsize, nil
}

// Host runs the classes that need no repository on this machine: the Go
// build cache (entries untouched for DefaultBuildCacheAge) and LabRuns over
// workDirs with DefaultQuiet. Each result is also written as a line to log.
// A host without a Go toolchain (a lab host) has no build cache to collect.
func Host(ctx context.Context, workDirs []string, log io.Writer) ([]Result, error) {
	var results []Result
	var failures []error
	for _, run := range []func() (Result, error){
		func() (Result, error) {
			if _, err := exec.LookPath("go"); err != nil {
				return Result{Class: "go-build-cache", Notes: []string{"no go toolchain on this host"}}, nil
			}
			cache, err := GoBuildCache(ctx)
			if err != nil {
				return Result{Class: "go-build-cache"}, err
			}
			return BuildCache(ctx, cache, DefaultBuildCacheAge, false)
		},
		func() (Result, error) { return LabRuns(ctx, workDirs, DefaultQuiet, false) },
	} {
		result, err := run()
		results = append(results, result)
		failures = append(failures, err)
		if _, err := fmt.Fprintln(log, "gc: "+result.String()); err != nil {
			failures = append(failures, err)
		}
	}
	return results, errors.Join(failures...)
}

// allocated returns the bytes allocated to path and everything beneath it,
// without following symlinks; unreadable parts count as nothing.
func allocated(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, err := d.Info(); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				total += stat.Blocks * 512
			}
		}
		return nil
	})
	return total
}

// changedSince reports whether anything at or beneath path changed after
// cutoff: its mtime and, with ctime, its inode change time (a rename or chmod
// is activity too).
func changedSince(path string, cutoff time.Time, ctime bool) (bool, error) {
	recent := false
	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		info, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		changed := info.ModTime()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && ctime {
			if changedAt := time.Unix(stat.Ctim.Unix()); changedAt.After(changed) {
				changed = changedAt
			}
		}
		if changed.After(cutoff) {
			recent = true
			return fs.SkipAll
		}
		return nil
	})
	return recent, err
}

// remove claims path by renaming it beside itself, so no reader ever sees it
// half removed under its own name, then removes it; it returns the bytes it
// held. A dry run only measures.
func remove(path string, dryRun bool) (int64, error) {
	bytes := allocated(path)
	if dryRun {
		return bytes, nil
	}
	trash := filepath.Join(filepath.Dir(path), fmt.Sprintf("%s%s-%d", trashPrefix, filepath.Base(path), os.Getpid()))
	if err := os.Rename(path, trash); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil // a concurrent gc claimed it
		}
		return 0, err
	}
	return bytes, removeTree(trash)
}

// removeTree removes path and everything beneath it, first giving the owner
// write and search permission on every directory in it: lab caches publish
// read-only trees (a-w), whose entries cannot otherwise be unlinked.
func removeTree(path string) error {
	err := filepath.WalkDir(path, func(name string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil // RemoveAll reports what stays unremovable
		}
		info, err := d.Info()
		if err != nil || info.Mode().Perm()&0o700 == 0o700 {
			return nil
		}
		// Before the walk reads the directory, so an unreadable one opens.
		return os.Chmod(name, info.Mode().Perm()|0o700)
	})
	return errors.Join(err, os.RemoveAll(path))
}

// sweepTrash removes what interrupted runs claimed in dir but left behind.
func sweepTrash(dir string, result *Result, dryRun bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), trashPrefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		bytes := allocated(path)
		if !dryRun {
			if err := removeTree(path); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		result.Reclaimed += bytes
		result.Removed++
	}
	return errors.Join(failures...)
}
