//go:build linux

package diskgc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GoBuildCache returns this user's Go build cache directory (go env GOCACHE).
func GoBuildCache(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOCACHE").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOCACHE: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" || dir == "off" || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("go build cache %q is not an absolute directory", dir)
	}
	return dir, nil
}

var (
	cacheShard = regexp.MustCompile(`^[0-9a-f]{2}$`)
	cacheEntry = regexp.MustCompile(`^[0-9a-f]{64}-[ad]$`)
)

// BuildCache removes Go build cache entries (<cache>/xx/<hash>-a|-d) whose
// mtime is older than age. The go command refreshes the mtime of an entry it
// uses once it is an hour old and treats a missing entry as a cache miss, so a
// concurrent build at worst recomputes an entry; this is the go command's own
// trim with a shorter horizon.
func BuildCache(ctx context.Context, dir string, age time.Duration, dryRun bool) (Result, error) {
	result := Result{Class: "go-build-cache"}
	if age < time.Hour {
		return result, fmt.Errorf("build cache age %s is below the hour the go command takes to refresh a used entry", age)
	}
	shards, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	cutoff := time.Now().Add(-age)
	var failures []error
	for _, shard := range shards {
		if !shard.IsDir() || !cacheShard.MatchString(shard.Name()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		entries, err := os.ReadDir(filepath.Join(dir, shard.Name()))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, entry := range entries {
			if !cacheEntry.MatchString(entry.Name()) {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue // removed concurrently
			}
			if info.ModTime().After(cutoff) {
				result.Kept++
				continue
			}
			bytes := allocated(filepath.Join(dir, shard.Name(), entry.Name()))
			if !dryRun {
				if err := os.Remove(filepath.Join(dir, shard.Name(), entry.Name())); err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						failures = append(failures, err)
					}
					continue
				}
			}
			result.Reclaimed += bytes
			result.Removed++
		}
	}
	return result, errors.Join(failures...)
}

// MatrixInputs removes the inputs/ directory (staged packages, repositories,
// signing keys) of each finished lab matrix run directly under root, keeping
// every record, log and evidence directory. A run is finished when no live
// process uses or names its directory and nothing in it changed within quiet.
func MatrixInputs(ctx context.Context, root string, quiet time.Duration, dryRun bool) (Result, error) {
	result := Result{Class: "matrix-inputs"}
	runs, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	procs, err := scanProcesses()
	if err != nil {
		return result, err
	}
	cutoff := time.Now().Add(-quiet)
	var failures []error
	for _, run := range runs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		dir := filepath.Join(root, run.Name())
		if !run.IsDir() {
			continue
		}
		failures = append(failures, sweepTrash(dir, &result, dryRun))
		inputs := filepath.Join(dir, "inputs")
		if info, err := os.Lstat(inputs); err != nil || !info.IsDir() {
			continue
		}
		if note := idle(procs, dir, cutoff); note != "" {
			result.keep(run.Name() + ": " + note)
			continue
		}
		bytes, err := remove(inputs, dryRun)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		result.Reclaimed += bytes
		result.Removed++
	}
	return result, errors.Join(failures...)
}

// LabRuns removes stale lab run directories in each work directory: the lane
// scratch directories lindm-* directly in it and remote run directories
// runs/run-*. Persistent state beside them (demos, images, encrypted,
// .leases, advisory-cache) is never touched. A directory is stale when no
// live process uses or names it and nothing in it changed within quiet.
func LabRuns(ctx context.Context, workDirs []string, quiet time.Duration, dryRun bool) (Result, error) {
	result := Result{Class: "lab-runs"}
	procs, err := scanProcesses()
	if err != nil {
		return result, err
	}
	cutoff := time.Now().Add(-quiet)
	var failures []error
	for _, work := range workDirs {
		for _, parent := range []struct{ dir, prefix string }{{work, "lindm-"}, {filepath.Join(work, "runs"), "run-"}} {
			entries, err := os.ReadDir(parent.dir)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				failures = append(failures, err)
				continue
			}
			failures = append(failures, sweepTrash(parent.dir, &result, dryRun))
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return result, err
				}
				if !entry.IsDir() || !strings.HasPrefix(entry.Name(), parent.prefix) {
					continue
				}
				dir := filepath.Join(parent.dir, entry.Name())
				if note := idle(procs, dir, cutoff); note != "" {
					result.keep(dir + ": " + note)
					continue
				}
				bytes, err := remove(dir, dryRun)
				if err != nil {
					failures = append(failures, err)
					continue
				}
				result.Reclaimed += bytes
				result.Removed++
			}
		}
	}
	return result, errors.Join(failures...)
}

// idle explains why dir is still active, or returns "" when it is not.
func idle(procs *uses, dir string, cutoff time.Time) string {
	if user := procs.user(dir); user != "" {
		return user
	}
	recent, err := changedSince(dir, cutoff)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	if recent {
		return "changed within the quiet period"
	}
	return ""
}
