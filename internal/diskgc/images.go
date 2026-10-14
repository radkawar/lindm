// SPDX-License-Identifier: Apache-2.0

//go:build linux

package diskgc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// imageCacheMarker identifies a directory the lab owns as an image or golden
// cache (internal/vmlab); anything else is never touched.
const imageCacheMarker = ".lindm-images"

var (
	digestEntry  = regexp.MustCompile(`^sha256-([0-9a-f]{64})$`)
	goldenEntry  = regexp.MustCompile(`^golden-([0-9a-f]{64})$`)
	hexDigest    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	installedDir = regexp.MustCompile(`^[a-z0-9]+-installed$`)
)

// SourceFile, inside a derived entry (a golden or an installed image), holds
// the sha256 of the image manifest it was built from.
const SourceFile = "source-sha256"

// Images removes cached lab images that nothing references. referenced holds
// the sha256 digests the repository still names: image manifests on main and
// every live worktree, their repository closures and the registry's rolling
// targets. In each cache directory (one carrying the lab's marker) it
// considers verified images sha256-<digest>, repository closures
// repository-snapshots/sha256/<digest>, installed images
// <kind>-installed/sha256-<id> and encrypted goldens golden-<id>. A derived
// entry (installed image, golden) is unreferenced only by its recorded source
// digest and is kept when it records none. An entry is removed only while no
// process uses it, gc holds its per-entry flock (the one every lab reader and
// writer takes; closures have none), and, for goldens, no persistent VM pins
// it.
func Images(ctx context.Context, caches []string, referenced map[string]bool, dryRun bool) (Result, error) {
	result := Result{Class: "lab-images"}
	if len(referenced) == 0 {
		return result, errors.New("no referenced image digests: refusing to treat every cached image as unreferenced")
	}
	procs, err := scanProcesses()
	if err != nil {
		return result, err
	}
	var failures []error
	// collect removes dir/name when source() names an unreferenced digest;
	// lockID names the entry's flock .<lockID>.lock in dir ("" for none).
	collect := func(dir, name, lockID string, source func() (string, error)) {
		path := filepath.Join(dir, name)
		digest, err := source()
		if err != nil {
			result.keep(path + ": " + err.Error())
			return
		}
		if referenced[digest] {
			result.Kept++
			return
		}
		if user := procs.user(path); user != "" {
			result.keep(path + ": " + user)
			return
		}
		if lockID != "" {
			unlock, ok, err := tryLock(filepath.Join(dir, "."+lockID+".lock"))
			if err != nil {
				failures = append(failures, err)
				return
			}
			if !ok {
				result.keep(path + ": locked by a lab process")
				return
			}
			defer unlock()
		}
		bytes, err := remove(path, dryRun)
		if err != nil {
			failures = append(failures, err)
			return
		}
		result.Reclaimed += bytes
		result.Removed++
	}
	fixed := func(digest string) func() (string, error) {
		return func() (string, error) { return digest, nil }
	}
	recorded := func(entry string) func() (string, error) {
		return func() (string, error) { return recordedSource(entry) }
	}
	for _, cache := range caches {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if _, err := os.Lstat(filepath.Join(cache, imageCacheMarker)); err != nil {
			continue // not (yet) a lab cache
		}
		entries, err := os.ReadDir(cache)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		failures = append(failures, sweepTrash(cache, &result, dryRun))
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() {
				continue
			}
			switch {
			case digestEntry.MatchString(name):
				digest := digestEntry.FindStringSubmatch(name)[1]
				collect(cache, name, digest, fixed(digest))
			case goldenEntry.MatchString(name):
				if pins, err := os.ReadDir(filepath.Join(cache, ".references", name)); err == nil && len(pins) != 0 {
					result.keep(filepath.Join(cache, name) + ": pinned by a persistent VM")
					continue
				}
				collect(cache, name, goldenEntry.FindStringSubmatch(name)[1], recorded(filepath.Join(cache, name)))
			case installedDir.MatchString(name):
				sub := filepath.Join(cache, name)
				installed, err := os.ReadDir(sub)
				if err != nil {
					failures = append(failures, err)
					continue
				}
				failures = append(failures, sweepTrash(sub, &result, dryRun))
				for _, item := range installed {
					if match := digestEntry.FindStringSubmatch(item.Name()); item.IsDir() && match != nil {
						collect(sub, item.Name(), match[1], recorded(filepath.Join(sub, item.Name())))
					}
				}
			case name == "repository-snapshots":
				sub := filepath.Join(cache, name, "sha256")
				closures, err := os.ReadDir(sub)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					failures = append(failures, err)
					continue
				}
				failures = append(failures, sweepTrash(sub, &result, dryRun))
				for _, item := range closures {
					if digest := item.Name(); item.IsDir() && hexDigest.MatchString(digest) {
						collect(sub, digest, "", fixed(digest))
					}
				}
			}
		}
	}
	return result, errors.Join(failures...)
}

// recordedSource reads a derived entry's source image digest.
func recordedSource(entry string) (string, error) {
	data, err := os.ReadFile(filepath.Join(entry, SourceFile))
	if errors.Is(err, fs.ErrNotExist) {
		return "", errors.New("records no source image (built before provenance was recorded)")
	}
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(string(data))
	if !hexDigest.MatchString(digest) {
		return "", fmt.Errorf("unreadable %s %q", SourceFile, digest)
	}
	return digest, nil
}

// tryLock takes the exclusive per-entry flock without waiting, creating the
// lock file as the lab does (private, singly linked); ok is false while
// another process holds it.
func tryLock(path string) (unlock func(), ok bool, err error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { _ = file.Close() }, true, nil
}
