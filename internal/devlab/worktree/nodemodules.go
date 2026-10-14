// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"lindm/internal/labexec"
)

// Every checkout owns its node_modules. A worktree symlinked to the main
// checkout's tree let npm ci in that worktree delete the shared install for
// every checkout; installs are therefore built beside their destination and
// published with an atomic exchange, so readers see either the old or the new
// tree and a failed install leaves the old one in place.

// NodeModulesState describes a checkout's node_modules: "own", "missing", or
// "symlink -> TARGET" for the retired shared layout.
func NodeModulesState(checkout string) string {
	path := filepath.Join(checkout, "node_modules")
	info, err := os.Lstat(path)
	switch {
	case err != nil:
		return "missing"
	case info.Mode()&os.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		return "symlink -> " + target
	default:
		return "own"
	}
}

// InstallNodeModules gives the worktree at path its own node_modules: a
// hardlinked copy of the main checkout's install when both pin identical
// package manifests (fast, no network, and npm in either checkout replaces
// files rather than writing through the links), otherwise npm ci
// --prefer-offline from the shared npm cache. An existing symlink or tree is
// replaced atomically.
func (r *Repository) InstallNodeModules(ctx context.Context, path string, log io.Writer) error {
	same, err := sameManifests(path, r.Main)
	if err != nil {
		return err
	}
	shared := filepath.Join(r.Main, "node_modules")
	if info, err := os.Lstat(shared); same && err == nil && info.IsDir() {
		err := PublishNodeModules(path, func(staging string) error {
			return labexec.Run(ctx, labexec.Command{Path: "cp", Args: []string{"-al", shared, filepath.Join(staging, "node_modules")}, Stdout: log, Stderr: log})
		})
		if err == nil {
			_, err = fmt.Fprintf(log, "node_modules: own hardlinked copy of %s (identical package manifests)\n", shared)
			return err
		}
		if _, werr := fmt.Fprintf(log, "node_modules: hardlinked copy failed (%v); installing with npm ci\n", err); werr != nil {
			return werr
		}
	}
	if err := PublishNodeModules(path, func(staging string) error { return npmCI(ctx, path, staging, log) }); err != nil {
		return err
	}
	_, err = fmt.Fprintln(log, "node_modules: own install (npm ci --prefer-offline)")
	return err
}

// npmCI installs checkout's locked dependencies into staging/node_modules.
func npmCI(ctx context.Context, checkout, staging string, log io.Writer) error {
	for _, file := range []string{"package.json", "package-lock.json"} {
		data, err := os.ReadFile(filepath.Join(checkout, file))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(staging, file), data, 0o644); err != nil {
			return err
		}
	}
	if err := labexec.Run(ctx, labexec.Command{Path: "npm", Args: []string{"ci", "--ignore-scripts", "--prefer-offline", "--no-audit", "--no-fund"}, Dir: staging, Stdout: log, Stderr: log}); err != nil {
		return fmt.Errorf("npm ci: %w", err)
	}
	return nil
}

// SyncNodeModules reinstalls checkout's node_modules from its lockfile with
// npm ci --prefer-offline, published atomically.
func SyncNodeModules(ctx context.Context, checkout string, log io.Writer) error {
	return PublishNodeModules(checkout, func(staging string) error { return npmCI(ctx, checkout, staging, log) })
}

// PublishNodeModules runs build to create staging/node_modules in a private
// directory on checkout's filesystem, then atomically exchanges it with
// checkout/node_modules (or renames it into place when absent) and removes the
// previous tree. A symlinked node_modules is replaced as a link: its target is
// never touched. On any failure the existing node_modules is unchanged.
func PublishNodeModules(checkout string, build func(staging string) error) (resultErr error) {
	staging, err := os.MkdirTemp(checkout, ".node_modules-staging-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(staging)) }()
	if err := build(staging); err != nil {
		return err
	}
	built := filepath.Join(staging, "node_modules")
	if info, err := os.Lstat(built); err != nil || !info.IsDir() {
		return errors.Join(err, fmt.Errorf("install produced no node_modules in %s", staging))
	}
	destination := filepath.Join(checkout, "node_modules")
	if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
		return os.Rename(built, destination)
	} else if err != nil {
		return err
	}
	// After the exchange the previous tree (or link) sits in staging and is
	// removed with it; RemoveAll removes a link itself, not its target.
	return unix.Renameat2(unix.AT_FDCWD, built, unix.AT_FDCWD, destination, unix.RENAME_EXCHANGE)
}

func sameManifests(a, b string) (bool, error) {
	for _, file := range []string{"package.json", "package-lock.json"} {
		x, err := os.ReadFile(filepath.Join(a, file))
		if err != nil {
			return false, err
		}
		y, err := os.ReadFile(filepath.Join(b, file))
		if err != nil {
			return false, err
		}
		if !bytes.Equal(x, y) {
			return false, nil
		}
	}
	return true, nil
}

// Holder is a process holding or waiting for a flock.
type Holder struct {
	PID     int
	Waiting bool
	Command string
}

// LockHolders reads /proc/locks for the processes that hold, or are blocked
// waiting for, a flock on path. Unlike the holder record written into the
// file, this cannot go stale. Waiters that poll with LOCK_NB do not appear.
func LockHolders(path string) ([]Holder, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, err
	}
	key := fmt.Sprintf("%02x:%02x:%d", unix.Major(stat.Dev), unix.Minor(stat.Dev), stat.Ino)
	data, err := os.ReadFile("/proc/locks")
	if err != nil {
		return nil, err
	}
	var holders []Holder
	for line := range bytes.Lines(data) {
		fields := bytes.Fields(line)
		waiting := len(fields) > 1 && string(fields[1]) == "->"
		if waiting {
			fields = append(fields[:1:1], fields[2:]...)
		}
		// "N: FLOCK ADVISORY WRITE PID MAJ:MIN:INODE START END"
		if len(fields) < 6 || string(fields[1]) != "FLOCK" || string(fields[5]) != key {
			continue
		}
		pid, err := strconv.Atoi(string(fields[4]))
		if err != nil {
			continue
		}
		command, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
		holders = append(holders, Holder{PID: pid, Waiting: waiting, Command: string(bytes.TrimSpace(bytes.ReplaceAll(command, []byte{0}, []byte{' '})))})
	}
	return holders, nil
}
