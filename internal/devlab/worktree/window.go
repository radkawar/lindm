// SPDX-License-Identifier: Apache-2.0

package worktree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The landing window is the time the main checkout is writable under the
// landing lock. Another process (a tool aimed at the wrong directory) can
// write into it then. Land and GateCommit commit only what they verified, by
// explicit path, and refuse (naming the files) when anything else changed.

// fingerprint is a path's content as Land applied it: the sha256 of the
// file (blanked for documents whose generated regions the gate regenerates),
// of a symlink's target, or "" when absent.
func (r *Repository) fingerprint(name string, blank func(string, []byte) []byte) (string, error) {
	path := filepath.Join(r.Main, name)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var content []byte
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		content = []byte("symlink:" + target)
	case info.Mode().IsRegular():
		if content, err = os.ReadFile(path); err != nil {
			return "", err
		}
		if blank != nil && strings.HasSuffix(name, ".md") {
			content = blank(name, content)
		}
	default:
		content = []byte("type:" + info.Mode().Type().String())
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

// fingerprints records fingerprint for each of names.
func (r *Repository) fingerprints(names []string, blank func(string, []byte) []byte) (map[string]string, error) {
	prints := make(map[string]string, len(names))
	for _, name := range names {
		print, err := r.fingerprint(name, blank)
		if err != nil {
			return nil, err
		}
		prints[name] = print
	}
	return prints, nil
}

// changedSince names the paths whose fingerprint differs from prints.
func (r *Repository) changedSince(prints map[string]string, blank func(string, []byte) []byte) ([]string, error) {
	var changed []string
	for _, name := range slices.Sorted(maps.Keys(prints)) {
		now, err := r.fingerprint(name, blank)
		if err != nil {
			return nil, err
		}
		if now != prints[name] {
			changed = append(changed, name)
		}
	}
	return changed, nil
}

// strayError names files another process changed during the landing window.
func strayError(names []string) error {
	return fmt.Errorf("files changed in the shared checkout during the landing by something other than the landing (a tool writing into the shared tree instead of a private worktree), nothing committed: %s", strings.Join(names, " "))
}

// savedState is an uncommitted path's content saved in the object database,
// so it can be written back exactly.
type savedState struct {
	print  string // fingerprint ("" absent)
	blob   string // object id of a regular file's content
	mode   fs.FileMode
	target string // symlink target
}

// saveUncommitted records every uncommitted path of the main checkout
// (tracked changes and untracked non-ignored files) and stores regular
// files' content as blobs, without hooks or filters.
func (r *Repository) saveUncommitted(ctx context.Context) (map[string]savedState, error) {
	tracked, untracked, err := r.uncommitted(ctx)
	if err != nil {
		return nil, err
	}
	states := map[string]savedState{}
	for _, name := range slices.Concat(tracked, untracked) {
		state, err := r.saveState(ctx, name)
		if err != nil {
			return nil, err
		}
		states[name] = state
	}
	return states, nil
}

func (r *Repository) saveState(ctx context.Context, name string) (savedState, error) {
	print, err := r.fingerprint(name, nil)
	if err != nil || print == "" {
		return savedState{print: print}, err
	}
	path := filepath.Join(r.Main, name)
	info, err := os.Lstat(path)
	if err != nil {
		return savedState{}, err
	}
	state := savedState{print: print, mode: info.Mode()}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		state.target, err = os.Readlink(path)
	case info.Mode().IsRegular():
		var object string
		object, err = git(ctx, r.Main, "hash-object", "-w", "--no-filters", "--", name)
		state.blob = strings.TrimSpace(object)
	}
	return state, err
}

// restoreState writes a saved state back, or restores name to HEAD (removing
// it when HEAD lacks it) when it was not uncommitted.
func (r *Repository) restoreState(ctx context.Context, name string, state savedState, saved bool) error {
	path := filepath.Join(r.Main, name)
	if !saved {
		if _, err := git(ctx, r.Main, "cat-file", "-e", "HEAD:"+name); err == nil {
			_, err := git(ctx, r.Main, "--literal-pathspecs", "checkout", "--quiet", "HEAD", "--", name)
			return err
		}
		return os.RemoveAll(path)
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	switch {
	case state.print == "":
		return nil
	case state.target != "":
		return os.Symlink(state.target, path)
	default:
		content, err := git(ctx, r.Main, "cat-file", "blob", state.blob)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(content), state.mode.Perm())
	}
}

// GateCommit runs gate (the full check) over the main checkout's uncommitted
// change and commits exactly that change, by explicit path, with message.
// Call it under the landing lock with the tree writable. If any path changes
// while the gate runs (a file another process wrote, or one it altered), it
// commits nothing, writes the verified state back, and names those paths.
// Hooks are skipped: the gate just ran, and a formatting hook would commit
// content the gate never saw.
func (r *Repository) GateCommit(ctx context.Context, message string, gate func() error) error {
	if strings.TrimSpace(message) == "" {
		return errors.New("gate-commit requires a commit message")
	}
	before, err := r.saveUncommitted(ctx)
	if err != nil {
		return err
	}
	if len(before) == 0 {
		return errors.New("nothing to commit: the shared checkout has no uncommitted change")
	}
	if err := gate(); err != nil {
		return fmt.Errorf("gate failed, nothing committed: %w", err)
	}
	after, err := r.saveUncommitted(ctx)
	if err != nil {
		return err
	}
	var changed []string
	for name, state := range after {
		if prior, ok := before[name]; !ok || prior.print != state.print {
			changed = append(changed, name)
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			changed = append(changed, name)
		}
	}
	if len(changed) != 0 {
		slices.Sort(changed)
		var failures []error
		for _, name := range changed {
			state, saved := before[name]
			failures = append(failures, r.restoreState(ctx, name, state, saved))
		}
		return errors.Join(append([]error{strayError(changed)}, failures...)...)
	}
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	slices.Sort(names)
	if _, err := gitWith(ctx, r.Main, nil, []byte(strings.Join(names, "\x00")), "--literal-pathspecs", "add", "--all", "--pathspec-from-file=-", "--pathspec-file-nul"); err != nil {
		return err
	}
	staged, err := git(ctx, r.Main, "diff", "--cached", "--name-only", "-z", "--no-renames")
	if err != nil {
		return err
	}
	if got := slices.Sorted(slices.Values(strings.FieldsFunc(staged, func(r rune) bool { return r == 0 }))); !slices.Equal(got, names) {
		_, resetErr := git(ctx, r.Main, "reset", "--quiet")
		return errors.Join(fmt.Errorf("staged %v, not the verified change %v; nothing committed", got, names), resetErr)
	}
	_, err = git(ctx, r.Main, "commit", "--quiet", "--no-verify", "-m", message)
	return err
}
