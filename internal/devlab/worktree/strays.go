package worktree

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Stray is an uncommitted change in the main checkout that no landing holds:
// usually an agent's edit aimed at its private worktree that a relative path
// sent to the shared tree instead.
type Stray struct {
	Status   string    // git status --porcelain XY code
	Path     string    // relative to the main checkout
	Modified time.Time // of the main checkout's copy; zero when it is deleted
	// Sources are the private worktrees whose working copy holds the same
	// change, likeliest first: identical copies, then the same hunks, each
	// ordered by how close its copy's mtime is to Modified.
	Sources []Source
}

// Source is a private worktree whose working copy holds a stray change.
type Source struct {
	Worktree string
	Owner    string // inferred from the directory name; a routing hint only
	// Identical is true when the worktree's copy equals the stray (or both
	// deleted it), false when it only holds the same hunks among others.
	Identical bool
	Modified  time.Time // of the worktree's copy; zero when it is deleted
}

// maxListedSources bounds the candidate worktrees named per stray.
const maxListedSources = 3

// String renders the stray with its mtime and likely source for a refusal.
func (s Stray) String() string {
	line := s.Status + " " + s.Path
	if s.Modified.IsZero() {
		line += "  (deleted)"
	} else {
		line += fmt.Sprintf("  modified %s (%s ago)", s.Modified.Local().Format("2006-01-02 15:04:05 MST"), time.Since(s.Modified).Round(time.Second))
	}
	if len(s.Sources) == 0 {
		return line + "; no private worktree holds this change"
	}
	var named []string
	for _, source := range s.Sources[:min(len(s.Sources), maxListedSources)] {
		match := "same hunks"
		if source.Identical {
			match = "identical file"
		}
		named = append(named, fmt.Sprintf("%s (owner %s, %s)", source.Worktree, source.Owner, match))
	}
	line += "; likely from " + named[0]
	if len(named) > 1 {
		line += "; also held by " + strings.Join(named[1:], ", ")
	}
	if extra := len(s.Sources) - len(named); extra > 0 {
		line += fmt.Sprintf(" and %d more", extra)
	}
	return line
}

// Strays lists the main checkout's uncommitted changes, each with the private
// worktrees whose own working copy holds it. Call it under the landing lock,
// when no landing's applied files can explain the changes. Only the first
// maxListedFiles are traced to worktrees.
func (r *Repository) Strays(ctx context.Context) ([]Stray, error) {
	status, err := git(ctx, r.Main, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
	if err != nil {
		return nil, err
	}
	var strays []Stray
	for record := range strings.SplitSeq(status, "\x00") {
		if len(record) > 3 {
			strays = append(strays, Stray{Status: record[:2], Path: record[3:]})
		}
	}
	entries, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	worktrees := entries[:0]
	for _, entry := range entries {
		if !entry.Missing {
			worktrees = append(worktrees, entry)
		}
	}
	bases := map[string]string{} // worktree HEAD -> merge base with HEAD of main, for deletions
	for i := range strays {
		stray := &strays[i]
		current, err := readCopy(filepath.Join(r.Main, stray.Path))
		if err != nil {
			return nil, err
		}
		stray.Modified = current.modified
		if i >= maxListedFiles {
			continue
		}
		head := copyState{known: true}
		if stray.Status[0] != '?' && stray.Status[0] != 'A' {
			blob, err := git(ctx, r.Main, "cat-file", "blob", "HEAD:"+stray.Path)
			// An unreadable HEAD copy (oversized, unusual entry) leaves only
			// identical copies as evidence.
			head = copyState{content: []byte(blob), exists: true, known: err == nil}
		}
		if !current.known || (head.known && current.exists == head.exists && bytes.Equal(current.content, head.content)) {
			continue // unreadable, or a mode change that every untouched copy would match
		}
		added, removed := lineDelta(head, current)
		for _, entry := range worktrees {
			theirs, err := readCopy(filepath.Join(entry.Path, stray.Path))
			if err != nil || !theirs.known {
				continue // an unreadable copy is no evidence
			}
			source := Source{Worktree: entry.Path, Owner: owner(entry.Path), Modified: theirs.modified}
			switch {
			case !current.exists && !theirs.exists:
				// Many trees lack a file because their base predates it; only
				// a tree whose base had it deleted it.
				base, err := r.baseOf(ctx, bases, entry.Head)
				if err != nil {
					continue // no common history is no evidence
				}
				if _, err := git(ctx, r.Main, "cat-file", "-e", base+":"+stray.Path); err != nil {
					continue
				}
				source.Identical = true
			case current.exists && theirs.exists && bytes.Equal(current.content, theirs.content):
				source.Identical = true
			case !current.exists || !theirs.exists || !head.known || (head.exists && bytes.Equal(theirs.content, head.content)):
				continue
			case !holdsHunks(theirs.content, added, removed):
				continue
			}
			stray.Sources = append(stray.Sources, source)
		}
		slices.SortStableFunc(stray.Sources, func(a, b Source) int {
			if a.Identical != b.Identical {
				if a.Identical {
					return -1
				}
				return 1
			}
			return cmp.Compare(distance(a.Modified, stray.Modified), distance(b.Modified, stray.Modified))
		})
	}
	return strays, nil
}

// refuseDirty is Land's refusal over uncommitted changes. Land holds the
// landing lock, so no live landing applied them: each is listed with its
// mtime and the worktree that likely made it, so the culprit is obvious.
func (r *Repository) refuseDirty(ctx context.Context, porcelain string) error {
	var report strings.Builder
	report.WriteString("refused: the shared checkout has uncommitted changes that no landing holds (a tool wrote into it instead of a private worktree, or a landing died); land them from their worktree or remove them first:\n")
	if landing, err := r.CurrentLanding(); err == nil && landing != nil && landing.PID != os.Getpid() {
		landing.Stale = true // this process holds the lock, so its writer is gone
		fmt.Fprintf(&report, "  %s\n", landing)
	}
	strays, err := r.Strays(ctx)
	if err != nil {
		return fmt.Errorf("%s%s\n(tracing the changes to worktrees failed: %w)", report.String(), porcelain, err)
	}
	for i, stray := range strays {
		if i == maxListedFiles {
			fmt.Fprintf(&report, "  … and %d more\n", len(strays)-i)
			break
		}
		fmt.Fprintf(&report, "  %s\n", stray)
	}
	return errors.New(strings.TrimSuffix(report.String(), "\n"))
}

// baseOf returns, memoized in bases, the merge base of a worktree's HEAD with
// the main checkout's HEAD.
func (r *Repository) baseOf(ctx context.Context, bases map[string]string, head string) (string, error) {
	if base, ok := bases[head]; ok {
		return base, nil
	}
	base, err := git(ctx, r.Main, "merge-base", "HEAD", head)
	if err != nil {
		return "", err
	}
	bases[head] = strings.TrimSpace(base)
	return bases[head], nil
}

// copyState is one copy of a path: its content (a symlink's target) when it
// exists and known says the content could be read within maxGitOutput.
type copyState struct {
	content  []byte
	exists   bool
	known    bool
	modified time.Time
}

func readCopy(path string) (copyState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return copyState{known: true}, nil
	}
	if err != nil {
		return copyState{}, err
	}
	state := copyState{exists: true, modified: info.ModTime()}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		state.content, state.known = []byte(target), err == nil
	case info.Mode().IsRegular() && info.Size() <= maxGitOutput:
		content, err := os.ReadFile(path)
		state.content, state.known = content, err == nil
	}
	return state, nil
}

// lineDelta returns the significant lines current adds to head and those it
// removes: the content of the change's hunks, independent of their context.
func lineDelta(head, current copyState) (added, removed []string) {
	before, after := lineSet(head.content), lineSet(current.content)
	for line := range after {
		if !before[line] {
			added = append(added, line)
		}
	}
	for line := range before {
		if !after[line] {
			removed = append(removed, line)
		}
	}
	return added, removed
}

// holdsHunks reports whether content carries a change's hunks: every line it
// adds and none it removes. A change of only insignificant lines (braces,
// blanks) proves nothing.
func holdsHunks(content []byte, added, removed []string) bool {
	if len(added) == 0 && len(removed) == 0 {
		return false
	}
	lines := lineSet(content)
	for _, line := range added {
		if !lines[line] {
			return false
		}
	}
	for _, line := range removed {
		if lines[line] {
			return false
		}
	}
	return true
}

func lineSet(content []byte) map[string]bool {
	lines := map[string]bool{}
	for line := range strings.Lines(string(content)) {
		if text := significant(line); text != "" {
			lines[text] = true
		}
	}
	return lines
}

func distance(a, b time.Time) time.Duration {
	if a.IsZero() || b.IsZero() {
		return 1<<63 - 1
	}
	return max(a.Sub(b), b.Sub(a))
}
