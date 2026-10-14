// SPDX-License-Identifier: Apache-2.0

// Package worktree manages private lindm git worktrees beside the main
// checkout (<main>.worktrees/<name>): creation with a lockfile-checked shared
// npm install, status listing, and pruning that archives unmerged work first
// and never removes a tree that a live process or running dev fixture uses.
// It does not create branches, fetch remotes or manage third-party clones.
package worktree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/project"
	"lindm/internal/labexec"
)

// Trunk is the branch that merged work must be reachable from.
const Trunk = "main"

// maxGitOutput bounds captured git output; large payloads (diffs) stream to files.
const maxGitOutput = 16 << 20

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Repository is one main checkout and its private worktree area.
type Repository struct {
	Main    string // main checkout that owns the common git directory
	Root    string // private worktree parent, <Main>.worktrees
	Archive string // archive parent for pruned unmerged work
}

// Open locates the main checkout of the repository containing dir.
func Open(ctx context.Context, dir string) (*Repository, error) {
	common, err := git(ctx, dir, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return nil, err
	}
	common = strings.TrimSpace(common)
	if filepath.Base(common) != ".git" {
		return nil, fmt.Errorf("worktree: %s is not a non-bare checkout's .git directory", common)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	main := filepath.Dir(common)
	return &Repository{Main: main, Root: main + ".worktrees", Archive: filepath.Join(cache, "lindm-worktree-archive")}, nil
}

// Add creates Root/name detached at rev, gives it its own node_modules
// (InstallNodeModules) and installs the pinned .tools.
// It returns the new path. Progress from npm goes to log.
func (r *Repository) Add(ctx context.Context, name, rev string, log io.Writer) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("worktree name %q must match %s", name, namePattern)
	}
	path := filepath.Join(r.Root, name)
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("%s already exists", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(r.Root, 0o755); err != nil {
		return "", err
	}
	if _, err := git(ctx, r.Main, "worktree", "add", "--detach", path, rev+"^{commit}"); err != nil {
		return "", err
	}
	if err := r.InstallNodeModules(ctx, path, log); err != nil {
		return path, fmt.Errorf("node_modules for %s: %w", path, err)
	}
	// Commit hooks and gates use the checkout's own pinned .tools; a shared
	// tool directory would be reinstalled by every newer Makefile.
	if err := labexec.Run(ctx, labexec.Command{Path: "make", Args: []string{"--no-print-directory", "tools"}, Dir: path, Stdout: log, Stderr: log}); err != nil {
		return path, fmt.Errorf("make tools in %s: %w", path, err)
	}
	return path, nil
}

// Remove force-removes a worktree this package created, without prune checks.
func (r *Repository) Remove(ctx context.Context, path string) error {
	if _, err := git(ctx, r.Main, "worktree", "remove", "--force", path); err != nil {
		return err
	}
	_, err := git(ctx, r.Main, "worktree", "prune")
	return err
}

// Entry is one registered worktree as git records it.
type Entry struct {
	Path, Head, Branch string
	Locked, Missing    bool
}

// List returns every registered worktree except the main checkout.
func (r *Repository) List(ctx context.Context) ([]Entry, error) {
	out, err := git(ctx, r.Main, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for field := range strings.SplitSeq(out, "\x00") {
		key, value, _ := strings.Cut(field, " ")
		if key == "worktree" {
			entries = append(entries, Entry{Path: value})
			continue
		}
		if len(entries) == 0 {
			continue
		}
		current := &entries[len(entries)-1]
		switch key {
		case "HEAD":
			current.Head = value
		case "branch":
			current.Branch = strings.TrimPrefix(value, "refs/heads/")
		case "locked":
			current.Locked = true
		case "prunable":
			current.Missing = true
		}
	}
	main := canonical(r.Main)
	kept := entries[:0]
	for _, entry := range entries {
		if canonical(entry.Path) != main {
			kept = append(kept, entry)
		}
	}
	return kept, nil
}

// Status is a worktree's relationship to Trunk and its on-disk footprint.
type Status struct {
	Entry
	Ahead, Behind int
	Merged, Dirty bool
	Modified      time.Time // newest mtime outside node_modules
	Bytes         int64     // allocated bytes, symlinks not followed
}

// Inspect reads a present worktree's status.
func (r *Repository) Inspect(ctx context.Context, entry Entry) (Status, error) {
	status := Status{Entry: entry}
	counts, err := git(ctx, r.Main, "rev-list", "--left-right", "--count", Trunk+"..."+entry.Head)
	if err != nil {
		return status, err
	}
	behind, ahead, _ := strings.Cut(strings.TrimSpace(counts), "\t")
	if status.Behind, err = strconv.Atoi(behind); err != nil {
		return status, fmt.Errorf("parse rev-list count %q: %w", counts, err)
	}
	if status.Ahead, err = strconv.Atoi(ahead); err != nil {
		return status, fmt.Errorf("parse rev-list count %q: %w", counts, err)
	}
	status.Merged = status.Ahead == 0
	dirty, err := git(ctx, entry.Path, "status", "--porcelain", "-z")
	if err != nil {
		return status, err
	}
	status.Dirty = dirty != ""
	modules := string(filepath.Separator) + "node_modules"
	err = filepath.WalkDir(entry.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			status.Bytes += stat.Blocks * 512
		}
		// A real node_modules is reinstallable bulk, not authored work.
		if !strings.Contains(path, modules) && info.ModTime().After(status.Modified) {
			status.Modified = info.ModTime()
		}
		return nil
	})
	return status, err
}

// PruneOptions selects what prune may remove.
type PruneOptions struct {
	OlderThan    time.Duration // keep trees modified more recently
	DryRun       bool          // report only; no archives, no removal
	ArchiveDirty bool          // archive then remove dirty or diverged trees
	Now          time.Time
}

// Decision is prune's verdict for one target.
type Decision struct {
	Path    string
	Status  *Status // nil when the target was not inspected
	Audit   *Audit  // set when the tree was dirty or diverged
	Removed bool    // removed, or would be in a dry run
	Reason  string
	Archive string
}

// Prune decides, and unless DryRun applies, the fate of each target path, or
// of every worktree under Root when targets is empty. Removal requires a
// clean tree merged into Trunk, or a dirty or diverged tree that the audit
// finds LANDED or SNAPSHOT (or any with ArchiveDirty) after a completed
// archive, and no process or running dev fixture using the tree. Git's records of missing
// worktrees are pruned afterwards.
func (r *Repository) Prune(ctx context.Context, targets []string, options PruneOptions, report func(Decision) error) error {
	entries, err := r.List(ctx)
	if err != nil {
		return err
	}
	byPath := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		byPath[canonical(entry.Path)] = entry
	}
	selected := targets
	if len(selected) == 0 {
		root := canonical(r.Root)
		for _, entry := range entries {
			if within(canonical(entry.Path), root) {
				selected = append(selected, entry.Path)
			}
		}
	}
	for _, target := range selected {
		entry, ok := byPath[canonical(target)]
		if !ok {
			if err := report(Decision{Path: target, Reason: "not a registered worktree of " + r.Main}); err != nil {
				return err
			}
			continue
		}
		decision, err := r.decide(ctx, entry, options)
		if err != nil {
			decision.Removed, decision.Reason = false, err.Error()
		}
		if err := report(decision); err != nil {
			return err
		}
	}
	if options.DryRun {
		return nil
	}
	_, err = git(ctx, r.Main, "worktree", "prune")
	return err
}

func (r *Repository) decide(ctx context.Context, entry Entry, options PruneOptions) (Decision, error) {
	decision := Decision{Path: entry.Path}
	switch {
	case entry.Missing:
		decision.Reason = "directory missing; record cleared by git worktree prune"
		return decision, nil
	case entry.Locked:
		decision.Reason = "locked"
		return decision, nil
	}
	if user, err := r.user(ctx, entry.Path); err != nil || user != "" {
		decision.Reason = user
		return decision, err
	}
	status, err := r.Inspect(ctx, entry)
	decision.Status = &status
	if err != nil {
		return decision, err
	}
	if age := options.Now.Sub(status.Modified); age < options.OlderThan {
		decision.Reason = "modified " + age.Round(time.Minute).String() + " ago"
		return decision, nil
	}
	var unmerged []string
	if status.Dirty {
		unmerged = append(unmerged, "dirty")
	}
	if !status.Merged {
		unmerged = append(unmerged, fmt.Sprintf("diverged (%d ahead of %s)", status.Ahead, Trunk))
	}
	decision.Removed, decision.Reason = true, "clean and merged into "+Trunk
	if len(unmerged) != 0 {
		// Work copied into main by hand leaves trees dirty or diverged yet
		// holding nothing main lacks; the audit recognizes it by content.
		audit := r.AuditPath(ctx, entry.Path)
		decision.Audit = &audit
		switch {
		case audit.Verdict.Disposable():
			decision.Reason = strings.Join(unmerged, ", ") + "; audit " + string(audit.Verdict) + "; archived"
		case options.ArchiveDirty:
			decision.Reason = strings.Join(unmerged, ", ") + "; audit " + string(audit.Verdict) + "; archived (-archive-dirty)"
		default:
			decision.Removed = false
			decision.Reason = fmt.Sprintf("%s; audit %s (%d unlanded files); -archive-dirty archives then removes", strings.Join(unmerged, ", "), audit.Verdict, len(audit.Unlanded))
			return decision, nil
		}
	}
	if options.DryRun {
		return decision, nil
	}
	if len(unmerged) != 0 {
		if decision.Archive, err = r.archive(ctx, status, options.Now); err != nil {
			return decision, fmt.Errorf("archive failed, kept: %w", err)
		}
	}
	// The process table changes while trees are walked and archived.
	if user, err := r.user(ctx, entry.Path); err != nil || user != "" {
		decision.Removed, decision.Reason = false, user
		return decision, err
	}
	if _, err := git(ctx, r.Main, "worktree", "remove", "--force", entry.Path); err != nil {
		return decision, err
	}
	return decision, nil
}

// archive saves what removal would lose: the HEAD record, a binary diff of
// tracked changes, a tar of untracked non-ignored files and, for diverged
// trees, a bundle of the commits Trunk does not contain.
func (r *Repository) archive(ctx context.Context, status Status, now time.Time) (string, error) {
	dir := filepath.Join(r.Archive, filepath.Base(status.Path)+"-"+now.UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(r.Archive, 0o700); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	head := fmt.Sprintf("%s\npath %s\nbranch %s\n", status.Head, status.Path, status.Branch)
	if err := os.WriteFile(filepath.Join(dir, "HEAD"), []byte(head), 0o600); err != nil {
		return dir, err
	}
	if err := gitToFile(ctx, status.Path, filepath.Join(dir, "diff.patch"), "diff", "--binary", "HEAD"); err != nil {
		return dir, err
	}
	list := filepath.Join(dir, "untracked.list")
	if err := gitToFile(ctx, status.Path, list, "ls-files", "--others", "--exclude-standard", "-z"); err != nil {
		return dir, err
	}
	if info, err := os.Stat(list); err != nil {
		return dir, err
	} else if info.Size() != 0 {
		output := newBuffer(64 << 10)
		args := []string{"-C", status.Path, "--null", "--no-recursion", "-T", list, "-cf", filepath.Join(dir, "untracked.tar")}
		if err := labexec.Run(ctx, labexec.Command{Path: "tar", Args: args, Stdout: output, Stderr: output}); err != nil {
			return dir, fmt.Errorf("tar untracked files: %w: %s", err, bytes.TrimSpace(output.Bytes()))
		}
	}
	if !status.Merged {
		if _, err := git(ctx, status.Path, "bundle", "create", filepath.Join(dir, "head.bundle"), "HEAD", "^"+Trunk); err != nil {
			return dir, err
		}
	}
	return dir, nil
}

// user names the first live user of path: a process whose cwd, root,
// executable or open file lies beneath it, or the running dev Compose project
// of a checkout there. Unreadable processes belong to other users.
func (r *Repository) user(ctx context.Context, path string) (string, error) {
	root := canonical(path)
	pids, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid.Name()); err != nil {
			continue
		}
		base := filepath.Join("/proc", pid.Name())
		links := []string{filepath.Join(base, "cwd"), filepath.Join(base, "root"), filepath.Join(base, "exe")}
		if fds, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
			for _, fd := range fds {
				links = append(links, filepath.Join(base, "fd", fd.Name()))
			}
		}
		for _, link := range links {
			target, err := os.Readlink(link)
			if err == nil && within(strings.TrimSuffix(target, " (deleted)"), root) {
				comm, _ := os.ReadFile(filepath.Join(base, "comm"))
				return fmt.Sprintf("in use by pid %s (%s)", pid.Name(), strings.TrimSpace(string(comm))), nil
			}
		}
	}
	return composeUser(ctx, root)
}

// composeUser reports a running dev fixture of the checkout at root; its
// containers bind-mount the tree but appear in no host process's links.
func composeUser(ctx context.Context, root string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil
	}
	stdout, stderr := newBuffer(1<<20), newBuffer(64<<10)
	if err := labexec.Run(ctx, labexec.Command{Path: "docker", Args: []string{"ps", "--format", `{{.Label "com.docker.compose.project"}}`}, Stdout: stdout, Stderr: stderr}); err != nil {
		return "", fmt.Errorf("list running containers: %w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	name := project.ComposeName(root)
	for line := range strings.Lines(stdout.String()) {
		if strings.TrimSpace(line) == name {
			return "dev fixture " + name + " is running", nil
		}
	}
	return "", nil
}

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// canonical resolves symlinks where the path exists, so recorded, typed and
// /proc paths compare equal.
func canonical(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved
	}
	return absolute
}

// noHooks keeps repository hooks out of this package's git commands: they
// operate on checkouts mid-landing, where a hook that builds the tree (the
// main checkout's post-checkout) would fail and abort a rollback.
var noHooks = []string{"-c", "core.hooksPath=/dev/null"}

// git runs git in dir and returns bounded stdout.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	return gitWith(ctx, dir, nil, nil, args...)
}

// gitWith runs git with extra environment and optional stdin, without hooks.
func gitWith(ctx context.Context, dir string, env []string, stdin []byte, args ...string) (string, error) {
	stdout, stderr := newBuffer(maxGitOutput), newBuffer(64<<10)
	command := labexec.Command{Path: "git", Args: append(slices.Clone(noHooks), args...), Dir: dir, Stdout: stdout, Stderr: stderr}
	if env != nil {
		command.Env = append(os.Environ(), env...)
	}
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	if err := labexec.Run(ctx, command); err != nil {
		return "", fmt.Errorf("git %s in %s: %w: %s", strings.Join(args, " "), dir, err, bytes.TrimSpace(stderr.Bytes()))
	}
	if stdout.Truncated() {
		return "", fmt.Errorf("git %s in %s: output exceeds %d bytes", strings.Join(args, " "), dir, maxGitOutput)
	}
	return stdout.String(), nil
}

// gitToFile streams git's stdout into a new private file.
func gitToFile(ctx context.Context, dir, path string, args ...string) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	stderr := newBuffer(64 << 10)
	if err := labexec.Run(ctx, labexec.Command{Path: "git", Args: append(slices.Clone(noHooks), args...), Dir: dir, Stdout: file, Stderr: stderr}); err != nil {
		return fmt.Errorf("git %s in %s: %w: %s", strings.Join(args, " "), dir, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return nil
}

// buffer retains the first limit bytes written to it.
type buffer struct {
	data      bytes.Buffer
	limit     int
	truncated bool
}

func newBuffer(limit int) *buffer { return &buffer{limit: limit} }

func (b *buffer) Write(p []byte) (int, error) {
	keep := min(len(p), b.limit-b.data.Len())
	b.truncated = b.truncated || keep < len(p)
	b.data.Write(p[:keep])
	return len(p), nil
}

func (b *buffer) Bytes() []byte   { return b.data.Bytes() }
func (b *buffer) String() string  { return b.data.String() }
func (b *buffer) Truncated() bool { return b.truncated }
