package worktree

import (
	"bytes"
	"context"
	"encoding/json"
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

// TryLock takes the landing lock only if it is free; ok is false, with
// nothing taken, while it is held.
func (r *Repository) TryLock() (unlock func() error, ok bool, err error) {
	file, err := openLock(r.LockPath())
	if err != nil {
		return nil, false, err
	}
	if ok, err := tryFlock(file); err != nil || !ok {
		return nil, false, errors.Join(err, file.Close())
	}
	return hold(file), true, nil
}

// LockFile takes an exclusive flock on path, waiting until ctx ends. While the
// lock is busy, waiting is called with the holder's record each time it
// changes (a new holder, or a holder's progress). The flock is the authority;
// the record is diagnostic. The returned unlock releases it; a crashed holder
// releases it implicitly.
func LockFile(ctx context.Context, path string, waiting func(holder string)) (unlock func() error, err error) {
	file, err := openLock(path)
	if err != nil {
		return nil, err
	}
	for last := ""; ; {
		ok, err := tryFlock(file)
		if err != nil {
			return nil, errors.Join(err, file.Close())
		}
		if ok {
			return hold(file), nil
		}
		if waiting != nil {
			// A record mid-rewrite reads empty; report only complete changes.
			recorded, _ := os.ReadFile(path)
			if holder := strings.TrimSpace(string(recorded)); holder != "" && holder != last {
				waiting(holder)
				last = holder
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func openLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
}

// tryFlock takes the exclusive flock on file without waiting; it reports
// false while another open file description holds it.
func tryFlock(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock %s: %w", file.Name(), err)
	}
	return true, nil
}

// hold records this process as the holder of file's flock and returns its
// release.
func hold(file *os.File) (unlock func() error) {
	holder := "pid " + strconv.Itoa(os.Getpid()) + " " + strings.Join(os.Args, " ") + "\n"
	if err := file.Truncate(0); err == nil {
		_, _ = file.WriteAt([]byte(holder), 0)
	}
	return func() error {
		return errors.Join(file.Truncate(0), syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
	}
}

// Change is a worktree's complete change against Trunk: commits since its
// merge base plus staged, unstaged and untracked non-ignored files.
type Change struct {
	Source string   // worktree the change comes from
	Base   string   // merge base with Trunk
	Patch  []byte   // binary patch with rename detection
	Files  []string // every path the patch creates, modifies or deletes
}

// Change computes the change of the worktree at path, limited to paths when
// any are given. The worktree's own index is never modified.
func (r *Repository) Change(ctx context.Context, path string, paths []string) (Change, error) {
	change := Change{Source: path}
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

// Land commits change to the main checkout's Trunk and pushes it to Trunk's
// upstream, holding nothing back for a later batch commit. Call it under the
// landing lock. It refuses unless the main checkout is on Trunk, has no
// uncommitted change and contains its freshly fetched upstream; local commits
// ahead of upstream are pushed with the landing. It applies the
// change atomically, runs gate on the touched files, commits exactly those
// files with message, and pushes; any failure restores the checkout and the
// local branch to their prior state.
func (r *Repository) Land(ctx context.Context, change Change, message string, gate func(files []string) error) error {
	if strings.TrimSpace(message) == "" {
		return errors.New("land requires a commit message")
	}
	branch, err := git(ctx, r.Main, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || strings.TrimSpace(branch) != "refs/heads/"+Trunk {
		return errors.Join(err, fmt.Errorf("%s is not on %s", r.Main, Trunk))
	}
	dirty, err := git(ctx, r.Main, "status", "--porcelain")
	if err != nil {
		return err
	}
	if dirty != "" {
		return r.refuseDirty(ctx, dirty)
	}
	upstream, err := git(ctx, r.Main, "rev-parse", "--abbrev-ref", Trunk+"@{upstream}")
	if err != nil {
		return err
	}
	remote, remoteBranch, ok := strings.Cut(strings.TrimSpace(upstream), "/")
	if !ok {
		return fmt.Errorf("unexpected upstream %q for %s", upstream, Trunk)
	}
	if _, err := git(ctx, r.Main, "fetch", "--quiet", remote, remoteBranch); err != nil {
		return err
	}
	prior, err := git(ctx, r.Main, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	prior = strings.TrimSpace(prior)
	// Local commits ahead of upstream (a gate-commit not yet pushed) go out
	// with this landing; a checkout behind or diverged from upstream would
	// push over or beside work it has not gated.
	if _, err := git(ctx, r.Main, "merge-base", "--is-ancestor", strings.TrimSpace(upstream), "HEAD"); err != nil {
		return fmt.Errorf("refused: %s %s at %.12s does not contain %s; bring the shared checkout up to %s first", Trunk, r.Main, prior, strings.TrimSpace(upstream), strings.TrimSpace(upstream))
	}
	// The marker tells anyone looking at the shared checkout mid-landing whose
	// applied files they see; it disappears on commit, rollback or refusal.
	if err := r.writeLanding(change, message); err != nil {
		return err
	}
	defer func() { _ = os.Remove(r.landingPath()) }()
	if err := r.Apply(ctx, change.Patch, false); err != nil {
		return fmt.Errorf("refused, nothing applied (rebase the worktree onto %s): %w", Trunk, err)
	}
	// Restoration outlives an interrupted or expired landing.
	restore := func(cause error) error {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, resetErr := git(cleanup, r.Main, "reset", "--quiet", "--soft", prior)
		if resetErr == nil {
			_, resetErr = git(cleanup, r.Main, "reset", "--quiet")
		}
		if err := errors.Join(resetErr, r.Apply(cleanup, change.Patch, true)); err != nil {
			return fmt.Errorf("%w; ROLLBACK FAILED, the shared checkout still holds the change: %w", cause, err)
		}
		return fmt.Errorf("%w; rolled back", cause)
	}
	if err := gate(change.Files); err != nil {
		return restore(fmt.Errorf("gate failed: %w", err))
	}
	if _, err := git(ctx, r.Main, append([]string{"add", "--all", "--"}, change.Files...)...); err != nil {
		return restore(err)
	}
	// The gate has just run; hooks would only repeat it.
	if _, err := git(ctx, r.Main, "commit", "--quiet", "--no-verify", "-m", message); err != nil {
		return restore(err)
	}
	if _, err := git(ctx, r.Main, "push", "--quiet", "--no-verify", remote, "HEAD:refs/heads/"+remoteBranch); err != nil {
		return restore(fmt.Errorf("push to %s failed: %w", strings.TrimSpace(upstream), err))
	}
	return nil
}

// Landing describes the dev land in progress in the main checkout.
type Landing struct {
	Owner     string    `json:"owner"`
	PID       int       `json:"pid"`
	Worktree  string    `json:"worktree"`
	Message   string    `json:"message"`
	Files     []string  `json:"files"`
	StartedAt time.Time `json:"started_at"`
	// Stale is set by CurrentLanding when no process holds the landing lock,
	// i.e. the lander died before removing its marker.
	Stale bool `json:"stale,omitempty"`
}

func (r *Repository) landingPath() string {
	return filepath.Join(r.Main, ".git", "lindm-landing.current")
}

func (r *Repository) writeLanding(change Change, message string) error {
	data, err := json.MarshalIndent(Landing{Owner: owner(change.Source), PID: os.Getpid(), Worktree: change.Source, Message: message, Files: change.Files, StartedAt: time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	temporary := r.landingPath() + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, r.landingPath())
}

// CurrentLanding returns the landing in progress, or nil when there is none.
func (r *Repository) CurrentLanding() (*Landing, error) {
	data, err := os.ReadFile(r.landingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	landing := new(Landing)
	if err := json.Unmarshal(data, landing); err != nil {
		return nil, fmt.Errorf("landing marker %s: %w", r.landingPath(), err)
	}
	_, held, err := LockHolder(r.LockPath())
	if err != nil {
		return nil, err
	}
	landing.Stale = !held
	return landing, nil
}

// String renders the landing for status output.
func (l *Landing) String() string {
	state := "in progress"
	if l.Stale {
		state = "STALE marker (no lander holds the lock)"
	}
	return fmt.Sprintf("landing %s since %s by %s (pid %d) from %s: %q, %d files: %s", state, l.StartedAt.Format(time.RFC3339), l.Owner, l.PID, l.Worktree, l.Message, len(l.Files), strings.Join(l.Files, " "))
}

// LockHolder reports whether a process holds the flock on path, naming the
// actual holders from /proc/locks and, when present, the record they wrote
// (diagnostic only: a holder that never rewrites it leaves an older record).
func LockHolder(path string) (holder string, held bool, err error) {
	holders, err := LockHolders(path)
	if err != nil {
		return "", false, err
	}
	var names []string
	for _, h := range holders {
		if !h.Waiting {
			names = append(names, fmt.Sprintf("pid %d (%s)", h.PID, h.Command))
		}
	}
	if len(names) == 0 {
		return "", false, nil
	}
	holder = strings.Join(names, ", ")
	if recorded, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(recorded)) != 0 {
		holder += "; record: " + strings.TrimSpace(string(recorded))
	}
	return holder, true, nil
}
