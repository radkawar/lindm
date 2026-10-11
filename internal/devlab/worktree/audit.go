package worktree

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Verdict classifies a worktree's work against Trunk.
type Verdict string

// Audit verdicts. Landed and Snapshot trees hold nothing main lacks.
const (
	Landed       Verdict = "LANDED"       // every changed file's content is in main
	Partial      Verdict = "PARTIAL"      // some changed files are not in main
	Unlanded     Verdict = "UNLANDED"     // no changed file is in main
	Snapshot     Verdict = "SNAPSHOT"     // no change against its base at all
	Missing      Verdict = "MISSING"      // registered, directory gone
	Unregistered Verdict = "UNREGISTERED" // not a worktree of this repository
)

// Disposable reports whether removing a tree with this verdict loses no work.
func (v Verdict) Disposable() bool { return v == Landed || v == Snapshot }

// Audit is one worktree's landing status.
type Audit struct {
	Path     string   `json:"path"`
	Head     string   `json:"head,omitempty"`
	Base     string   `json:"base,omitempty"`
	Verdict  Verdict  `json:"verdict"`
	Owner    string   `json:"owner"`
	Changed  int      `json:"changed_files"`
	Unlanded []string `json:"unlanded_files,omitempty"`
	Note     string   `json:"note,omitempty"`
	// Active says why the owner is evidently still working in the tree;
	// such PARTIAL/UNLANDED trees are work in progress, not stranded work.
	Active string `json:"active,omitempty"`
}

// maxListedFiles bounds the unlanded paths recorded per tree.
const maxListedFiles = 200

var ownerNoise = regexp.MustCompile(`^(lindm[-_.]?)|([-_.](\d{8}|\d{8}T\d+Z?|snap\d+|s\d+|r\d+|pin\d+|land|base|pristine|stable)$)`)

// owner infers the responsible agent from the tree's directory name, which
// agents choose after themselves or their task (lindm-<task>, <Agent>,
// <Agent>-land). It is a routing hint, never authority.
func owner(path string) string {
	name := filepath.Base(path)
	for {
		trimmed := ownerNoise.ReplaceAllString(name, "")
		if trimmed == name || trimmed == "" {
			return name
		}
		name = trimmed
	}
}

// AuditPath classifies the tree at path. A file is landed when main holds the
// tree's exact content for it (or also lacks a deleted file), held it at any
// commit since the tree's base (landed, then superseded), or when the tree's
// change to it reverse-applies to main, i.e. main already contains every hunk. Copy-landed work is therefore recognized without shared commits.
func (r *Repository) AuditPath(ctx context.Context, path string) Audit {
	audit := Audit{Path: path, Owner: owner(path)}
	entry, ok, err := r.registered(ctx, path)
	switch {
	case err != nil:
		audit.Verdict, audit.Note = Unregistered, err.Error()
		return audit
	case !ok:
		audit.Verdict, audit.Note = Unregistered, unregisteredKind(path)
		return audit
	case entry.Missing:
		audit.Verdict, audit.Head = Missing, entry.Head
		return audit
	}
	audit.Head = entry.Head
	if audit.Active, err = r.activity(ctx, entry.Path); err != nil {
		audit.Note = "activity unknown: " + err.Error()
	}
	if err := r.snapshot(ctx, entry.Path, nil, func(base string, git gitFunc, scope []string) error {
		audit.Base = base
		return r.classify(ctx, &audit, git, scope)
	}); err != nil {
		audit.Verdict, audit.Note = Unlanded, "audit failed, treated as unlanded: "+err.Error()
	}
	return audit
}

// ActiveWindow is how recently a file must have changed for the audit to
// treat a tree as being worked on by its live owner.
const ActiveWindow = 2 * time.Hour

// activity explains why the tree's owner is evidently still working in it: a
// live process uses it, or a file outside node_modules changed within
// ActiveWindow. It returns "" for an idle tree.
func (r *Repository) activity(ctx context.Context, path string) (string, error) {
	if user, err := r.user(ctx, path); err != nil || user != "" {
		return user, err
	}
	var newest time.Time
	err := filepath.WalkDir(path, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if age := time.Since(newest); age < ActiveWindow {
		return "modified " + age.Round(time.Minute).String() + " ago", nil
	}
	return "", nil
}

func unregisteredKind(path string) string {
	info, err := os.Lstat(filepath.Join(path, ".git"))
	switch {
	case err != nil:
		return "no .git: plain directory copy"
	case info.IsDir():
		return "separate clone"
	default:
		return "worktree of another repository"
	}
}

type changed struct {
	path, blob string // blob is empty for a deletion
}

func (r *Repository) classify(ctx context.Context, audit *Audit, git gitFunc, scope []string) error {
	raw, err := git(append([]string{"diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", audit.Base}, scope...)...)
	if err != nil {
		return err
	}
	var files []changed
	fields := strings.Split(raw, "\x00")
	for i := 0; i+1 < len(fields); i += 2 {
		meta := strings.Fields(fields[i])
		if len(meta) != 5 {
			return fmt.Errorf("unexpected raw diff record %q", fields[i])
		}
		blob := meta[3]
		if strings.Trim(blob, "0") == "" {
			blob = ""
		}
		files = append(files, changed{path: fields[i+1], blob: blob})
	}
	audit.Changed = len(files)
	if len(files) == 0 {
		audit.Verdict = Snapshot
		return nil
	}
	trunk, err := r.trunkBlobs(ctx, files)
	if err != nil {
		return err
	}
	history, err := r.historicalBlobs(ctx, audit.Base, files)
	if err != nil {
		return err
	}
	var differing []string
	for _, file := range files {
		// Main holding this exact content now, or at any commit since the
		// base, means the work landed (possibly superseded since).
		if trunk[file.path] != file.blob && !history[file.path][file.blob] {
			differing = append(differing, file.path)
		}
	}
	unlanded, err := r.notInTrunk(ctx, git, audit.Base, differing, trunk, history)
	if err != nil {
		return err
	}
	switch {
	case len(unlanded) == 0:
		audit.Verdict = Landed
	case len(unlanded) == len(files):
		audit.Verdict = Unlanded
	default:
		audit.Verdict = Partial
	}
	if len(unlanded) > maxListedFiles {
		audit.Note = fmt.Sprintf("%d unlanded files; first %d listed", len(unlanded), maxListedFiles)
		unlanded = unlanded[:maxListedFiles]
	}
	audit.Unlanded = unlanded
	return nil
}

// trunkBlobs maps each changed path to its blob in Trunk; absent paths are "".
func (r *Repository) trunkBlobs(ctx context.Context, files []changed) (map[string]string, error) {
	blobs := make(map[string]string, len(files))
	for start := 0; start < len(files); start += 256 {
		args := []string{"ls-tree", "-z", "--full-tree", Trunk, "--"}
		for _, file := range files[start:min(start+256, len(files))] {
			args = append(args, file.path)
		}
		out, err := git(ctx, r.Main, args...)
		if err != nil {
			return nil, err
		}
		for record := range strings.SplitSeq(out, "\x00") {
			meta, path, ok := strings.Cut(record, "\t")
			if fields := strings.Fields(meta); ok && len(fields) == 3 {
				blobs[path] = fields[2]
			}
		}
	}
	return blobs, nil
}

// historicalBlobs maps each changed path to every blob (including "" for a
// deletion) that Trunk's commits since base gave it.
func (r *Repository) historicalBlobs(ctx context.Context, base string, files []changed) (map[string]map[string]bool, error) {
	blobs := make(map[string]map[string]bool, len(files))
	for start := 0; start < len(files); start += 256 {
		args := []string{"log", "--raw", "-z", "--no-abbrev", "--no-renames", "--format=", base + ".." + Trunk, "--"}
		for _, file := range files[start:min(start+256, len(files))] {
			args = append(args, file.path)
		}
		out, err := git(ctx, r.Main, args...)
		if err != nil {
			return nil, err
		}
		tokens := strings.Split(out, "\x00")
		for i := 0; i+1 < len(tokens); i++ {
			meta := strings.Fields(strings.TrimSpace(tokens[i]))
			if len(meta) != 5 || !strings.HasPrefix(meta[0], ":") {
				continue
			}
			blob := meta[3]
			if strings.Trim(blob, "0") == "" {
				blob = ""
			}
			path := tokens[i+1]
			if blobs[path] == nil {
				blobs[path] = map[string]bool{}
			}
			blobs[path][blob] = true
			i++
		}
	}
	return blobs, nil
}

// notInTrunk returns the paths whose change from base main does not hold. A
// change is held when it reverse-applies to Trunk's tree (checked in a scratch
// index so no checkout is touched) or, failing that because main has since
// moved the surrounding context, when every significant line it adds appears
// in main's current or historical content for the path (and, for a pure
// removal, no removed line survives in main). Snapshots of a shared tree taken
// mid-edit are thereby recognized once their lines landed.
func (r *Repository) notInTrunk(ctx context.Context, git gitFunc, base string, paths []string, trunk map[string]string, history map[string]map[string]bool) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	scratch, err := os.MkdirTemp("", "lindm-audit-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(scratch, "index")}
	if _, err := gitWith(ctx, r.Main, env, nil, "read-tree", Trunk); err != nil {
		return nil, err
	}
	var unlanded []string
	for _, path := range paths {
		patch, err := git("diff", "--cached", "--binary", "--full-index", "--no-renames", base, "--", path)
		if err != nil {
			return nil, err
		}
		if _, err := gitWith(ctx, r.Main, env, []byte(patch), "apply", "--cached", "--check", "--reverse", "-"); err == nil {
			continue
		}
		held, err := r.linesHeld(ctx, patch, trunk[path], history[path])
		if err != nil {
			return nil, err
		}
		if !held {
			unlanded = append(unlanded, path)
		}
	}
	return unlanded, nil
}

// maxHistoricalBlobs bounds the historical versions read per path.
const maxHistoricalBlobs = 32

func (r *Repository) linesHeld(ctx context.Context, patch, current string, history map[string]bool) (bool, error) {
	if strings.Contains(patch, "\nGIT binary patch\n") {
		return false, nil
	}
	var added, removed []string
	for line := range strings.Lines(patch) {
		switch {
		case strings.HasPrefix(line, "+++ "), strings.HasPrefix(line, "--- "):
		case strings.HasPrefix(line, "+"):
			if text := significant(line[1:]); text != "" {
				added = append(added, text)
			}
		case strings.HasPrefix(line, "-"):
			if text := significant(line[1:]); text != "" {
				removed = append(removed, text)
			}
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return false, nil
	}
	lines := map[string]bool{}
	readBlob := func(blob string) error {
		if blob == "" {
			return nil
		}
		content, err := git(ctx, r.Main, "cat-file", "blob", blob)
		if err != nil {
			return err
		}
		for line := range strings.Lines(content) {
			lines[significant(line)] = true
		}
		return nil
	}
	if err := readBlob(current); err != nil {
		return false, err
	}
	if len(added) == 0 {
		for _, line := range removed {
			if lines[line] {
				return false, nil
			}
		}
		return true, nil
	}
	count := 0
	for blob := range history {
		if count == maxHistoricalBlobs {
			break
		}
		if err := readBlob(blob); err != nil {
			return false, err
		}
		count++
	}
	for _, line := range added {
		if !lines[line] {
			return false, nil
		}
	}
	return true, nil
}

// significant normalizes a line for containment, discarding lines too short
// or generic (braces, blank) to evidence anything.
func significant(line string) string {
	text := strings.TrimSpace(line)
	if len(text) < 4 {
		return ""
	}
	return text
}

// AuditAll audits every registered worktree except the main checkout, then any
// extra paths that are not registered worktrees.
func (r *Repository) AuditAll(ctx context.Context, extra []string, report func(Audit) error) error {
	entries, err := r.List(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[canonical(entry.Path)] = true
		if err := report(r.AuditPath(ctx, entry.Path)); err != nil {
			return err
		}
	}
	for _, path := range extra {
		if seen[canonical(path)] || canonical(path) == canonical(r.Main) {
			continue
		}
		seen[canonical(path)] = true
		if err := report(r.AuditPath(ctx, path)); err != nil {
			return err
		}
	}
	return nil
}
