package worktree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Derivation names what a landing derives in the main checkout instead of
// applying the worktree's bytes, so landings that each change a shared
// derived file compose instead of the later one's patch failing to apply.
type Derivation struct {
	// Roots are generator output directories. The worktree's output there is
	// left out of the patch; the gate regenerates it from main plus the
	// change.
	Roots []string
	// Merge holds files merged structurally rather than patched: each is
	// called with the main checkout's current content and the worktree's
	// base and own versions (nil when absent) and returns the merged content.
	Merge map[string]func(current, base, theirs []byte) ([]byte, error)
	// Blank, when set, empties the generated regions of the Markdown file at the
	// repository-relative name (returning other files unchanged). The patch is
	// computed between blanked base and worktree files and applied to
	// blanked main files, so it carries only hand-written changes; the gate
	// regenerates the regions.
	Blank func(name string, content []byte) []byte
}

// blob reads an object (rev:path, or :path for the snapshot index).
func blob(git gitFunc, object string) ([]byte, error) {
	content, err := git("cat-file", "blob", object)
	return []byte(content), err
}

// blankIndexed replaces name's entry in the snapshot index with its blanked
// content when blanking changes it.
func blankIndexed(git gitFunc, name string, blank func(name string, content []byte) []byte) error {
	content, err := blob(git, ":"+name)
	if err != nil {
		return err
	}
	blanked := blank(name, content)
	if bytes.Equal(blanked, content) {
		return nil
	}
	entry, err := git("ls-files", "--stage", "-z", "--", ":(literal)"+name)
	if err != nil {
		return err
	}
	mode, _, ok := strings.Cut(entry, " ")
	if !ok {
		return fmt.Errorf("snapshot index lacks %s", name)
	}
	object, err := hashObject(git, blanked)
	if err != nil {
		return err
	}
	_, err = git("update-index", "--cacheinfo", mode+","+object+","+name)
	return err
}

// hashObject stores content as a blob and returns its id.
func hashObject(git gitFunc, content []byte) (string, error) {
	scratch, err := os.CreateTemp("", "lindm-blank-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(scratch.Name()) }()
	if _, err := scratch.Write(content); err != nil {
		return "", errors.Join(err, scratch.Close())
	}
	if err := scratch.Close(); err != nil {
		return "", err
	}
	object, err := git("hash-object", "-w", "--no-filters", scratch.Name())
	return strings.TrimSpace(object), err
}

// blankedTree writes a tree equal to base with names' generated regions
// blanked, in a scratch index of the worktree at path.
func blankedTree(ctx context.Context, path, base string, names []string, blank func(name string, content []byte) []byte) (string, error) {
	scratch, err := os.MkdirTemp("", "lindm-base-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(scratch, "index")}
	run := func(args ...string) (string, error) { return gitWith(ctx, path, env, nil, args...) }
	if _, err := run("read-tree", base); err != nil {
		return "", err
	}
	for _, name := range names {
		if err := blankIndexed(run, name, blank); err != nil {
			return "", err
		}
	}
	tree, err := run("write-tree")
	return strings.TrimSpace(tree), err
}

// blankFiles blanks, in the main checkout's working tree, each of names whose
// content blanking changes, and returns those.
func (r *Repository) blankFiles(names []string, blank func(name string, content []byte) []byte) ([]string, error) {
	if blank == nil {
		return nil, nil
	}
	var blanked []string
	for _, name := range names {
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		path := filepath.Join(r.Main, name)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return blanked, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return blanked, err
		}
		if next := blank(name, content); !bytes.Equal(next, content) {
			if err := os.WriteFile(path, next, info.Mode().Perm()); err != nil {
				return blanked, err
			}
			blanked = append(blanked, name)
		}
	}
	return blanked, nil
}

// uncommitted lists the main checkout's tracked paths that differ from its
// index and its untracked non-ignored paths.
func (r *Repository) uncommitted(ctx context.Context) (tracked, untracked []string, err error) {
	status, err := git(ctx, r.Main, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
	if err != nil {
		return nil, nil, err
	}
	for record := range strings.SplitSeq(status, "\x00") {
		if len(record) <= 3 {
			continue
		}
		if record[:2] == "??" {
			untracked = append(untracked, record[3:])
		} else {
			tracked = append(tracked, record[3:])
		}
	}
	return tracked, untracked, nil
}

// onlyGenerated reports whether the main checkout's copy of name differs from
// rev only inside generated regions.
func (r *Repository) onlyGenerated(ctx context.Context, name, rev string, blank func(name string, content []byte) []byte) (bool, error) {
	if blank == nil || !strings.HasSuffix(name, ".md") {
		return false, nil
	}
	current, err := os.ReadFile(filepath.Join(r.Main, name))
	if err != nil {
		return false, nil // deleted or unreadable: not a regeneration
	}
	prior, err := git(ctx, r.Main, "cat-file", "blob", rev+":"+name)
	if err != nil {
		return false, nil // not in rev
	}
	return bytes.Equal(blank(name, current), blank(name, []byte(prior))), nil
}

// landed lists every path the landing changed in the main checkout after the
// gate: the patch's files, regenerated output under the roots, merged files
// and documents whose generated regions were regenerated. Any other change
// fails the landing, the gate must not edit what it checks, and is discarded.
func (r *Repository) landed(ctx context.Context, change Change) ([]string, error) {
	tracked, untracked, err := r.uncommitted(ctx)
	if err != nil {
		return nil, err
	}
	var files, stray []string
	var failures []error
	for _, name := range slices.Concat(tracked, untracked) {
		switch {
		case slices.Contains(change.Files, name), underAny(name, change.Derivation.Roots), change.Derivation.Merge[name] != nil:
			files = append(files, name)
		default:
			generated, err := r.onlyGenerated(ctx, name, "HEAD", change.Derivation.Blank)
			if err != nil {
				return nil, err
			}
			switch {
			case generated:
				files = append(files, name)
			case slices.Contains(untracked, name):
				stray = append(stray, name)
				failures = append(failures, os.RemoveAll(filepath.Join(r.Main, name)))
			default:
				stray = append(stray, name)
				_, checkoutErr := git(ctx, r.Main, "--literal-pathspecs", "checkout", "--quiet", "HEAD", "--", name)
				failures = append(failures, checkoutErr)
			}
		}
	}
	if len(stray) != 0 {
		return nil, errors.Join(append([]error{strayError(stray)}, failures...)...)
	}
	return files, nil
}

// restoreDerivedFiles returns the merged files and the documents whose
// generated regions alone differ to rev, which must be HEAD with a matching
// index; it runs after the patch is reversed.
func (r *Repository) restoreDerivedFiles(ctx context.Context, change Change, rev string) error {
	tracked, untracked, err := r.uncommitted(ctx)
	if err != nil {
		return err
	}
	var restore []string
	var failures []error
	for _, name := range untracked {
		if change.Derivation.Merge[name] != nil {
			failures = append(failures, os.Remove(filepath.Join(r.Main, name)))
		}
	}
	for _, name := range tracked {
		generated, err := r.onlyGenerated(ctx, name, rev, change.Derivation.Blank)
		if err != nil {
			return err
		}
		if generated || change.Derivation.Merge[name] != nil {
			restore = append(restore, name)
		}
	}
	if len(restore) != 0 {
		_, err := gitWith(ctx, r.Main, nil, []byte(strings.Join(restore, "\x00")), "--literal-pathspecs", "checkout", "--quiet", rev, "--pathspec-from-file=-", "--pathspec-file-nul")
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// merge writes the structural merge of a worktree's change into the main
// checkout's copy of the file.
func (r *Repository) merge(change MergedFile, merge func(current, base, theirs []byte) ([]byte, error)) error {
	if merge == nil {
		return fmt.Errorf("no merge for %s", change.Path)
	}
	path := filepath.Join(r.Main, change.Path)
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	merged, err := merge(current, change.Base, change.Theirs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, merged, 0o644)
}

func mergedPaths(change Change) []string {
	paths := make([]string, 0, len(change.Merged))
	for _, merged := range change.Merged {
		paths = append(paths, merged.Path)
	}
	return paths
}
