package vmlab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// InstallProjectionBoundaryEvidence distinguishes native directory traversal
// from root-aware final-file symlink handling. Every source is fixture-owned,
// including the intentionally different source outside the native --root.
// This is not qualification of a production snapshotter or sandbox.
type InstallProjectionBoundaryEvidence struct {
	RawDirectoryLinks       []InstallProjectionLink `json:"raw_directory_links"`
	RewrittenDirectoryLinks []InstallProjectionLink `json:"rewritten_directory_links"`
	AbsoluteFileLinks       []InstallProjectionLink `json:"absolute_file_links"`
}

func checkProjectionRootBoundary(ctx context.Context, binary, fixture string) (*InstallProjectionBoundaryEvidence, error) {
	boundary := filepath.Join(fixture, "root-boundary")
	root := filepath.Join(boundary, "staged")
	outside := filepath.Join(boundary, "source-units")
	shadow := root + outside
	vendor := filepath.Join(root, "usr/lib/systemd/system")
	units := filepath.Join(root, "etc/systemd/system")
	const primary = "projection-boundary.service"
	const alias = "projection-boundary-alias.service"
	for _, directory := range []string{outside, shadow, filepath.Dir(vendor), units} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return nil, err
		}
	}
	for _, source := range []struct{ directory, target string }{
		{outside, "projection-outside.target"},
		{shadow, "projection-staged.target"},
	} {
		definition := "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=" + source.target + "\nAlias=" + alias + "\n"
		if err := os.WriteFile(filepath.Join(source.directory, primary), []byte(definition), 0600); err != nil {
			return nil, err
		}
	}
	if err := os.Symlink(outside, vendor); err != nil {
		return nil, err
	}
	enable := func() ([]InstallProjectionLink, error) {
		if _, err := projectionCommand(ctx, binary, "--system", "--root="+root, "--no-reload", "--no-ask-password", "--no-pager", "enable", "--", primary); err != nil {
			return nil, err
		}
		return observeProjectionLinks(units)
	}
	disable := func() error {
		_, err := projectionCommand(ctx, binary, "--system", "--root="+root, "--no-reload", "--no-ask-password", "--no-pager", "disable", "--", primary)
		return err
	}
	want := func(target, source string) []InstallProjectionLink {
		links := []InstallProjectionLink{
			{Path: alias, Target: source},
			{Path: target + ".wants/" + primary, Target: source},
		}
		slices.SortFunc(links, func(a, b InstallProjectionLink) int { return strings.Compare(a.Path, b.Path) })
		return links
	}
	logicalSource := "/usr/lib/systemd/system/" + primary
	evidence := &InstallProjectionBoundaryEvidence{}
	var err error
	evidence.RawDirectoryLinks, err = enable()
	if err != nil {
		return nil, err
	}
	if !slices.Equal(evidence.RawDirectoryLinks, want("projection-outside.target", logicalSource)) {
		return nil, fmt.Errorf("raw absolute directory link did not demonstrate the expected native root escape: %v", evidence.RawDirectoryLinks)
	}
	if err := disable(); err != nil {
		return nil, err
	}
	// Only the directory link is rewritten. Its logical path and the native
	// install source path remain unchanged; the actual read stays in the copy.
	relative, err := filepath.Rel(filepath.Dir(vendor), shadow)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(vendor); err != nil {
		return nil, err
	}
	if err := os.Symlink(relative, vendor); err != nil {
		return nil, err
	}
	evidence.RewrittenDirectoryLinks, err = enable()
	if err != nil {
		return nil, err
	}
	if !slices.Equal(evidence.RewrittenDirectoryLinks, want("projection-staged.target", logicalSource)) {
		return nil, fmt.Errorf("rewritten directory link did not confine the native definition read while preserving install paths: %v", evidence.RewrittenDirectoryLinks)
	}
	if err := disable(); err != nil {
		return nil, err
	}
	// In contrast, a final file symlink is consumed by native root-aware unit
	// lookup. Keep its absolute target, including its same-name linked-unit
	// identity, rather than applying the directory rewrite to every symlink.
	linked := filepath.Join(boundary, "linked-source")
	for _, source := range []struct{ directory, target string }{
		{linked, "projection-file-outside.target"},
		{root + linked, "projection-file-staged.target"},
	} {
		if err := os.MkdirAll(source.directory, 0700); err != nil {
			return nil, err
		}
		definition := "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=" + source.target + "\nAlias=" + alias + "\n"
		if err := os.WriteFile(filepath.Join(source.directory, primary), []byte(definition), 0600); err != nil {
			return nil, err
		}
	}
	if err := os.Remove(filepath.Join(shadow, primary)); err != nil {
		return nil, err
	}
	if err := os.Symlink(filepath.Join(linked, primary), filepath.Join(shadow, primary)); err != nil {
		return nil, err
	}
	evidence.AbsoluteFileLinks, err = enable()
	if err != nil {
		return nil, err
	}
	expected := want("projection-file-staged.target", filepath.Join(linked, primary))
	// Native enable also materializes the linked unit in the configuration
	// directory when its resolved definition is outside the lookup paths.
	expected = append(expected, InstallProjectionLink{Path: primary, Target: filepath.Join(linked, primary)})
	slices.SortFunc(expected, func(a, b InstallProjectionLink) int { return strings.Compare(a.Path, b.Path) })
	if !slices.Equal(evidence.AbsoluteFileLinks, expected) {
		return nil, fmt.Errorf("absolute file link did not retain native root-aware linked-unit semantics: %v", evidence.AbsoluteFileLinks)
	}
	return evidence, nil
}
