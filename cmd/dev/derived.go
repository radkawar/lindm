package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"lindm/internal/devlab/worktree"
)

// derivedRoots returns the output directories that make generate-code (buf
// generate, sqlc generate) writes, as declared by buf.gen.yaml and sqlc.yaml
// in each checkout: the shared one and the landing worktree, which may add a
// root. A checkout without a config declares nothing.
func derivedRoots(checkouts ...string) ([]string, error) {
	var roots []string
	add := func(config, out string) error {
		if out == "" {
			return nil // an entry without this generator's output
		}
		root := path.Clean(filepath.ToSlash(out))
		if root == "." || path.IsAbs(root) || root == ".." || strings.HasPrefix(root, "../") {
			return fmt.Errorf("%s: output %q is not a directory inside the repository", config, out)
		}
		if !slices.Contains(roots, root) {
			roots = append(roots, root)
		}
		return nil
	}
	for _, checkout := range checkouts {
		var buf struct {
			Plugins []struct {
				Out string `yaml:"out"`
			} `yaml:"plugins"`
		}
		config := filepath.Join(checkout, "buf.gen.yaml")
		if err := readYAML(config, &buf); err != nil {
			return nil, err
		}
		for _, plugin := range buf.Plugins {
			if err := add(config, plugin.Out); err != nil {
				return nil, err
			}
		}
		var sqlc struct {
			SQL []struct {
				Gen struct {
					Go struct {
						Out string `yaml:"out"`
					} `yaml:"go"`
				} `yaml:"gen"`
			} `yaml:"sql"`
		}
		config = filepath.Join(checkout, "sqlc.yaml")
		if err := readYAML(config, &sqlc); err != nil {
			return nil, err
		}
		for _, target := range sqlc.SQL {
			if err := add(config, target.Gen.Go.Out); err != nil {
				return nil, err
			}
		}
	}
	slices.Sort(roots)
	return roots, nil
}

// readYAML decodes file into target; a missing file leaves target empty.
func readYAML(file string, target any) error {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parse %s: %w", file, err)
	}
	return nil
}

// maxListedDerived bounds the regenerated paths a landing prints.
const maxListedDerived = 20

// regenerate runs make generate-code in the shared checkout, under the landing
// lock with the change applied, and returns the derived files it changed:
// this landing's generated output, composed with every landing before it.
func regenerate(ctx context.Context, repo *worktree.Repository, change worktree.Change) ([]string, error) {
	if len(change.Derivation.Roots) == 0 {
		return nil, nil
	}
	fmt.Println("land: regenerating buf/sqlc output (make generate-code)")
	if err := stream(ctx, repo.Main, nil, "make", "--no-print-directory", "generate-code"); err != nil {
		return nil, fmt.Errorf("regenerate derived files: %w", err)
	}
	regenerated, err := repo.DerivedChanges(ctx, change)
	if err != nil {
		return nil, err
	}
	listed := regenerated[:min(len(regenerated), maxListedDerived)]
	report := fmt.Sprintf("land: regeneration changed %d generated files (the worktree changed %d)", len(regenerated), len(change.Derived))
	if len(listed) != 0 {
		report += ": " + strings.Join(listed, " ")
	}
	if extra := len(regenerated) - len(listed); extra > 0 {
		report += fmt.Sprintf(" … and %d more", extra)
	}
	fmt.Println(report)
	return regenerated, nil
}
