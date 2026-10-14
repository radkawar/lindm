// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
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

// ledgerFile is the lab matrix ledger, merged record by record.
const ledgerFile = "lab/ledger.json"

// maxLedgerBytes bounds a ledger read for merging.
const maxLedgerBytes = 16 << 20

// mergeLedger merges a worktree's change to the matrix ledger structurally,
// so landings that each record entries compose: the entries theirs adds to
// base are appended to current once and the entries theirs removes from base
// are removed. Entries are compared as JSON records, independent of
// formatting; validating them against the schema is the gate's (generate-docs
// -check loads the ledger strictly). It needs no product packages, so a
// landing that breaks the lab schema still merges and rolls back.
func mergeLedger(current, base, theirs []byte) ([]byte, error) {
	parse := func(name string, data []byte) ([]string, error) {
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, nil
		}
		if len(data) > maxLedgerBytes {
			return nil, fmt.Errorf("%s ledger exceeds %d bytes", name, maxLedgerBytes)
		}
		var ledger struct {
			Entries []json.RawMessage `json:"entries"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&ledger); err != nil {
			return nil, fmt.Errorf("decode %s ledger: %w", name, err)
		}
		entries := make([]string, 0, len(ledger.Entries))
		for _, entry := range ledger.Entries {
			var compact bytes.Buffer
			if err := json.Compact(&compact, entry); err != nil {
				return nil, fmt.Errorf("decode %s ledger: %w", name, err)
			}
			entries = append(entries, compact.String())
		}
		return entries, nil
	}
	merged, err := parse("current", current)
	if err != nil {
		return nil, err
	}
	before, err := parse("base", base)
	if err != nil {
		return nil, err
	}
	after, err := parse("their", theirs)
	if err != nil {
		return nil, err
	}
	// take removes one occurrence of entry, reporting whether there was one.
	take := func(entries *[]string, entry string) bool {
		if i := slices.Index(*entries, entry); i >= 0 {
			*entries = slices.Delete(*entries, i, i+1)
			return true
		}
		return false
	}
	removed := slices.Clone(before)
	var added []string
	for _, entry := range after {
		if !take(&removed, entry) {
			added = append(added, entry)
		}
	}
	for _, entry := range removed {
		take(&merged, entry)
	}
	for _, entry := range added {
		if !slices.Contains(merged, entry) {
			merged = append(merged, entry)
		}
	}
	// The layout labmatrix.Marshal writes: two-space indented JSON.
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(`{"entries":[`+strings.Join(merged, ",")+`]}`), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
