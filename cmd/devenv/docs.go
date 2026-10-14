// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"lindm/internal/gendoc"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

// generateDocs rewrites (or with -check verifies) every Markdown block
// generated from the platform registry and the lab matrix ledger.
func generateDocs(args []string) error {
	flags := flag.NewFlagSet("generate-docs", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	check := flags.Bool("check", false, "fail if any generated block differs instead of rewriting it")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("generate-docs takes no positional arguments")
	}
	blocks, err := docBlocks(*root)
	if err != nil {
		return err
	}
	stale, err := gendoc.Sync(*root, blocks, !*check)
	if err != nil {
		return err
	}
	if *check && len(stale) > 0 {
		return fmt.Errorf("generated documentation is stale; run make generate: %s", strings.Join(stale, ", "))
	}
	for _, file := range stale {
		if _, err := fmt.Fprintln(os.Stdout, "regenerated", file); err != nil {
			return err
		}
	}
	return nil
}

// docBlocks returns every Markdown block generate-docs maintains under root.
func docBlocks(root string) ([]gendoc.Block, error) {
	blocks, err := platform.DocBlocks()
	if err != nil {
		return nil, err
	}
	matrix, err := labmatrix.DocBlock(root)
	if err != nil {
		return nil, err
	}
	return append(blocks, matrix), nil
}
