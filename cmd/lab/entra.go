// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/devlab"
)

func runAuthCheckEntra(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("auth check-entra", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("repo", ".", "checkout owning protected development trust and PostgreSQL fixture")
	binary := flags.String("lindmd", "", "prebuilt real lindmd executable; isolated dynamic listeners")
	cleanup := flags.String("cleanup-prefix", "", "delete only the complete lindm-entra-check-UUID test-owned namespace")
	record := flags.String("record", "", "exclusively create private nonsecret JSON evidence, including failure and cleanup")
	unsandboxed := flags.Bool("chromium-no-sandbox", false, "explicitly authorize an ephemeral no-sandbox lab browser; never a production/browser default")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*binary == "") == (*cleanup == "") {
		return errors.New("auth check-entra requires exactly one of -lindmd FILE or -cleanup-prefix lindm-entra-check-UUID; optional -repo DIR -record NEW_FILE")
	}
	result, err := devlab.CheckEntraAuthorization(ctx, *root, *binary, *cleanup, *unsandboxed)
	return errors.Join(err, writeLabEvidence(stdout, *record, result))
}
