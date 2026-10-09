package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/vmlab"
)

func runInstallProjection(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("native check-install-projection", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workDir := flags.String("work-dir", "", "protected existing parent for an owned disposable fixture (default: OS temporary directory)")
	record := flags.String("record", "", "write successful isolated native evidence to a new private JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("native check-install-projection accepts flags only")
	}
	result, err := vmlab.CheckInstallProjection(ctx, *workDir)
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
