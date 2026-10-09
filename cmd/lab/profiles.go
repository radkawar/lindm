package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/devlab"
)

func runProfileCatalog(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("profiles check-catalog", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("repo", ".", "checkout owning the protected development fixture")
	binary := flags.String("lindmd", "", "prebuilt server binary for the isolated real-process fixture")
	record := flags.String("record", "", "write successful catalog evidence to a new private JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binary == "" || flags.NArg() != 0 {
		return errors.New("profiles check-catalog requires -lindmd FILE; positional arguments are not accepted")
	}
	result, err := devlab.CheckProfileCatalog(ctx, *root, *binary)
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
