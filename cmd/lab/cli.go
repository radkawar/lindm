package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/devlab"
)

func runCLICheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("cli check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "checkout owning the running Keycloak development fixture")
	record := flags.String("record", "", "write nonsecret qualification evidence to a new private JSON file")
	binary := flags.String("lindmd", "", "prebuilt server for an owned isolated database/server instead of the running server")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("cli check accepts only -root DIR, -lindmd FILE and -record NEW_FILE")
	}
	result, err := devlab.CheckCLI(ctx, *root, *binary)
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
