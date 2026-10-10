package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/deploylab"
)

func runServerCompose(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("server compose", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "checkout with built embedded console and pinned Go dependencies")
	record := flags.String("record", "", "new nonsecret JSON evidence file (also printed to stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("server compose accepts only -repo DIR and -record FILE")
	}
	result, runErr := deploylab.RunCompose(ctx, *repo)
	return errors.Join(runErr, writeLabEvidence(stdout, *record, result))
}
