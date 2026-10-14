// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/vmlab"
)

func runVMServer(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "verified Ubuntu 24.04 image manifest")
	repository := flags.String("repo", ".", "source checkout with built embedded console")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	work := flags.String("work-dir", "", "existing private VM working parent")
	record := flags.String("record", "", "write nonsecret evidence to a new private file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE is required; positional arguments are not accepted")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	result, err := vmlab.ServerVM(ctx, manifest, vmlab.VMServerOptions{Repository: *repository, CacheDir: *cache, WorkDir: *work})
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
