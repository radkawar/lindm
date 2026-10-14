// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"lindm/internal/loadlab"
)

// runHA is the maintained replicated-topology qualification lane. It owns every
// container, database and process it starts; there is no endpoint override.
func runHA(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ha", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "initialized development fixture checkout providing read-only trust material")
	binary := flags.String("lindmd", "", "prebuilt release N lindmd executable")
	upgrade := flags.String("upgrade-lindmd", "", "prebuilt release N+1 lindmd executable for the rolling upgrade")
	devices := flags.Int("devices", 24, "simulated devices (4..256)")
	phase := flags.Duration("phase-duration", time.Minute, "observation interval per fault phase (20s..30m)")
	seed := flags.Uint64("seed", 1, "deterministic jitter seed")
	record := flags.String("record", "", "new private nonsecret JSON evidence file, including failed runs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binary == "" || *upgrade == "" || flags.NArg() != 0 {
		return errors.New("lab ha requires -lindmd FILE and -upgrade-lindmd FILE; no positional arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	result, err := loadlab.RunHA(ctx, loadlab.HAOptions{Repository: *repo, ServerBinary: *binary, UpgradeBinary: *upgrade, Devices: *devices, PhaseDuration: *phase, Seed: *seed})
	if err == nil && !result.Passed {
		err = errors.New("lab ha: one or more acceptance checks failed")
	}
	return errors.Join(err, writeLabEvidence(stdout, *record, result))
}
