package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"
	"time"

	"lindm/internal/loadlab"
)

func runLoad(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("load", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "repository with running Keycloak/Postgres dev dependencies (read-only)")
	binary := flags.String("lindmd", "", "prebuilt real lindmd executable")
	stages := flags.String("stages", "500,2000,5000,10000", "increasing simulated device counts; stop on SLO breach")
	duration := flags.Duration("stage-duration", 11*time.Minute, "steady-state duration per stage (1m..3h; use2h for qualified-level soak)")
	packages := flags.Int("packages", 2000, "packages per snapshot (1..5000)")
	assignments := flags.Int("assignment-percent", 5, "percentage of devices assigned synthetic service work (1..100)")
	workers := flags.Int("enrollment-workers", 8, "bounded parallel enrollments (1..64)")
	seed := flags.Uint64("seed", 1, "deterministic per-device scheduling seed")
	pool := flags.Uint("pool-size", 8, "explicit server database connection pool (protobuf validated)")
	profiles := flags.String("profile-dir", "", "create private directory for real CPU/mutex/block and PostgreSQL diagnostics")
	storage := flags.String("database-storage", "shared", "shared dev cluster, dedicated nvme loop/XFS, or tmpfs (not durable qualification)")
	generatorCPUs := flags.String("generator-cpus", "", "generator CPU list; re-exec before starting workload")
	serverCPUs := flags.String("server-cpus", "", "real server CPU list; disjoint from generator/Postgres")
	postgresCPUs := flags.String("postgres-cpus", "", "dedicated PostgreSQL container CPU list")
	record := flags.String("record", "", "new private nonsecret JSON evidence file, including failed runs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binary == "" || flags.NArg() != 0 {
		return errors.New("lab load requires -lindmd FILE; no positional arguments")
	}
	if uint64(*pool) > uint64(^uint32(0)) {
		return errors.New("pool-size exceeds uint32")
	}
	var counts []int
	for _, value := range strings.Split(*stages, ",") {
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		counts = append(counts, n)
	}
	if reexecuted, err := loadlab.ReexecWithGeneratorCPUs(ctx, loadlab.CPUConfig{GeneratorCPUs: *generatorCPUs, ServerCPUs: *serverCPUs, PostgresCPUs: *postgresCPUs}, stdout, stderr); reexecuted || err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Hour)
	defer cancel()
	result, err := loadlab.Run(ctx, loadlab.Options{Repository: *repo, ServerBinary: *binary, Stages: counts, StageDuration: *duration, Packages: *packages, AssignmentPercent: *assignments, EnrollmentWorkers: *workers, Seed: *seed, PoolSize: uint32(*pool), ProfileDir: *profiles, DatabaseStorage: *storage, GeneratorCPUs: *generatorCPUs, ServerCPUs: *serverCPUs, PostgresCPUs: *postgresCPUs})
	return errors.Join(err, writeLabEvidence(stdout, *record, result))
}
