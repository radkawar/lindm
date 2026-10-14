// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"
	"time"

	"lindm/internal/devlab"
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
	listen := flags.String("listen-address", "", "bind server listeners to this local IPv4 address (for example a direct-link address); default loopback")
	generatorHost := flags.String("generator-host", "", "SSH alias running simulated devices via `lab load-generator`; default in-process")
	generatorBinary := flags.String("generator-binary", "", "absolute path of the prebuilt lab executable on -generator-host")
	generatorSSH := flags.String("generator-ssh-config", "", "optional absolute ssh_config file (ssh -F) for -generator-host")
	remoteGeneratorCPUs := flags.String("remote-generator-cpus", "", "remote generator taskset CPU list; isolate it from remote lindmd replicas")
	replicaHost := flags.String("replica-host", "", "SSH host for an additional owned lindmd replica behind TLS passthrough HAProxy")
	replicaSSH := flags.String("replica-ssh-config", "", "absolute ssh_config file for the remote replica")
	replicaBinary := flags.String("replica-binary", "", "absolute prebuilt lindmd path on the replica host")
	replicaAddress := flags.String("replica-address", "", "remote replica direct-link IPv4 address")
	replicaCPUs := flags.String("replica-cpus", "", "remote lindmd CPU list")
	replicas := flags.Int("replicas", 2, "scale-out replicas (2 or 3); requires -replica-host")
	thirdReplicaCPUs := flags.String("third-replica-cpus", "", "third replica local CPU list, disjoint from local lindmd/PostgreSQL")
	advisoryFeeds := flags.String("advisory-feeds", "", "strict protobuf JSON AdvisoryConfig of real feeds; enables server refresh/evaluation and the advisory freshness SLO")
	packageBaseline := flags.String("package-baseline", "", "protobuf JSON PackageBatch of recorded native packages placed first in every snapshot")
	postgresSettings := flags.String("postgres-settings", "", "comma-separated allowlisted name=value tuning for the dedicated nvme/tmpfs PostgreSQL (durability settings are rejected)")
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
	var scaleOut *devlab.ScaleOutOptions
	if *replicaHost != "" {
		scaleOut = &devlab.ScaleOutOptions{SSHHost: *replicaHost, SSHConfig: *replicaSSH, RemoteBinary: *replicaBinary, RemoteAddress: *replicaAddress, RemoteCPUs: *replicaCPUs, LocalReplicaCPUs: *thirdReplicaCPUs, Replicas: *replicas}
	} else if *replicaSSH != "" || *replicaBinary != "" || *replicaAddress != "" || *replicaCPUs != "" || *thirdReplicaCPUs != "" || *replicas != 2 {
		return errors.New("replica options require -replica-host")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Hour)
	defer cancel()
	result, err := loadlab.Run(ctx, loadlab.Options{Repository: *repo, ServerBinary: *binary, Stages: counts, StageDuration: *duration, Packages: *packages, AssignmentPercent: *assignments, EnrollmentWorkers: *workers, Seed: *seed, PoolSize: uint32(*pool), ProfileDir: *profiles, DatabaseStorage: *storage, GeneratorCPUs: *generatorCPUs, ServerCPUs: *serverCPUs, PostgresCPUs: *postgresCPUs, ListenAddress: *listen, GeneratorHost: *generatorHost, GeneratorBinary: *generatorBinary, GeneratorSSHConfig: *generatorSSH, AdvisoryFeeds: *advisoryFeeds, PackageBaseline: *packageBaseline, PostgresSettings: splitSettings(*postgresSettings), ScaleOut: scaleOut, RemoteGeneratorCPUs: *remoteGeneratorCPUs})
	return errors.Join(err, writeLabEvidence(stdout, *record, result))
}

// runLoadGenerator is started by `lab load -generator-host` over SSH. It speaks
// only the orchestrator's stdin/stdout protocol and accepts no arguments.
func runLoadGenerator(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("lab load-generator takes no arguments; it is started by lab load -generator-host")
	}
	return loadlab.ServeGenerator(ctx, stdin, stdout)
}

func splitSettings(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
