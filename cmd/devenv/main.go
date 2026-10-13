// Command devenv maintains the development environment: the real
// PostgreSQL/Keycloak fixture, gates that build product code (signoff,
// pre-push, test-integration), Markdown generated from the platform registry
// and lab matrix, and disk collection. Landing in the shared checkout is
// cmd/dev's, which stays free of product imports.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/devlab/project"
)

const usage = `Usage: go run ./cmd/devenv <init|up|check|trust|test-integration|down|reset|recreate-database|rotate-credentials|signoff|pre-push|gc|generate-docs> [options]

  generate-docs  Rewrite Markdown blocks generated from internal/platform; -check
         fails instead when any block is stale (make generate / make lint).

  init   Atomically generate .cache/dev; validate, never overwrite, on reuse.
  up     Start pinned PostgreSQL and optional Keycloak, await TLS readiness,
         migrate as lindm_migrator, restrict metadata writes. Keycloak bootstraps
         the fixed owner; local mode prints the explicit one-shot bootstrap command.
  check  Check PostgreSQL runtime TLS login and, in Keycloak mode, directory access.
  test-integration  Run real PostgreSQL regressions in isolated disposable schemas.
         The fixture comes from -root; -code <checkout> (default -root) selects
         the code under test, so a clean worktree runs against the shared fixture.
         Queues on the host-wide integration lock, then waits for local lab
         memory admission and runs at nice 10.
         -packages <Go pattern> selects a focused package (default ./internal/...).
         -json-output <new file> retains owner-only go test JSON for profiling.
  trust  Generate/verify development-only execution/release roots and bootstrap.
  down   Stop this checkout's Compose project; preserve fixture and volumes.
  reset  DESTROY this checkout's fixture and dependency volumes. Requires
         -confirm-delete. Stop the separately supervised lindmd first.
  recreate-database  DESTROY only lindm, terminate its connections, reprovision,
         migrate and bootstrap. Requires -confirm-delete; preserves other databases.
  rotate-credentials  Replace the postgres, lindm_migrator and lindm_runtime
         passwords in the running cluster and rewrite their fixture files and
         manifest; keeps data. Restart a running lindmd afterwards.
  signoff  Gate a clean worktree of the pushed HEAD and post gh-signoff
         statuses for that SHA; see signoff -h.
  pre-push  Git hook body: make check in a clean worktree of each pushed SHA
         unless it already has a green signoff/unit; see pre-push -h.
  gc  Reclaim disk: stale Go build cache, finished matrix inputs, landed
         worktrees, stale lab runs and unreferenced lab images; prints bytes
         per class. dev land runs it under 200 GiB free; see gc -h.

Options: -root <repository> (default .), -timeout <duration> (default 10m;
for test-integration 40m, max 45m, counted only while it holds the integration lock;
queueing for the lock is bounded separately at 3h).
Init/up accept -authentication local|keycloak (default keycloak). A fixture's mode
is immutable. Local mode does not start or contact an IdP.
Reset and recreate-database accept -confirm-delete. Requires Linux, Go, Docker
with Compose v2 and a local daemon. Ports 15432, 18443, 18444 and 18445 are loopback-only.
Run the app separately after up: go run ./cmd/lindmd serve -config .cache/dev/server.json
Trust .cache/dev/transport-ca.crt in your development browser for HTTPS login.

Realm: https://localhost:18443/realms/lindm
Users: owner, administrator; passwords: .cache/dev/{owner,administrator}-password
Service credentials: .cache/dev/{console,directory,lab-admin}-secret
Database URLs: .cache/dev/{database-url,migration-database-url}
All secret files are 0600 in a 0700 fixture directory. Never commit/copy them.
Certificates last five years; changed/expired fixtures fail rather than rotate
credentials beneath persisted data. Restore originals or explicitly reset.
Database role passwords rotate only through rotate-credentials.
Compose project names are checkout-specific; fixed ports permit one running lab.
`

func run() error {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("a command is required")
	}
	verb := os.Args[1]
	if verb == "help" || verb == "-h" || verb == "--help" {
		fmt.Print(usage)
		return nil
	}
	if verb == "generate-docs" {
		return generateDocs(os.Args[2:])
	}
	switch verb {
	case "signoff":
		return runSignoff(os.Args[2:])
	case "pre-push":
		return runPrePush(os.Args[2:])
	case "gc":
		return runGC(os.Args[2:])
	}
	if verb != "init" && verb != "up" && verb != "check" && verb != "trust" && verb != "test-integration" && verb != "down" && verb != "reset" && verb != "recreate-database" && verb != "rotate-credentials" {
		return fmt.Errorf("unknown command %q; use help (land, gate-commit, status, protect and worktree are go run ./cmd/dev)", verb)
	}
	flags := flag.NewFlagSet(verb, flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	// The integration suite runs every package under -race against real
	// PostgreSQL with a 30-minute per-binary deadline. Its -timeout bounds the
	// run while it holds the host-wide integration lock (queueing is not
	// counted) and is capped so no run can monopolize the lock.
	defaultTimeout := 10 * time.Minute
	if verb == "test-integration" {
		defaultTimeout = 40 * time.Minute
	}
	timeout := flags.Duration("timeout", defaultTimeout, "command deadline; for test-integration, the run under the integration lock (max 45m)")
	var confirm bool
	authentication := "keycloak"
	if verb == "init" || verb == "up" {
		flags.StringVar(&authentication, "authentication", "keycloak", "primary authentication: local or keycloak")
	}
	if verb == "reset" || verb == "recreate-database" {
		flags.BoolVar(&confirm, "confirm-delete", false, "confirm destructive deletion for the selected operation")
	}
	var code, packages, jsonOutput string
	if verb == "test-integration" {
		flags.StringVar(&code, "code", "", "checkout whose code is built and tested (default -root)")
		flags.StringVar(&packages, "packages", "./internal/...", "Go package pattern to exercise (default all internal packages)")
		flags.StringVar(&jsonOutput, "json-output", "", "owner-only file retaining go test -json events for per-test profiling")
	}
	var usageErr error
	flags.Usage = func() { _, usageErr = fmt.Fprint(flags.Output(), usage) }
	if err := flags.Parse(os.Args[2:]); err != nil {
		if err == flag.ErrHelp {
			return usageErr
		}
		return errors.Join(err, usageErr)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if verb == "test-integration" && *timeout > integrationLockCap {
		return fmt.Errorf("test-integration -timeout %s exceeds the %s cap: the run holds the host-wide integration lock that every other integration run queues on; a suite slower than that needs fixing or sharding, not a longer lock", *timeout, integrationLockCap)
	}
	if verb == "reset" && !confirm {
		return fmt.Errorf("reset requires -confirm-delete; this destroys lab data and login credentials")
	}
	if verb == "recreate-database" && !confirm {
		return fmt.Errorf("recreate-database requires -confirm-delete; this destroys lindm data and terminates its connections")
	}
	absolute, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// test-integration bounds only its locked run (testIntegration); queueing
	// for the lock ends on interrupt.
	runTimeout := *timeout
	if verb != "test-integration" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	operations := map[string]func(context.Context, string) error{
		"init":  func(ctx context.Context, root string) error { return devlab.Init(ctx, root, authentication) },
		"up":    func(ctx context.Context, root string) error { return devlab.Up(ctx, root, authentication) },
		"check": devlab.Check,
		"down":  devlab.Down, "reset": devlab.Reset,
		"test-integration": func(ctx context.Context, root string) error {
			if code == "" {
				return testIntegration(ctx, root, root, runTimeout, packages, jsonOutput)
			}
			codeRoot, err := filepath.Abs(code)
			if err != nil {
				return err
			}
			return testIntegration(ctx, root, codeRoot, runTimeout, packages, jsonOutput)
		},
		"trust": devlab.Trust,
		"recreate-database": func(ctx context.Context, root string) error {
			return devlab.RecreateDatabase(ctx, root, confirm)
		},
		"rotate-credentials": devlab.RotateCredentials,
	}
	fmt.Printf("Compose project: %s\nFixture: %s\n", project.ComposeName(absolute), devlab.FixturePath(absolute))
	if err := operations[verb](ctx, absolute); err != nil {
		return err
	}
	fmt.Printf("%s complete\n", verb)
	if verb == "init" || verb == "up" {
		fmt.Printf("Server config: %s\nBrowser trust CA: %s\n", filepath.Join(devlab.FixturePath(absolute), "server.json"), filepath.Join(devlab.FixturePath(absolute), "transport-ca.crt"))
		if authentication == "keycloak" {
			fmt.Printf("Owner password file: %s\n", filepath.Join(devlab.FixturePath(absolute), "owner-password"))
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devenv:", err)
		os.Exit(1)
	}
}
