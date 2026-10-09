// Command dev maintains the real PostgreSQL/Keycloak development fixture.
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
)

const usage = `Usage: go run ./cmd/dev <init|up|check|trust|test-integration|down|reset> [options]

  init   Atomically generate .cache/dev; validate, never overwrite, on reuse.
  up     Start pinned PostgreSQL and optional Keycloak, await TLS readiness,
         migrate as lindm_migrator, restrict metadata writes. Keycloak bootstraps
         the fixed owner; local mode prints the explicit one-shot bootstrap command.
  check  Check PostgreSQL runtime TLS login and, in Keycloak mode, directory access.
  test-integration  Run real PostgreSQL regressions in isolated disposable schemas.
  trust  Generate/verify development-only execution/release roots and bootstrap.
  down   Stop this checkout's Compose project; preserve fixture and volumes.
  reset  DESTROY this checkout's fixture and dependency volumes. Requires
         -confirm-delete. Stop the separately supervised lindmd first.

Options: -root <repository> (default .), -timeout <duration> (default 10m).
Init/up accept -authentication local|keycloak (default keycloak). A fixture's mode
is immutable. Local mode does not start or contact an IdP.
Only reset accepts -confirm-delete. Requires Linux, Go, Docker with Compose v2,
and a local Docker daemon. Ports 15432, 18443, 18444 and 18445 are loopback-only.
Run the app separately after up: go run ./cmd/lindmd serve -config .cache/dev/server.json
Trust .cache/dev/transport-ca.crt in your development browser for HTTPS login.

Realm: https://localhost:18443/realms/lindm
Users: owner, administrator; passwords: .cache/dev/{owner,administrator}-password
Service credentials: .cache/dev/{console,directory,lab-admin}-secret
Database URLs: .cache/dev/{database-url,migration-database-url}
All secret files are 0600 in a 0700 fixture directory. Never commit/copy them.
Certificates last five years; changed/expired fixtures fail rather than rotate
credentials beneath persisted data. Restore originals or explicitly reset.
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
	if verb != "init" && verb != "up" && verb != "check" && verb != "trust" && verb != "test-integration" && verb != "down" && verb != "reset" {
		return fmt.Errorf("unknown command %q; use help", verb)
	}
	flags := flag.NewFlagSet(verb, flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	timeout := flags.Duration("timeout", 10*time.Minute, "overall command deadline")
	var confirm bool
	authentication := "keycloak"
	if verb == "init" || verb == "up" {
		flags.StringVar(&authentication, "authentication", "keycloak", "primary authentication: local or keycloak")
	}
	if verb == "reset" {
		flags.BoolVar(&confirm, "confirm-delete", false, "destroy this checkout's fixture and volumes")
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
	if verb == "reset" && !confirm {
		return fmt.Errorf("reset requires -confirm-delete; this destroys lab data and login credentials")
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
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	operations := map[string]func(context.Context, string) error{
		"init":  func(ctx context.Context, root string) error { return devlab.Init(ctx, root, authentication) },
		"up":    func(ctx context.Context, root string) error { return devlab.Up(ctx, root, authentication) },
		"check": devlab.Check,
		"down":  devlab.Down, "reset": devlab.Reset,
		"test-integration": devlab.TestIntegration,
		"trust":            devlab.Trust,
	}
	fmt.Printf("Compose project: %s\nFixture: %s\n", devlab.ProjectName(absolute), devlab.FixturePath(absolute))
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
		fmt.Fprintln(os.Stderr, "dev:", err)
		os.Exit(1)
	}
}
