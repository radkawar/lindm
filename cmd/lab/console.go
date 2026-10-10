package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/loadlab"
)

func runConsole(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("console", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "repository with protected development trust and running Postgres (read-only)")
	binary := flags.String("lindmd", "", "prebuilt real lindmd executable with current embedded console")
	devices := flags.Int("devices", 300, "simulated devices with host and package inventory (1..10000)")
	packages := flags.Int("packages", 200, "simulated packages per device (1..5000)")
	assignments := flags.Int("assignment-percent", 20, "percentage assigned synthetic service work (1..100)")
	workers := flags.Int("enrollment-workers", 8, "bounded parallel enrollments (1..64)")
	hostObservation := flags.String("host-observation", "", "captured HostObservation protobuf JSON to replay on one simulated device (historical, at most 1 MiB)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binary == "" || flags.NArg() != 0 {
		return errors.New("lab console requires -lindmd FILE; no positional arguments")
	}
	setup, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(setup, *repo, *binary)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
	population, err := loadlab.Populate(setup, fixture, loadlab.PopulateOptions{Devices: *devices, Packages: *packages, AssignmentPercent: *assignments, EnrollmentWorkers: *workers, HostObservationFile: *hostObservation})
	if err != nil {
		return err
	}
	enrollment, err := fixture.CreateConsoleEnrollment(setup)
	if err != nil {
		return err
	}
	defer func() { enrollment.Secret = "" }()
	_, err = fmt.Fprintf(stdout, "Protected disposable console lab — output contains a one-time enrollment secret.\nConsole origin: %s\nEnrollment URL: %s/enroll\nUsername: console-owner\nEnrollment secret (shown once): %s\nExpires at: %s\nOwned database: %s\nSimulated devices: %d\nPackages per device: %d\nCompleted simulated assignments: %d\nChoose a password and register a browser authenticator, then sign in.\nSynthetic inventory/results are not native device evidence; devices stop reporting after population.\nPress Ctrl-C to stop the server and remove only this fixture's database/resources.\n", fixture.ConsoleOrigin, fixture.ConsoleOrigin, enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), fixture.DatabaseName, len(population.DeviceIDs), *packages, population.CompletedAssignments)
	enrollment.Secret = ""
	if err != nil {
		return err
	}
	if population.HistoricalDeviceID != "" {
		if _, err := fmt.Fprintf(stdout, "Historical host replay device: %s\nOriginal observation fields and collection times are preserved. Labels identify historical replay; package inventory and action results remain synthetic.\n", population.HistoricalDeviceID); err != nil {
			return err
		}
	}
	cancel()
	return fixture.Wait(ctx)
}
