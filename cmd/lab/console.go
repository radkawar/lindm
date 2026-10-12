package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/loadlab"
)

func runConsole(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	if len(args) > 0 && args[0] == "review" {
		return runConsoleReview(ctx, args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("console", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "repository with protected development trust and running Postgres (read-only)")
	binary := flags.String("lindmd", "", "prebuilt real lindmd executable with current embedded console")
	devices := flags.Int("devices", 300, "simulated devices with host and package inventory (1..10000)")
	packages := flags.Int("packages", 200, "simulated packages per device (1..5000)")
	assignments := flags.Int("assignment-percent", 20, "percentage assigned synthetic service work (1..100)")
	workers := flags.Int("enrollment-workers", 8, "bounded parallel enrollments (1..64)")
	hostObservation := flags.String("host-observation", "", "captured HostObservation protobuf JSON to replay on one simulated device (historical, at most 1 MiB)")
	revealApproval := flags.Bool("reveal-approval", false, "require a second human to approve secret and local-admin password reveals")
	demo := flags.Bool("demo", false, "seed the deterministic console demo dataset instead of the capacity population (ignores -devices/-packages/-assignment-percent/-enrollment-workers)")
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
	if *revealApproval {
		if err := fixture.RequireConsoleRevealApproval(setup); err != nil {
			return err
		}
	}
	var summary string
	reporting := "devices stop reporting after population."
	if *demo {
		// The outer context: the route device keeps checking in until the console stops.
		seeded, presence, err := loadlab.SeedDemo(ctx, fixture, loadlab.DemoOptions{HostObservationFile: *hostObservation})
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, presence.Stop()) }()
		summary = demoSummary(seeded)
		reporting = "other devices stop reporting after population."
	} else {
		population, err := loadlab.Populate(setup, fixture, loadlab.PopulateOptions{Devices: *devices, Packages: *packages, AssignmentPercent: *assignments, EnrollmentWorkers: *workers, HostObservationFile: *hostObservation})
		if err != nil {
			return err
		}
		summary = fmt.Sprintf("Simulated devices: %d\nPackages per device: %d\nCompleted simulated assignments: %d\n", len(population.DeviceIDs), *packages, population.CompletedAssignments)
		if population.HistoricalDeviceID != "" {
			summary += fmt.Sprintf("Historical host replay device: %s\nOriginal observation fields and collection times are preserved. Labels identify historical replay; package inventory and action results remain synthetic.\n", population.HistoricalDeviceID)
		}
	}
	enrollment, err := fixture.CreateConsoleEnrollment(setup)
	if err != nil {
		return err
	}
	defer func() { enrollment.Secret = "" }()
	_, err = fmt.Fprintf(stdout, "Protected disposable console lab — output contains a one-time enrollment secret.\nConsole origin: %s\nEnrollment URL: %s/enroll\nUsername: console-owner\nEnrollment secret (shown once): %s\nExpires at: %s\nOwned database: %s\n%sChoose a password and register a browser authenticator, then sign in.\nSynthetic inventory/results are not native device evidence; %s\nPress Ctrl-C to stop the server and remove only this fixture's database/resources.\n", fixture.ConsoleOrigin, fixture.ConsoleOrigin, enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), fixture.DatabaseName, summary, reporting)
	enrollment.Secret = ""
	if err != nil {
		return err
	}
	cancel()
	return fixture.Wait(ctx)
}

// demoSummary lists seeded device and route IDs; Demo carries no secrets.
func demoSummary(demo loadlab.Demo) string {
	var b strings.Builder
	b.WriteString("Demo devices (synthetic):\n")
	for _, device := range demo.Devices {
		fmt.Fprintf(&b, "  %-8s %s %s %s\n", device.State, device.ID, cmp.Or(device.Hostname, "-"), cmp.Or(device.OS, "-"))
	}
	routes := demo.Routes
	fmt.Fprintf(&b, "Routes: device %s, profile %s, secret %s, action %s, assistance %s, recovery %s\n", routes.DeviceID, routes.ProfileID, routes.SecretID, routes.ActionID, routes.AssistanceSessionID, routes.RecoveryActionID)
	fmt.Fprintf(&b, "Device %s keeps checking in so remote assistance and inventory refreshes can be requested; it completes refreshes, no user answers.\n", routes.DeviceID)
	fmt.Fprintf(&b, "Assistance turned off (headless): device %s; refused before start: device %s session %s\n", routes.AssistanceOffDeviceID, routes.RefusedAssistanceDeviceID, routes.RefusedAssistanceSessionID)
	if demo.HistoricalDeviceID != "" {
		fmt.Fprintf(&b, "Historical host replay device: %s\nOriginal observation fields and collection times are preserved; package inventory and action results remain synthetic.\n", demo.HistoricalDeviceID)
	}
	return b.String()
}
