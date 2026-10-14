// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
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
	repo := flags.String("repo", ".", "repository with read-only development trust, running Postgres and the shared demo advisory cache")
	source := flags.String("code", ".", "checkout whose agent sources form the signed stock artifact; independent of fixture -repo")
	binary := flags.String("lindmd", "", "prebuilt real lindmd executable with current embedded console")
	devices := flags.Int("devices", 300, "simulated devices with host and package inventory (1..10000)")
	packages := flags.Int("packages", 200, "simulated packages per device (1..5000)")
	assignments := flags.Int("assignment-percent", 20, "percentage assigned synthetic service work (1..100)")
	workers := flags.Int("enrollment-workers", 8, "bounded parallel enrollments (1..64)")
	hostObservation := flags.String("host-observation", "", "captured HostObservation protobuf JSON to replay on one simulated device (historical, at most 1 MiB)")
	revealApproval := flags.Bool("reveal-approval", false, "require a second human to approve secret and local-admin password reveals")
	demo := flags.Bool("demo", false, "seed the deterministic console demo dataset instead of the capacity population (ignores -devices/-packages/-assignment-percent/-enrollment-workers)")
	advisoryCache := flags.String("advisory-cache", "", "persistent vendor HTTP cache for -demo -feeds real (default <repo>/.cache/lab/advisories)")
	feeds := flags.String("feeds", "fixtures", "-demo advisory feeds: fixtures (small checked-in vendor documents, ready in minutes) or real (current full vendor exports; first refresh can take an hour)")
	artifactTimeout := flags.Duration("artifact-build-timeout", time.Hour, "signed stock artifact preparation deadline, separate from console setup")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binary == "" || flags.NArg() != 0 {
		return errors.New("lab console requires -lindmd FILE; no positional arguments")
	}
	if *feeds != "fixtures" && *feeds != "real" {
		return errors.New("lab console -feeds must be fixtures or real")
	}
	if *advisoryCache == "" {
		*advisoryCache = filepath.Join(*repo, ".cache", "lab", "advisories")
	}
	started := time.Now()
	_, _ = fmt.Fprintln(stderr, "lab console: preparing signed stock console artifact")
	preparation, stopPreparation := context.WithTimeout(ctx, *artifactTimeout)
	err := devlab.PrepareNativeEnrollmentRepository(preparation, *source)
	stopPreparation()
	if err != nil {
		return fmt.Errorf("prepare stock console artifact: %w", err)
	}
	setupTimeout := 30 * time.Minute
	if *demo && *feeds == "real" {
		setupTimeout = 3 * time.Hour
	}
	setup, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	_, _ = fmt.Fprintf(stderr, "lab console +%s: opening console fixture\n", time.Since(started).Round(time.Second))
	fixture, err := devlab.OpenStockConsoleAuthorityFixture(setup, *repo, *source, *binary)
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
		// The outer context: the route device keeps checking in until the console
		// stops. SeedDemo bounds and names each of its steps itself and reports
		// progress on stderr, so an overrun fails with the step that overran. The
		// refused package scan state, gated by the server's five-minute package
		// admission interval, finishes in the background after the console is ready.
		_, _ = fmt.Fprintf(stderr, "lab console +%s: seeding demo\n", time.Since(started).Round(time.Second))
		seeded, presence, err := loadlab.SeedDemo(ctx, fixture, loadlab.DemoOptions{HostObservationFile: *hostObservation, AdvisoryCache: *advisoryCache, FixtureFeeds: *feeds == "fixtures", Progress: stderr, BackgroundPackageFailure: true})
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, presence.Stop()) }()
		summary = demoSummary(seeded)
		reporting = "the route device and two isolated fleet-pilot hosts keep checking in; other devices stop reporting after population."
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
	// Its own bound: the setup deadline covers opening the fixture and the
	// capacity population, not a demo seed that bounds its own steps.
	issue, cancelIssue := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelIssue()
	enrollment, err := fixture.CreateConsoleEnrollment(issue)
	if err != nil {
		return fmt.Errorf("issue console owner enrollment: %w", err)
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
	fmt.Fprintln(&b, "The two fleet-pilot hosts retain simulated package, SSH-banner, firewall-zone and update-policy state for staged rollouts; this is not native execution evidence.")
	fmt.Fprintf(&b, "Assistance turned off (headless): device %s; refused before start: device %s session %s\n", routes.AssistanceOffDeviceID, routes.RefusedAssistanceDeviceID, routes.RefusedAssistanceSessionID)
	if demo.HistoricalDeviceID != "" {
		fmt.Fprintf(&b, "Historical host replay device: %s\nOriginal observation fields and collection times are preserved; package inventory and action results remain synthetic.\n", demo.HistoricalDeviceID)
	}
	return b.String()
}
