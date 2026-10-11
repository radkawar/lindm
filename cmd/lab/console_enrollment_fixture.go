package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"lindm/internal/devlab"
)

// runConsoleEnrollment holds a real, initially empty console with signed native
// repositories. No synthetic or preinstalled device can satisfy the native lane.
func runConsoleEnrollment(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("console-enrollment", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", ".", "checkout with protected dev trust and running PostgreSQL")
	source := flags.String("code", "", "checkout whose current agent sources are packaged; independent of fixture -repo")
	binary := flags.String("lindmd", "", "release-stamped current server with embedded production console")
	architectures := flags.String("architectures", "arm64", "comma-separated package architectures: arm64,amd64")
	publication := flags.String("publication-record", "", "optional new private JSON recording actual package digests and signed metadata publication")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *binary == "" || *source == "" {
		return errors.New("console-enrollment requires -lindmd and -code; no positional arguments")
	}
	setup, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenEnrollmentConsoleAuthorityFixture(setup, *repository, *source, *binary, strings.Split(*architectures, ","))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
	if *publication != "" {
		if err := writeLabEvidence(io.Discard, *publication, fixture.NativeRepository); err != nil {
			return err
		}
	}
	enrollment, err := fixture.CreateConsoleEnrollment(setup)
	if err != nil {
		return err
	}
	defer func() { enrollment.Secret = "" }()
	_, err = fmt.Fprintf(stdout, "Protected disposable enrollment console; output contains a one-time secret.\nEnrollment URL: %s/enroll\nUsername: console-owner\nEnrollment secret: %s\nExpires: %s\nAdmin address: %s\nDevice address: %s\nNative repositories: %s/repo/apt and %s/repo/rpm\nNo devices are pre-enrolled. Copy the production install command after the native lane reports a fresh guest ready.\nCtrl-C removes this fixture's owned server, database, packages and signing custody.\n", fixture.ConsoleOrigin, enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), fixture.AdminAddress, fixture.DeviceAddress, fixture.ConsoleOrigin, fixture.ConsoleOrigin)
	enrollment.Secret = ""
	if err != nil {
		return err
	}
	cancel()
	return fixture.Wait(ctx)
}
