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

// runConsoleEnrollment holds a real, initially empty console with a signed
// executable-adjacent agent artifact and no release repository configuration.
// No synthetic or preinstalled device can satisfy the native lane.
func runConsoleEnrollment(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("console-enrollment", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repository := flags.String("repo", ".", "checkout with protected dev trust and running PostgreSQL")
	source := flags.String("code", "", "checkout whose current agent sources are packaged; independent of fixture -repo")
	binary := flags.String("lindmd", "", "release-stamped current server with embedded production console")
	architectures := flags.String("architectures", "arm64", "comma-separated required package architectures: arm64,amd64 (artifact contains the stock native matrix)")
	publication := flags.String("publication-record", "", "optional new private JSON recording signed artifact, no-config startup and observed readiness")
	publicHost := flags.String("public-host", "", "optional lowercase multi-label DNS name (e.g. lindm-console.test) for both origins instead of localhost; guests and browsers map it to the fixture listeners")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *binary == "" || *source == "" {
		return errors.New("console-enrollment requires -lindmd and -code; no positional arguments")
	}
	if *publicHost != "" {
		if err := devlab.ValidatePublicHost(*publicHost); err != nil {
			return err
		}
	}
	setup, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenEnrollmentConsoleAuthorityFixture(setup, *repository, *source, *binary, strings.Split(*architectures, ","), *publicHost)
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
	approver, err := fixture.CreateConsoleApproverEnrollment(setup)
	if err != nil {
		return err
	}
	defer func() { approver.Secret = "" }()
	if _, err := fmt.Fprintln(stdout, "Signed artifact startup: Ready. releaseRepository and nativeRepositories are absent. Development package and attestation signing keys were removed before startup."); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Protected disposable enrollment console; output contains one-time secrets.\nEnrollment URL: %s/enroll\nUsername: console-owner\nEnrollment secret: %s\nExpires: %s\nApprover username: console-approver\nApprover enrollment secret: %s\nApprover expires: %s\nAdmin address: %s\nDevice address: %s\nNative repositories: %s/repo/apt, %s/repo/rpm and %s/repo/arch\nNo devices are pre-enrolled. Copy the production install command after the native lane reports a fresh guest ready.\nCtrl-C removes this fixture's owned server, database, packages and signing custody.\n", fixture.ConsoleOrigin, enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), approver.GetSecret(), approver.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), fixture.AdminAddress, fixture.DeviceAddress, fixture.ConsoleOrigin, fixture.ConsoleOrigin, fixture.ConsoleOrigin)
	enrollment.Secret, approver.Secret = "", ""
	if err != nil {
		return err
	}
	cancel()
	return fixture.Wait(ctx)
}
