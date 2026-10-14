// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/devlab/toolchain"
	"lindm/internal/loadlab"
)

type consoleReviewConfig struct {
	Origin                 string                                     `json:"origin"`
	Username               string                                     `json:"username"`
	Password               string                                     `json:"password"`
	EnrollmentSecret       string                                     `json:"enrollmentSecret"`
	EvidenceDirectory      string                                     `json:"evidenceDirectory"`
	Checkout               string                                     `json:"checkout"`
	Demo                   loadlab.Demo                               `json:"demo"`
	Build                  map[string]string                          `json:"build"`
	EnrollmentFixture      consoleReviewEnrollmentFixture             `json:"enrollmentFixture"`
	MissingArtifactFixture consoleReviewEnrollmentFixture             `json:"missingArtifactFixture"`
	DirectoryFixture       *devlab.DirectoryAuthorizationReviewConfig `json:"directoryFixture,omitempty"`
}

type consoleReviewEnrollmentFixture struct {
	Origin    string `json:"origin"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	SetupCode string `json:"setupCode"`
}

// consoleReviewReport is the subset of the runner's sanitized report.json that
// the command summarizes; the file itself remains the evidence.
type consoleReviewReport struct {
	Passed   bool     `json:"passed"`
	Failures []string `json:"failures"`
	Results  []struct {
		Passed bool `json:"passed"`
	} `json:"results"`
}

const consoleReviewPrintedFailures = 200

// runConsoleReview seeds the demo console fixture, then drives the maintained
// browser review (web/acceptance/review.mjs) through real enrollment and sign-in.
func runConsoleReview(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("console review", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "repository with read-only development trust, running Postgres and the shared advisory cache")
	binary := flags.String("lindmd", "", "prebuilt real lindmd executable with the console under review embedded")
	evidence := flags.String("evidence", "", "new private directory for report.json, index.html and screenshots")
	hostObservation := flags.String("host-observation", "", "optional captured HostObservation protobuf JSON to replay on one demo device")
	directoryAuthorization := flags.Bool("directory-authorization", false, "include real Keycloak group-role editing and scoped browser authorization")
	advisoryCache := flags.String("advisory-cache", "", "persistent vendor HTTP cache (default <repo>/.cache/lab/advisories)")
	timeout := flags.Duration("timeout", 3*time.Hour, "overall review deadline including first vendor refresh")
	artifactTimeout := flags.Duration("artifact-build-timeout", time.Hour, "signed stock artifact preparation deadline, separate from the review deadline")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binary == "" || *evidence == "" || flags.NArg() != 0 {
		return errors.New("lab console review requires -lindmd FILE -evidence NEW_DIRECTORY; no positional arguments")
	}
	if *advisoryCache == "" {
		*advisoryCache = filepath.Join(*repo, ".cache", "lab", "advisories")
	}
	checkout, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(checkout, "web/acceptance/review.mjs")); err != nil {
		return fmt.Errorf("run lab console review from the checkout under review: %w", err)
	}
	directory, err := filepath.Abs(*evidence)
	if err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	serverDigest, err := acceptanceFileDigest(*binary)
	if err != nil {
		return err
	}
	preparation, stopPreparation := context.WithTimeout(ctx, *artifactTimeout)
	err = devlab.PrepareNativeEnrollmentRepository(preparation, checkout)
	stopPreparation()
	if err != nil {
		return fmt.Errorf("prepare stock console artifact: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	private, err := os.MkdirTemp("", "lindm-console-review-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(private)) }()
	fixture, err := devlab.OpenStockConsoleAuthorityFixture(ctx, *repo, checkout, *binary)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
	demo, presence, err := loadlab.SeedDemo(ctx, fixture, loadlab.DemoOptions{HostObservationFile: *hostObservation, SourceDirectory: checkout, AdvisoryCache: *advisoryCache})
	if err != nil {
		return fmt.Errorf("seed demo console: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, presence.Stop()) }()
	var directoryReviewConfig *devlab.DirectoryAuthorizationReviewConfig
	if *directoryAuthorization {
		directoryFixture, err := devlab.OpenAuthorityFixture(ctx, *repo, *binary)
		if err != nil {
			return fmt.Errorf("open real directory review fixture: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, directoryFixture.Close()) }()
		directoryDevices, err := loadlab.Populate(ctx, directoryFixture, loadlab.PopulateOptions{Devices: 2, Packages: 1, AssignmentPercent: 1, EnrollmentWorkers: 1})
		if err != nil {
			return fmt.Errorf("populate synthetic directory review devices: %w", err)
		}
		directoryReview, err := directoryFixture.OpenDirectoryAuthorizationReview(ctx, directoryDevices.DeviceIDs)
		if err != nil {
			return fmt.Errorf("prepare directory authorization review: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, directoryReview.Close(context.WithoutCancel(ctx))) }()
		directoryReviewConfig = &directoryReview.Config
	}
	// Build publication from the checkout under review, never from the separate
	// directory that supplies development database/TLS trust.
	enrollmentFixture, setupCode, err := devlab.OpenSetupEnrollmentConsoleAuthorityFixture(ctx, *repo, checkout, *binary, []string{"amd64", "arm64"})
	if err != nil {
		return fmt.Errorf("open published enrollment review fixture: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, enrollmentFixture.Close()) }()
	defer func() { setupCode = "" }()
	missingFixture, missingSetupCode, err := devlab.OpenSetupMissingArtifactConsoleAuthorityFixture(ctx, *repo, *binary)
	if err != nil {
		return fmt.Errorf("open missing artifact review fixture: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, missingFixture.Close()) }()
	defer func() { missingSetupCode = "" }()
	enrollment, err := fixture.CreateConsoleEnrollment(ctx)
	if err != nil {
		return err
	}
	var password [24]byte
	if _, err := rand.Read(password[:]); err != nil {
		return err
	}
	cfg := consoleReviewConfig{
		Origin: fixture.ConsoleOrigin, Username: "console-owner", Password: hex.EncodeToString(password[:]),
		EnrollmentSecret: enrollment.GetSecret(), EvidenceDirectory: directory, Checkout: checkout, Demo: demo,
		Build:            map[string]string{"lindmdSHA256": serverDigest},
		DirectoryFixture: directoryReviewConfig,
		EnrollmentFixture: consoleReviewEnrollmentFixture{
			Origin: enrollmentFixture.ConsoleOrigin, Username: "setup-owner",
			Password: hex.EncodeToString(password[:]), SetupCode: setupCode,
		},
		MissingArtifactFixture: consoleReviewEnrollmentFixture{
			Origin: missingFixture.ConsoleOrigin, Username: "console-owner",
			Password: hex.EncodeToString(password[:]), SetupCode: missingSetupCode,
		},
	}
	enrollment.Secret = ""
	setupCode, missingSetupCode = "", ""
	clear(password[:])
	encoded, err := json.Marshal(cfg)
	cfg.Password, cfg.EnrollmentSecret = "", ""
	cfg.EnrollmentFixture.Password, cfg.EnrollmentFixture.SetupCode = "", ""
	cfg.MissingArtifactFixture.Password, cfg.MissingArtifactFixture.SetupCode = "", ""
	if cfg.DirectoryFixture != nil {
		cfg.DirectoryFixture.ReaderPassword = ""
		for i := range cfg.DirectoryFixture.OwnerCookies {
			cfg.DirectoryFixture.OwnerCookies[i].Value = ""
		}
	}
	if err != nil {
		return err
	}
	configPath := filepath.Join(private, "review-config.json")
	err = os.WriteFile(configPath, encoded, 0600)
	clear(encoded)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Reviewing console at %s with %d demo devices; evidence: %s\n", fixture.ConsoleOrigin, len(demo.Devices), directory); err != nil {
		return err
	}
	node, environ, err := toolchain.Node(ctx, checkout, os.Environ())
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, node, filepath.Join(checkout, "web/acceptance/review.mjs"), configPath)
	command.Dir, command.Env, command.WaitDelay = checkout, environ, 45*time.Second
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	// Framework diagnostics can echo filled credentials; the runner writes its
	// own sanitized report instead.
	command.Stdout, command.Stderr = io.Discard, io.Discard
	runErr := command.Run()
	return errors.Join(summarizeConsoleReview(stdout, directory), runErr)
}

func summarizeConsoleReview(stdout io.Writer, directory string) error {
	body, err := os.ReadFile(filepath.Join(directory, "report.json"))
	if err != nil {
		return fmt.Errorf("console review produced no report: %w", err)
	}
	var report consoleReviewReport
	if err := json.Unmarshal(body, &report); err != nil {
		return fmt.Errorf("decode console review report: %w", err)
	}
	passed := 0
	for _, result := range report.Results {
		if result.Passed {
			passed++
		}
	}
	if _, err := fmt.Fprintf(stdout, "Captures: %d passed of %d\nContact sheet: %s\n", passed, len(report.Results), filepath.Join(directory, "index.html")); err != nil {
		return err
	}
	for index, failure := range report.Failures {
		if index == consoleReviewPrintedFailures {
			if _, err := fmt.Fprintf(stdout, "... %d more in report.json\n", len(report.Failures)-index); err != nil {
				return err
			}
			break
		}
		if _, err := fmt.Fprintf(stdout, "FAIL %s\n", failure); err != nil {
			return err
		}
	}
	if !report.Passed {
		return fmt.Errorf("console review failed with %d findings", len(report.Failures))
	}
	_, err = fmt.Fprintln(stdout, "Console review passed.")
	return err
}
