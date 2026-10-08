//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/packaging"
	"lindm/internal/vmlab"
)

func runVMLifecycle(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm lifecycle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "verified image protobuf JSON manifest")
	firstPath := flags.String("first-build", "", "first version's native BuildResult JSON record")
	secondPath := flags.String("second-build", "", "upgrade version's native BuildResult JSON record")
	aptPath := flags.String("apt-repository", "", "signed APTRepository JSON record (Ubuntu)")
	rejectionPath := flags.String("rejections", "", "actual RejectionFixtures JSON record")
	publicKey := flags.String("public-key", "", "separately pinned ASCII-armored package signing key")
	fingerprint := flags.String("fingerprint", "", "expected package signer fingerprint")
	repository := flags.String("repo", ".", "checkout with the existing real development control-plane fixture")
	cache := flags.String("cache", ".cache/lab/images", "verified image cache")
	workDir := flags.String("work-dir", "", "parent for owned disposable VM state")
	diagnostics := flags.String("diagnostics", "", "existing directory for opt-in private failure diagnostics")
	probe := flags.String("lab", "", "built lab probe binary (defaults to this executable)")
	observe := flags.Duration("observe-for", 0, "optional console inspection interval after first two publications (at most ten minutes)")
	executionTrust := flags.Bool("execution-trust", false, "exercise signed execution trust rotation, revocation and retained rollback fences after upgrade")
	record := flags.String("record", "", "write successful lifecycle evidence to a new private file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *firstPath == "" || *secondPath == "" || *rejectionPath == "" || *publicKey == "" || *fingerprint == "" {
		return errors.New("vm lifecycle requires -manifest, -first-build, -second-build, -rejections, -public-key and -fingerprint; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	format := packaging.FormatDEB
	if manifest.GetDistribution() == "fedora" {
		format = packaging.FormatRPM
	}
	first, err := readNativeBuildArtifact(*firstPath, format)
	if err != nil {
		return err
	}
	second, err := readNativeBuildArtifact(*secondPath, format)
	if err != nil {
		return err
	}
	var apt *packaging.APTRepository
	if *aptPath != "" {
		apt = new(packaging.APTRepository)
		if err := readLabEvidence(*aptPath, apt); err != nil {
			return err
		}
	}
	var rejections packaging.RejectionFixtures
	if err := readLabEvidence(*rejectionPath, &rejections); err != nil {
		return err
	}
	if *probe == "" {
		*probe, err = os.Executable()
		if err != nil {
			return err
		}
	}
	result, err := vmlab.LifecycleVM(ctx, manifest, vmlab.VMLifecycleOptions{Repository: *repository, CacheDir: *cache, WorkDir: *workDir, DiagnosticsDir: *diagnostics, LabBinary: *probe, First: first, Second: second, APT: apt, PublicKey: *publicKey, SignerFingerprint: *fingerprint, Rejections: rejections.Cases, ObserveFor: *observe, Progress: stderr, ExecutionTrust: *executionTrust})
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}

func runRejectionFixtures(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("packages rejection-fixtures", flag.ContinueOnError)
	flags.SetOutput(stderr)
	buildPath := flags.String("build", "", "positive first-version BuildResult JSON record with DEB and RPM")
	aptPath := flags.String("apt-repository", "", "positive signed APTRepository JSON record")
	output := flags.String("output", "", "new or empty private fixture directory")
	home := flags.String("signer-home", "", "explicit development package-signing home")
	fingerprint := flags.String("fingerprint", "", "pinned development signer fingerprint")
	record := flags.String("record", "", "write fixture metadata to a new private JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *buildPath == "" || *aptPath == "" || *output == "" || *home == "" || *fingerprint == "" {
		return errors.New("rejection-fixtures requires -build, -apt-repository, -output, -signer-home and -fingerprint; no positional arguments")
	}
	deb, err := readNativeBuildArtifact(*buildPath, packaging.FormatDEB)
	if err != nil {
		return err
	}
	rpm, err := readNativeBuildArtifact(*buildPath, packaging.FormatRPM)
	if err != nil {
		return err
	}
	var apt packaging.APTRepository
	if err := readLabEvidence(*aptPath, &apt); err != nil {
		return err
	}
	if err := resolvePackagePaths(output, home, record); err != nil {
		return err
	}
	if err := createPackageOutput(*output); err != nil {
		return err
	}
	result, err := packaging.BuildRejectionFixtures(ctx, packaging.RejectionRequest{DEB: deb, RPM: rpm, APT: &apt, Signer: packaging.SigningKey{Home: *home, Fingerprint: *fingerprint, Custody: packaging.CustodyDevelopment}, OutputDir: *output})
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}

func readNativeBuildArtifact(path string, format packaging.Format) (packaging.Artifact, error) {
	var build packaging.BuildResult
	if err := readLabEvidence(path, &build); err != nil {
		return packaging.Artifact{}, err
	}
	var selected packaging.Artifact
	found := false
	for _, artifact := range build.Artifacts {
		if artifact.Format != format {
			continue
		}
		if found || artifact.Version != build.Version || artifact.PayloadSHA256 != build.BinarySHA256 {
			return packaging.Artifact{}, errors.New("native build record has ambiguous or inconsistent artifacts")
		}
		selected = artifact
		found = true
	}
	if !found {
		return packaging.Artifact{}, errors.New("native build record does not contain the requested format")
	}
	return selected, nil
}
