//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lindm/internal/packaging"
)

func runPackages(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("packages requires keygen, build, build-server, build-cli, apt, rpm, arch or rejection-fixtures")
	}
	if args[0] == "rejection-fixtures" {
		return runRejectionFixtures(ctx, args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("packages "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "private output directory (created mode 0700 if absent)")
	if args[0] == "keygen" {
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *output == "" || flags.NArg() != 0 {
			return errors.New("packages keygen requires -output DIR and no positional arguments")
		}
		if err := resolvePackagePaths(output); err != nil {
			return err
		}
		if err := createPackageOutput(*output); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		key, err := packaging.GenerateDevelopmentSigner(ctx, *output)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "development-only package signer\nhome %s\nfingerprint %s\nnot an execution, transport, TUF or production key\n", key.Home, key.Fingerprint)
		return err
	}
	if args[0] != "build" && args[0] != "build-server" && args[0] != "build-cli" && args[0] != "apt" && args[0] != "rpm" && args[0] != string(packaging.FormatArch) {
		return errors.New("unknown packages command")
	}
	home := flags.String("signer-home", "", "isolated GnuPG package-signing home")
	fingerprint := flags.String("fingerprint", "", "pinned package-signing fingerprint")
	development := flags.Bool("development-key", false, "explicitly permit a marked development-only signer")
	passphrase := flags.String("passphrase-file", "", "protected production signing passphrase file")
	record := flags.String("record", "", "write result metadata to a new private JSON file")
	epoch := flags.Int64("source-date-epoch", 0, "deterministic native package timestamp")
	var rejectedSPKI, rejectedFingerprints, rejectedHomes []string
	flags.Func("reject-spki-sha256", "forbid actual signing public key material (repeatable)", func(value string) error { rejectedSPKI = append(rejectedSPKI, value); return nil })
	flags.Func("reject-fingerprint", "forbid native signing fingerprint (repeatable)", func(value string) error { rejectedFingerprints = append(rejectedFingerprints, value); return nil })
	flags.Func("reject-home-prefix", "forbid a signing-home subtree (repeatable)", func(value string) error { rejectedHomes = append(rejectedHomes, value); return nil })
	var agent, repository, version, revision, formats, architecture *string
	if args[0] == "build" || args[0] == "build-server" || args[0] == "build-cli" {
		binaryFlag := "agent"
		if args[0] == "build-server" {
			binaryFlag = "lindmd"
		}
		if args[0] == "build-cli" {
			binaryFlag = "lindmctl"
		}
		agent = flags.String(binaryFlag, "", "prebuilt version-stamped executable; mutually exclusive with -repo")
		repository = flags.String("repo", "", "checkout to compile using cached Go builds")
		version = flags.String("version", "", "three-component numeric upstream version")
		revision = flags.String("revision", "development", "source build revision label; not a clean-source attestation")
		formats = flags.String("formats", "deb,rpm", "comma-separated native formats: deb,rpm,arch (Arch is agent-only)")
		architecture = flags.String("arch", "", "target architecture: amd64 or arm64; default is the build host")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("-output DIR is required")
	}
	if err := resolvePackagePaths(output, home, passphrase, agent, repository); err != nil {
		return err
	}
	artifacts := flags.Args()
	for index := range artifacts {
		if err := resolvePackagePaths(&artifacts[index]); err != nil {
			return err
		}
	}
	custody := packaging.CustodyProduction
	if *development {
		custody = packaging.CustodyDevelopment
	}
	signer := packaging.SigningKey{Home: *home, Fingerprint: *fingerprint, Custody: custody, PassphraseFile: *passphrase, RejectPublicKeySHA256: rejectedSPKI, RejectFingerprints: rejectedFingerprints, RejectPathPrefixes: rejectedHomes}
	if err := createPackageOutput(*output); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var result any
	var err error
	switch args[0] {
	case "build", "build-server", "build-cli":
		if flags.NArg() != 0 || *version == "" || (*agent == "") == (*repository == "") {
			return errors.New("packages build requires -version and exactly one prebuilt executable or -repo DIR; no positional arguments")
		}
		var requested []packaging.Format
		for _, format := range strings.Split(*formats, ",") {
			requested = append(requested, packaging.Format(format))
		}
		request := packaging.BuildRequest{AgentBinary: *agent, Version: *version, TargetArchitecture: *architecture, OutputDir: *output, Formats: requested, Signer: signer, SourceDateEpoch: *epoch}
		if args[0] == "build-server" {
			if *repository != "" {
				result, err = packaging.BuildServerSource(ctx, packaging.SourceRequest{Repository: *repository, Revision: *revision, BuildRequest: request})
			} else {
				result, err = packaging.BuildServer(ctx, request)
			}
		} else if args[0] == "build-cli" {
			if *repository != "" {
				result, err = packaging.BuildCLISource(ctx, packaging.SourceRequest{Repository: *repository, Revision: *revision, BuildRequest: request})
			} else {
				result, err = packaging.BuildCLI(ctx, request)
			}
		} else if *repository != "" {
			result, err = packaging.BuildSource(ctx, packaging.SourceRequest{Repository: *repository, Revision: *revision, BuildRequest: request})
		} else {
			result, err = packaging.Build(ctx, request)
		}
	case "apt":
		if flags.NArg() == 0 {
			return errors.New("packages apt requires one or more built DEB paths")
		}
		result, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: *output, DEBs: artifacts, Signer: signer, SourceDateEpoch: *epoch})
	case "rpm":
		if flags.NArg() == 0 {
			return errors.New("packages rpm requires one or more signed RPM paths")
		}
		result, err = packaging.PublishRPM(ctx, packaging.RPMRequest{OutputDir: *output, RPMs: artifacts, Signer: signer, SourceDateEpoch: *epoch})
	case string(packaging.FormatArch):
		if flags.NArg() == 0 {
			return errors.New("packages arch requires signed .pkg.tar.zst paths with adjacent .sig files")
		}
		result, err = packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: *output, Packages: artifacts, Signer: signer, SourceDateEpoch: *epoch})
	}
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}

func createPackageOutput(directory string) error {
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// The packaging library performs ownership, mode and ancestry validation
	// before writing. Existing contents are never replaced by this helper.
	return nil
}

func resolvePackagePaths(paths ...*string) error {
	for _, path := range paths {
		if path == nil || *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	return nil
}
