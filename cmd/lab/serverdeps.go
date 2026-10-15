// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"

	"lindm/internal/platform"
	"lindm/internal/serverdeps"
	"lindm/internal/vmlab"
)

func runServerDependenciesCapture(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm serverdeps", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifest := flags.String("manifest", "", "authenticated fresh Ubuntu24.04 or RHEL9 x86 base image")
	cache := flags.String("cache", ".cache/lab/images", "authenticated image cache")
	snapshots := flags.String("snapshot-cache", "", "dependency closure store, default image cache")
	replaySHA := flags.String("replay-sha256", "", "replay an existing Ubuntu closure without recapturing vendor metadata")
	packages := flags.String("packages", "", "exact comma-separated installer prerequisites")
	custody := flags.String("custody", "development-lab", "development-lab, production-vendor (Ubuntu) or entitled-customer-private (RHEL)")
	maxBytes := flags.Uint64("max-bytes", 2<<30, "aggregate retained closure ceiling, maximum16GiB")
	maxPackages := flags.Uint("max-packages", 1000, "native package closure ceiling, maximum5000")
	work := flags.String("work-dir", "", "disposable VM parent")
	labBinary := flags.String("lab-binary", "", "matching native guest helper required for existing-closure replay or RHEL capture")
	labSHA := flags.String("lab-sha256", "", "required immutable native consumer helper SHA256 for existing-closure replay")
	redhatToken := flags.String("redhat-token-file", "", "protected RHEL entitlement token file")
	record := flags.String("record", "", "required new observed capture/replay evidence file")
	flags.String("repo", ".", "source checkout for remote native driver")
	hardware := newVMHardwareFlags(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifest == "" || *record == "" || *maxPackages > uint(serverdeps.HardMaxPackages) {
		return errors.New("serverdeps requires -manifest, -record and bounded native closure")
	}
	if *replaySHA == "" && *packages == "" {
		return errors.New("serverdeps capture requires -packages")
	}
	image, err := vmlab.LoadManifest(*manifest)
	if err != nil {
		return err
	}
	if *replaySHA != "" {
		if *packages != "" || *redhatToken != "" || *snapshots == "" || *labBinary == "" || *labSHA == "" {
			return errors.New("serverdeps replay requires -snapshot-cache, -lab-binary and -lab-sha256; capture packages and entitlement token are not replay inputs")
		}
		result, transcript, err := vmlab.ReplayServerDependencies(ctx, image, *replaySHA, vmlab.ServerDependenciesOptions{CacheDir: *cache, SnapshotCache: *snapshots, WorkDir: *work, LabBinary: *labBinary, LabSHA256: *labSHA, Hardware: hardware.options()})
		if err != nil {
			return err
		}
		return writeLabEvidence(stdout, *record, map[string]any{"distribution": result.Distribution, "version": result.Version, "architecture": result.Architecture, "backend": result.Backend.String(), "manifest_sha256": result.ManifestSha256, "base_image_sha256": result.BaseImageSha256, "requested_packages": result.RequestedPackages, "package_count": result.PackageCount, "total_bytes": result.TotalBytes, "custody": result.Custody, "helper_sha256": *labSHA, "consumer_replay": string(transcript), "cleanup": "owned disposable guest cleanup returned success; authenticated image and original closure retained"})
	}
	requested := strings.Split(*packages, ",")
	for _, value := range requested {
		if !validServerDependencyInput(value) {
			return errors.New("invalid native dependency package input")
		}
	}
	var result *serverdepsv1.Manifest
	release := platform.ForManifest(image.Distribution, image.Version)
	if err := release.LabLaneOn(platform.LaneDeploy, image.Architecture); err != nil {
		return err
	}
	if !release.Server.DependencySnapshots {
		return errors.New("server dependency snapshots are not qualified for this connected-only recipe")
	}
	switch release.Packages.Backend.PackageDB() {
	case platform.PackageDBDpkg:
		result, err = vmlab.CaptureServerDependencies(ctx, image, vmlab.ServerDependenciesOptions{CacheDir: *cache, SnapshotCache: *snapshots, WorkDir: *work, Custody: *custody, RequestedPackages: requested, MaxBytes: *maxBytes, MaxPackages: uint32(*maxPackages), Hardware: hardware.options()})
	case platform.PackageDBRPM:
		if *snapshots == "" {
			*snapshots = *cache
		}
		result, err = vmlab.CaptureRHELServerDependencies(ctx, image, vmlab.RHELServerDependenciesOptions{CacheDir: *cache, WorkDir: *work, DependencyCache: *snapshots, LabBinary: *labBinary, RedHatTokenFile: *redhatToken, Custody: *custody, Packages: requested, MaxBytes: *maxBytes, MaxPackages: uint32(*maxPackages), Hardware: hardware.options()})
	default:
		return errors.New("unsupported native server dependency distro")
	}
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, map[string]any{"distribution": result.Distribution, "version": result.Version, "architecture": result.Architecture, "backend": result.Backend.String(), "manifest_sha256": result.ManifestSha256, "base_image_sha256": result.BaseImageSha256, "requested_packages": result.RequestedPackages, "package_count": result.PackageCount, "total_bytes": result.TotalBytes, "solver_version": result.SolverVersion, "custody": result.Custody, "offline_replay": "fresh baseline native " + result.Backend.String() + " install, external network denied"})
}

func validServerDependencyInput(value string) bool {
	if value == "" || len(value) > 256 || value[0] == '-' {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+_.:~^=-", c) {
			continue
		}
		return false
	}
	return true
}

func runServerDependenciesTransfer(ctx context.Context, operation string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("serverdeps "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	cache := flags.String("cache", "", "dependency closure store")
	digest := flags.String("sha256", "", "release-authenticated closure content address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *cache == "" || *digest == "" {
		return errors.New("serverdeps transfer requires -cache and -sha256")
	}
	switch operation {
	case "export":
		return serverdeps.Export(ctx, *cache, *digest, stdout)
	case "import":
		return serverdeps.Import(ctx, *cache, *digest, stdin)
	case "present":
		_, _, err := serverdeps.Load(*cache, *digest)
		return err
	case "install":
		return serverdeps.Install(ctx, *cache, *digest)
	default:
		return errors.New("unsupported serverdeps operation")
	}
}
