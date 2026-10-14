// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"lindm/internal/vmlab"
)

func runVMInspectStorage(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm inspect-storage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options vmlab.EncryptedStorageInspectOptions
	var hardware vmlab.VMHardwareOptions
	options.VM.Hardware = &hardware
	manifestPath := flags.String("manifest", "", "pinned Ubuntu 24.04 or Fedora 44 encrypted installer manifest")
	flags.StringVar(&options.Repository, "repo", ".", "harness source checkout for base commit, diff and untracked source provenance")
	flags.StringVar(&options.BuildRepository, "build-repo", "", "source checkout used for the prebuilt agent (default: repo); no compilation in this lane")
	flags.StringVar(&options.Agent, "agent", "", "already-built version-stamped Linux lindm-agent, packaged and installed with the native manager")
	flags.StringVar(&options.PackageVersion, "package-version", "0.1.0", "exact prebuilt agent version required by the package builder")
	flags.StringVar(&options.FixtureOutput, "fixture-output", "", "new fixture directory under an existing caller-owned mode-0700 parent; create-only mode-0600 files after cleanup")
	flags.StringVar(&options.VM.CacheDir, "cache", ".cache/lab/images", "verified official ISO cache")
	flags.StringVar(&options.VM.GoldenDir, "golden-cache", ".cache/lab/encrypted", "private immutable encrypted golden cache")
	flags.StringVar(&options.VM.WorkDir, "work-dir", "", "parent for private disposable VM and package state")
	flags.StringVar(&hardware.Accelerator, "accelerator", "kvm", "kvm or tcg, never automatic fallback")
	flags.StringVar(&hardware.StorageBus, "storage-bus", "virtio-scsi", "virtio-blk, virtio-scsi, nvme or sata; virtio-scsi exposes explicit WWN")
	flags.BoolVar(&hardware.TPM, "tpm", true, "attach owned per-machine TPM")
	flags.StringVar(&options.VM.Desktop, "desktop", "", "golden desktop variant: gnome, kde or empty")
	flags.BoolVar(&options.VM.TPMBoot, "tpm-boot", false, "select TPM-capable golden boot variant")
	flags.StringVar(&options.VM.Firmware.Code, "firmware-code", "", "host distro package-owned OVMF code file")
	flags.StringVar(&options.VM.Firmware.Vars, "firmware-vars", "", "matching package-owned OVMF NVRAM template")
	flags.StringVar(&options.VM.Firmware.Package, "firmware-package", "", "installed host firmware package name")
	flags.StringVar(&options.VM.Firmware.Version, "firmware-version", "", "exact required host firmware package version")
	flags.BoolVar(&options.VM.Firmware.SecureBoot, "secure-boot", false, "require enforced Secure Boot")
	record := flags.String("record", "", "additional create-only mode-0600 public evidence JSON after guest cleanup")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || options.Agent == "" || options.FixtureOutput == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE -agent FILE -fixture-output NEW_DIR are required; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	result, err := vmlab.InspectEncryptedStorage(ctx, manifest, options)
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
