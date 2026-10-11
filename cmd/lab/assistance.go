package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"lindm/internal/vmlab"
)

func runVMAssistance(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm assistance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "signed Ubuntu 24.04 or Fedora 44 encrypted installer manifest")
	var options vmlab.VMAssistanceOptions
	hardware := &vmlab.VMHardwareOptions{TPM: true, Desktop: true, AllowNetwork: true}
	flags.StringVar(&hardware.Architecture, "architecture", "x86_64", "emulated architecture; manifest and installer must qualify it")
	flags.StringVar(&hardware.Accelerator, "accelerator", "kvm", "kvm or explicit tcg; never an implicit fallback")
	flags.StringVar(&hardware.StorageBus, "storage-bus", "virtio-scsi", "virtio-scsi, sata, nvme or virtio-blk")
	flags.StringVar(&options.Repository, "repo", ".", "repository with initialized dev PostgreSQL and trust fixture")
	flags.StringVar(&options.BuildRepository, "build-repo", "", "package and browser-driver source checkout with installed npm dependencies; defaults to -repo")
	flags.StringVar(&options.LabBinary, "lab", "", "prebuilt Linux lab executable for installed guest probes")
	flags.StringVar(&options.LindmdBinary, "lindmd", "", "prebuilt current server executable with embedded console")
	flags.StringVar(&options.RelayAddress, "relay-address", "127.0.0.1", "specific IPv4 address for TURN relay allocations on this host")
	flags.StringVar(&options.Encrypted.CacheDir, "cache", ".cache/lab/images", "verified official image cache")
	flags.StringVar(&options.Encrypted.GoldenDir, "golden-cache", ".cache/lab/encrypted", "private encrypted installer golden cache")
	flags.BoolVar(&options.Encrypted.RequireCachedGolden, "require-cached-golden", false, "fail instead of provisioning a missing encrypted GNOME golden")
	flags.StringVar(&options.Encrypted.WorkDir, "work-dir", "", "existing short parent for private disposable VM state (QEMU unix socket paths must stay under 108 bytes)")
	flags.StringVar(&options.Encrypted.Firmware.Code, "firmware-code", "", "package-owned OVMF code")
	flags.StringVar(&options.Encrypted.Firmware.Vars, "firmware-vars", "", "matching package-owned OVMF NVRAM template")
	flags.StringVar(&options.Encrypted.Firmware.Package, "firmware-package", "", "installed host firmware package")
	flags.StringVar(&options.Encrypted.Firmware.Version, "firmware-version", "", "exact required firmware package version")
	flags.BoolVar(&options.Encrypted.Firmware.SecureBoot, "secure-boot", false, "require observed enforced Secure Boot using enrolled template")
	evidence := flags.String("evidence", "", "required new private directory for the record, screenshots and journal excerpts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || options.LabBinary == "" || options.LindmdBinary == "" || *evidence == "" {
		return errors.New("vm assistance requires -manifest, -lab, -lindmd and -evidence NEW_DIRECTORY; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	for _, path := range []*string{&options.Repository, &options.BuildRepository, evidence} {
		if *path == "" {
			continue
		}
		if *path, err = filepath.Abs(*path); err != nil {
			return err
		}
	}
	if err := os.Mkdir(*evidence, 0o700); err != nil {
		return err
	}
	options.EvidenceDir = *evidence
	options.Encrypted.Desktop = "gnome"
	options.Encrypted.TPMBoot = true
	options.Encrypted.Hardware = hardware
	result, laneErr := vmlab.AssistanceVM(ctx, manifest, options)
	if result == nil {
		return laneErr
	}
	record := filepath.Join(*evidence, "assistance.json")
	if err := writeLabEvidence(stdout, record, result); err != nil {
		return errors.Join(laneErr, err)
	}
	return errors.Join(laneErr, os.Chmod(record, 0o400))
}
