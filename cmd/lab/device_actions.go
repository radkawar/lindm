package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"lindm/internal/vmlab"
)

func runVMDeviceActions(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm device-actions", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "signed encrypted installer manifest of a release whose registry row supports the selected device-action capabilities")
	recoveryPath := flags.String("recovery-manifest", "", "signed same-distribution cloud recovery image manifest")
	var options vmlab.VMDeviceActionsOptions
	flags.StringVar(&options.Scenario, "scenario", "all", "all, encryption, wipe or compliance native qualification scenarios")
	flags.StringVar(&options.WipePhase, "wipe-phase", "", "with -scenario wipe: live-actions (lock, quarantine, wipe and loss without recovery), lock-quarantine, live-erase, live-report-loss, recovery-nvme, recovery-sata or recovery-attestation-refusal (TPM-less, measured-grub); empty runs all")
	flags.StringVar(&options.EncryptionPhase, "encryption-phase", "", "with -scenario encryption: tpm for separately recorded bind/cold-boot/PCR recovery; empty runs all")
	flags.StringVar(&options.RecoveryBootMode, "recovery-boot-mode", "", "original-device recovery: empty for the owned systemd-boot UKI, measured-grub for stock shim+GRUB with a TPM-attested initramfs")
	hardware := &vmlab.VMHardwareOptions{TPM: true, Desktop: true, AllowNetwork: true}
	flags.StringVar(&hardware.Architecture, "architecture", "x86_64", "shared emulated architecture; manifest and installer must qualify it")
	flags.StringVar(&hardware.Accelerator, "accelerator", "kvm", "kvm or explicit tcg; never an implicit fallback")
	flags.StringVar(&hardware.StorageBus, "storage-bus", "virtio-scsi", "virtio-scsi, sata, nvme or virtio-blk; actual complete WWN/serial identity required")
	flags.BoolVar(&hardware.TPM, "tpm", true, "swtpm2 present; false requires an observed real-server TPM-absent denial instead of a positive bind")
	flags.StringVar(&options.Repository, "repo", ".", "repository with initialized dev PostgreSQL and trust fixture")
	flags.StringVar(&options.BuildRepository, "build-repo", "", "package source repository; defaults to -repo")
	flags.StringVar(&options.LabBinary, "lab", "", "prebuilt Linux amd64 lab executable for installed guest probes")
	flags.StringVar(&options.LindmdBinary, "lindmd", "", "prebuilt current server executable")
	flags.StringVar(&options.Encrypted.CacheDir, "cache", ".cache/lab/images", "verified official image cache")
	flags.StringVar(&options.Encrypted.GoldenDir, "golden-cache", ".cache/lab/encrypted", "private encrypted installer golden cache")
	flags.StringVar(&options.Encrypted.WorkDir, "work-dir", "", "existing parent for private disposable VM state")
	flags.StringVar(&options.Encrypted.DiagnosticsDir, "diagnostics", "", "private owned failure diagnostics parent; returned from SSH hosts")
	flags.StringVar(&options.RedHatTokenFile, "redhat-token-file", "", "protected Red Hat offline-token file; required for RHEL original-device recovery, which installs entitled boot tooling in the disposable vendor guest")
	flags.StringVar(&options.Encrypted.Firmware.Code, "firmware-code", "", "package-owned OVMF code")
	flags.StringVar(&options.Encrypted.Firmware.Vars, "firmware-vars", "", "matching package-owned enrolled OVMF NVRAM template")
	flags.StringVar(&options.Encrypted.Firmware.Package, "firmware-package", "", "installed host firmware package")
	flags.StringVar(&options.Encrypted.Firmware.Version, "firmware-version", "", "exact required firmware package version")
	flags.BoolVar(&options.Encrypted.Firmware.SecureBoot, "secure-boot", false, "require observed enforced Secure Boot using enrolled template")
	flags.StringVar(&options.Encrypted.Desktop, "desktop", "gnome", "lab session desktop of the golden: gnome, cinnamon, cosmic or hyprland")
	flags.BoolVar(&options.Encrypted.TPMBoot, "tpm-boot", true, "golden built with a TPM2-capable unbound boot stack; false is accepted only with -wipe-phase lock-quarantine")
	record := flags.String("record", "", "required new nonsecret evidence JSON, exclusively created then made read-only")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *recoveryPath == "" || options.LabBinary == "" || options.LindmdBinary == "" || *record == "" {
		return errors.New("device-actions requires -manifest, -recovery-manifest, -lab, -lindmd and -record; no positional arguments")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	options.RecoveryManifest, err = vmlab.LoadManifest(*recoveryPath)
	if err != nil {
		return err
	}
	options.Encrypted.Hardware = hardware
	result, laneErr := vmlab.DeviceActionsVM(ctx, manifest, options)
	if result == nil {
		return laneErr
	}
	if err := writeLabEvidence(stdout, *record, result); err != nil {
		return errors.Join(laneErr, err)
	}
	return errors.Join(laneErr, os.Chmod(*record, 0400))
}
