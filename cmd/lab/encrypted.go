package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"lindm/internal/vmlab"
)

func runVMEncrypted(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm encrypted", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "signed official Ubuntu 24.04/26.04, Fedora 44 or RHEL 9.8/10.2 installer ISO manifest")
	var options vmlab.EncryptedVMOptions
	var hardware vmlab.VMHardwareOptions
	options.Hardware = &hardware
	flags.StringVar(&hardware.Accelerator, "accelerator", "kvm", "kvm or tcg, never automatic fallback")
	flags.StringVar(&hardware.StorageBus, "storage-bus", "virtio-blk", "virtio-blk, virtio-scsi, nvme or sata")
	flags.IntVar(&hardware.ExtraDisks, "extra-disks", 0, "additional owned 1 GiB blank disks, zero to four")
	flags.BoolVar(&hardware.TPM, "tpm", true, "attach per-machine swtpm TPM 2.0; false proves absence")
	flags.StringVar(&options.Desktop, "desktop", "", "native installer desktop: gnome or kde; empty is headless; Ubuntu desktop media require gnome")
	flags.BoolVar(&options.TPMBoot, "tpm-boot", false, "install systemd/dracut TPM-capable boot path without enrolling a token")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified official ISO cache")
	flags.StringVar(&options.GoldenDir, "golden-cache", ".cache/lab/encrypted", "private immutable encrypted golden machine cache")
	flags.StringVar(&options.WorkDir, "work-dir", "", "parent for private disposable VM state")
	flags.StringVar(&options.Firmware.Code, "firmware-code", "", "host distro package-owned OVMF code file")
	flags.StringVar(&options.Firmware.Vars, "firmware-vars", "", "matching package-owned OVMF NVRAM template; enrolled keys for Secure Boot")
	flags.StringVar(&options.Firmware.Package, "firmware-package", "", "installed host firmware package name")
	flags.StringVar(&options.Firmware.Version, "firmware-version", "", "exact required host firmware package version")
	flags.BoolVar(&options.Firmware.SecureBoot, "secure-boot", false, "require enrolled firmware template and observed enforced Secure Boot")
	record := flags.String("record", "", "write nonsecret observed evidence to a new private JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE is required; positional arguments are not accepted")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	evidence, err := vmlab.EncryptedSmoke(ctx, manifest, options)
	return errors.Join(err, writeLabEvidence(stdout, *record, evidence))
}
