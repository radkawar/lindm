package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "hosts" {
		return runHosts(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "host-exec" {
		return runHostExec(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 1 && args[0] == "vm" {
		return runScheduledVM(ctx, args, stdout, stderr)
	}
	return runUnscheduled(ctx, args, stdout, stderr)
}

func runUnscheduled(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) >= 1 && args[0] == "acceptance" {
		return runAcceptance(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "console" {
		return runConsole(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "load" {
		return runLoad(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "guest" {
		return runGuestProbe(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "packages" {
		return runPackages(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "release" {
		return runRelease(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "auth" && args[1] == "check" {
		return runAuthCheck(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "cli" && args[1] == "check" {
		return runCLICheck(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "auth" && args[1] == "check-fresh" {
		return runAuthCheckFresh(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "auth" && args[1] == "check-broker" {
		return runAuthCheckBroker(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "auth" && args[1] == "check-entra" {
		return runAuthCheckEntra(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "profiles" && args[1] == "check-catalog" {
		return runProfileCatalog(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "native" && args[1] == "check-install-projection" {
		return runInstallProjection(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "native" && args[1] == "check-install-snapshot" {
		return runInstallSnapshot(ctx, args[2:], stdout, stderr)
	}
	if len(args) == 2 && args[0] == "native" && args[1] == "install-snapshot-child" {
		return vmlab.RunInstallSnapshotChild(ctx, stdout)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "server" {
		return runVMServer(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "updates" {
		return runVMUpdates(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "server" && args[1] == "compose" {
		return runServerCompose(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "enroll-unattended" {
		return runVMEnrollUnattended(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "lifecycle" {
		return runVMLifecycle(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "dispatch" {
		return runVMDispatch(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "encrypted" {
		return runVMEncrypted(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "device-actions" {
		return runVMDeviceActions(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "inspect-storage" {
		return runVMInspectStorage(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "inspect" {
		return runVMInspect(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "vm" && args[1] == "services" {
		return runVMServices(ctx, args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "images" && args[1] == "redhat" {
		return runRedHatImages(ctx, args[2:], stdout, stderr)
	}
	if len(args) < 2 || args[0] != "images" || (args[1] != "fetch" && args[1] != "verify") {
		return errors.New("usage: lab acceptance -evidence NEW_DIRECTORY [-web-only|-skip-feeds] [flags]; lab hosts baseline-browser -record NEW_FILE [flags]; lab packages {keygen|build|build-server|build-cli|apt|rpm|arch|rejection-fixtures} [flags]; lab release {attestation-keygen|build|verify|repository} [flags]; lab auth {check|check-fresh|check-broker|check-entra} [-repo DIR] [-lindmd FILE] [-cleanup-prefix PREFIX]; lab cli check [-root DIR] [-lindmd FILE] [-record NEW_FILE]; lab load -lindmd FILE [-record NEW_FILE] [flags]; lab console -lindmd FILE [-devices 300] [flags]; lab profiles check-catalog -lindmd FILE [flags]; lab native {check-install-projection|check-install-snapshot} [flags]; lab vm {inspect|lifecycle|services|dispatch|server|updates|encrypted|device-actions|enroll-unattended} [flags]; lab server compose [-repo DIR] [-record NEW_FILE]; lab images {fetch|verify} -manifest FILE [-cache DIR]; lab images redhat {discover|fetch|inventory|cleanup} [flags]; lab guest {bootstrap-interrupted|network-boundaries|executor-ready|connection-identity|services}")
	}
	flags := flag.NewFlagSet("images "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "strict protobuf JSON image manifest")
	cache := flags.String("cache", ".cache/lab/images", "dedicated digest-addressed image cache")
	var files vmlab.Artifacts
	if args[1] == "verify" {
		flags.StringVar(&files.Image, "image", "", "existing image to verify offline instead of the cache")
		flags.StringVar(&files.Checksum, "checksum", "", "existing signed vendor checksum or sanitized authenticated-vendor receipt")
		flags.StringVar(&files.Signature, "signature", "", "existing detached checksum signature (Ubuntu or Arch)")
		flags.StringVar(&files.Key, "key", "", "existing vendor public key or keyring")
	}
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE is required; positional arguments are not accepted")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	direct := files.Image != "" || files.Checksum != "" || files.Key != "" || files.Signature != ""
	if direct {
		if files.Image == "" || files.Checksum == "" || (manifest.ChecksumMode != labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED && files.Key == "") {
			return errors.New("offline artifact verification requires -image and -checksum; signed modes also require -key")
		}
		cacheSet := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "cache" {
				cacheSet = true
			}
		})
		if cacheSet {
			return errors.New("choose either -cache or explicit artifact files, not both")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	var verified *vmlab.VerifiedImage
	if args[1] == "fetch" {
		verified, err = (vmlab.Fetcher{}).Fetch(ctx, manifest, *cache)
	} else if direct {
		if (manifest.SignatureUrl != nil) != (files.Signature != "") {
			return errors.New("-signature is required exactly when the manifest uses detached checksums")
		}
		if manifest.ChecksumMode == labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED && files.Key != "" {
			return errors.New("authenticated vendor mode has no offline signing key")
		}
		verified, err = vmlab.VerifyArtifacts(ctx, manifest, files)
	} else {
		verified, err = vmlab.VerifyCache(ctx, manifest, *cache)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified %s\nsha256 %s\nbytes %d\nverification_mode %s\nsigner %s\nprimary %s\nimage %q\n", manifest.Id, verified.SHA256, verified.Size, manifest.ChecksumMode, verified.SigningFingerprint, verified.PrimaryFingerprint, verified.Path)
	return err
}

func runVMInspect(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "strict protobuf JSON image manifest")
	agent := flags.String("agent", "", "built Linux lindm-agent executable matching the manifest architecture")
	cache := flags.String("cache", ".cache/lab/images", "dedicated verified image cache")
	workDir := flags.String("work-dir", "", "existing parent for a disposable private run directory (default: OS temporary directory)")
	diagnosticsDir := flags.String("diagnostics", "", "existing directory for opt-in private cloud-init failure JSON; may contain sensitive guest data")
	record := flags.String("record", "", "write complete inspection and runtime evidence to a new private JSON file")
	inventoryRecord := flags.String("inventory-record", "", "opt-in new private NativeObservation JSON file (0600); contains local account/network identifiers")
	hardware := newVMHardwareFlags(flags)
	encryptionFixture := flags.String("encryption-fixture", "none", "format only an extra disposable disk: none, luks1, luks2 or lvm-luks2; requires guest tools")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *agent == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE and -agent FILE are required; positional arguments are not accepted")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	result, err := vmlab.InspectVM(ctx, manifest, vmlab.VMInspectOptions{Agent: *agent, CacheDir: *cache, WorkDir: *workDir, DiagnosticsDir: *diagnosticsDir, Hardware: hardware.options(), EncryptionFixture: *encryptionFixture, InventoryRecord: *inventoryRecord})
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}

type vmHardwareFlags struct {
	hardware vmlab.VMHardwareOptions
	firmware vmlab.EncryptedFirmwareOptions
}

// All cloud-image lanes use the same explicit hardware selection and defaults.
func newVMHardwareFlags(flags *flag.FlagSet) *vmHardwareFlags {
	options := new(vmHardwareFlags)
	flags.StringVar(&options.hardware.Accelerator, "accelerator", "", "kvm or tcg (default: native KVM, cross-architecture TCG; no fallback)")
	flags.StringVar(&options.hardware.StorageBus, "storage-bus", "virtio-blk", "emulated data-disk bus: virtio-blk, virtio-scsi, nvme or sata")
	flags.IntVar(&options.hardware.ExtraDisks, "extra-disks", 0, "additional disposable 1 GiB disks (0–4); never host devices")
	flags.BoolVar(&options.hardware.TPM, "tpm", false, "attach emulated swtpm TPM 2.0 (default: TPM absent)")
	flags.BoolVar(&options.hardware.Desktop, "display-device", false, "attach virtual GPU and private Unix VNC socket; does not install a desktop")
	flags.BoolVar(&options.hardware.AllowNetwork, "allow-network", false, "permit guest user-mode egress for connected vendor first-boot/time services; default remains restricted")
	flags.StringVar(&options.firmware.Code, "firmware-code", "", "installed EFI code image (default: x86 BIOS; required for aarch64)")
	flags.StringVar(&options.firmware.Vars, "firmware-vars", "", "installed EFI variables template, privately copied for this guest")
	flags.StringVar(&options.firmware.Package, "firmware-package", "", "distribution package owning the selected EFI files")
	flags.StringVar(&options.firmware.Version, "firmware-version", "", "exact installed EFI package version; RPM includes epoch")
	flags.BoolVar(&options.firmware.SecureBoot, "secure-boot", false, "require selected EFI firmware to enforce Secure Boot with enrolled keys")
	return options
}

func (f *vmHardwareFlags) options() *vmlab.VMHardwareOptions {
	if f.firmware.Code != "" || f.firmware.Vars != "" || f.firmware.Package != "" || f.firmware.Version != "" || f.firmware.SecureBoot {
		f.hardware.Firmware = &f.firmware
	}
	return &f.hardware
}

func runVMServices(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm services", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "strict protobuf JSON image manifest")
	cache := flags.String("cache", ".cache/lab/images", "dedicated verified image cache")
	workDir := flags.String("work-dir", "", "existing parent for owned disposable VM state")
	diagnostics := flags.String("diagnostics", "", "existing directory for opt-in private failure diagnostics")
	record := flags.String("record", "", "write successful native service evidence to a new private JSON file")
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
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	result, err := vmlab.ServicesVM(ctx, manifest, vmlab.VMServicesOptions{LabBinary: binary, CacheDir: *cache, WorkDir: *workDir, DiagnosticsDir: *diagnostics})
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
