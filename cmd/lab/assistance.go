package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	scenarios := flags.String("scenarios", "", "comma-separated subset of control,view,decline,portal-cancel,lock; -hold defaults to none")
	hold := flags.Bool("hold", false, "hands-on demo: after the selected scenarios keep lindmd and the VM running until interrupted; writes owner access to EVIDENCE/owner-access, never a qualification record")
	flags.BoolVar(&options.ConsoleTURNTCP, "console-turn-tcp", false, "restrict the operator Chromium to TURN over TCP (a remote console behind an SSH forward) and require a TCP relay pair")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || options.LabBinary == "" || options.LindmdBinary == "" || *evidence == "" {
		return errors.New("vm assistance requires -manifest, -lab, -lindmd and -evidence NEW_DIRECTORY; no positional arguments")
	}
	if *scenarios != "" && !*hold {
		return errors.New("vm assistance -scenarios requires -hold; a qualification record always runs every scenario")
	}
	if *hold {
		options.Scenarios = []string{}
		if *scenarios != "" {
			options.Scenarios = strings.Split(*scenarios, ",")
		}
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
	if *hold {
		options.Hold = func(access *vmlab.AssistanceHold) error { return writeAssistanceHold(stdout, *evidence, access) }
		_, err := vmlab.AssistanceVM(ctx, manifest, options)
		return err
	}
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

// writeAssistanceHold puts the owner's secrets only in a new 0400 file inside
// the private evidence directory; stdout (often a service log) gets the rest.
func writeAssistanceHold(stdout io.Writer, dir string, access *vmlab.AssistanceHold) error {
	path := filepath.Join(dir, "owner-access")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "Enrollment URL: %s/enroll\nUsername: %s\nEnrollment secret (one-time): %s\nExpires at: %s\nGuest desktop user: %s\nGuest desktop password: %s\n", access.ConsoleOrigin, access.Username, access.EnrollmentSecret, access.ExpiresAt.Format(time.RFC3339), access.DesktopUser, access.DesktopPassword)
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	origin, err := url.Parse(access.ConsoleOrigin)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, `Remote-assistance demo is running; Ctrl-C stops lindmd and the VM and removes their state.
Console: %s (trust .cache/dev/transport-ca.crt in a dedicated browser profile)
Relay: TURN on loopback port %d (UDP and TCP)
Remote browser: ssh -L %s:localhost:%s -L %d:localhost:%d <user>@<this-host>, then open the console URL; media uses TURN over TCP through the forward
Owner enrollment: %s/enroll as %s, expires %s; the one-time secret is in %s
Device: %s (%s), GNOME Wayland, GDM autologin as %s; its password is in the same file
Guest display (TigerVNC >= 1.11, Unix socket, no TCP listener): vncviewer %s
On this host: %s vm assistance-respond -evidence %s {%s}
From another host: ssh <user>@<this-host> %s vm assistance-respond -evidence %s {%s}
  allow = Allow + Share in the desktop dialog (+ Allow Remote Interaction for a Control request); decline; stop; screenshot.
Request assistance from the device page; consent is the guest user's own Allow/Decline.
`, access.ConsoleOrigin, access.RelayPort, origin.Port(), origin.Port(), access.RelayPort, access.RelayPort, access.ConsoleOrigin, access.Username, access.ExpiresAt.Format(time.RFC3339), path, access.Hostname, access.DeviceID, access.DesktopUser, access.DisplaySocket, executable, dir, strings.Join(vmlab.AssistanceRespondActions, "|"), executable, dir, strings.Join(vmlab.AssistanceRespondActions, "|"))
	return err
}

// runVMAssistanceRespond clicks one local-user control in a held demo's guest
// and prints the screenshot taken afterwards.
func runVMAssistanceRespond(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm assistance-respond", flag.ContinueOnError)
	flags.SetOutput(stderr)
	evidence := flags.String("evidence", "", "evidence directory of a running `lab vm assistance -hold`")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *evidence == "" || flags.NArg() != 1 {
		return fmt.Errorf("usage: lab vm assistance-respond -evidence DIR {%s}; allow completes consent (Allow, Allow Remote Interaction for a Control request, Share)", strings.Join(vmlab.AssistanceRespondActions, "|"))
	}
	dir, err := filepath.Abs(*evidence)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	shot, err := vmlab.AssistanceRespond(ctx, dir, flags.Arg(0))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Guest screenshot after %s: %s\n", flags.Arg(0), shot)
	return err
}
