// SPDX-License-Identifier: Apache-2.0

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

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

func runVMAssistance(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	flags := flag.NewFlagSet("vm assistance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "signed encrypted installer manifest of a release whose registry row supports assistance")
	var options vmlab.VMAssistanceOptions
	hardware := &vmlab.VMHardwareOptions{TPM: true, Desktop: true, AllowNetwork: true}
	flags.StringVar(&hardware.Architecture, "architecture", "x86_64", "emulated architecture; manifest and installer must qualify it")
	flags.StringVar(&hardware.Accelerator, "accelerator", "kvm", "kvm or explicit tcg; never an implicit fallback")
	flags.StringVar(&hardware.StorageBus, "storage-bus", "virtio-scsi", "virtio-scsi, sata, nvme or virtio-blk")
	flags.BoolVar(&hardware.TPM, "tpm", true, "swtpm2 present; false selects the TPM-absent golden where the guest kernel cannot observe QEMU's TPM (Debian arm64)")
	flags.StringVar(&options.Repository, "repo", ".", "repository with initialized dev PostgreSQL and trust fixture")
	flags.StringVar(&options.BuildRepository, "build-repo", "", "package and browser-driver source checkout with installed npm dependencies; defaults to -repo")
	flags.StringVar(&options.LabBinary, "lab", "", "prebuilt Linux lab executable for installed guest probes")
	flags.StringVar(&options.LindmdBinary, "lindmd", "", "prebuilt current server executable with embedded console")
	flags.StringVar(&options.RelayAddress, "relay-address", "127.0.0.1", "specific IPv4 address for TURN relay allocations on this host")
	flags.StringVar(&options.Encrypted.CacheDir, "cache", ".cache/lab/images", "verified official image cache")
	flags.StringVar(&options.Encrypted.GoldenDir, "golden-cache", ".cache/lab/encrypted", "private encrypted installer golden cache")
	flags.BoolVar(&options.Encrypted.RequireCachedGolden, "require-cached-golden", false, "fail instead of provisioning a missing encrypted desktop golden")
	flags.StringVar(&options.Encrypted.WorkDir, "work-dir", "", "existing short parent for private disposable VM state (QEMU unix socket paths must stay under 108 bytes)")
	flags.StringVar(&options.Encrypted.Firmware.Code, "firmware-code", "", "package-owned OVMF code")
	flags.StringVar(&options.Encrypted.Firmware.Vars, "firmware-vars", "", "matching package-owned OVMF NVRAM template")
	flags.StringVar(&options.Encrypted.Firmware.Package, "firmware-package", "", "installed host firmware package")
	flags.StringVar(&options.Encrypted.Firmware.Version, "firmware-version", "", "exact required firmware package version")
	flags.BoolVar(&options.Encrypted.Firmware.SecureBoot, "secure-boot", false, "require observed enforced Secure Boot using enrolled template")
	flags.StringVar(&options.Encrypted.Desktop, "desktop", "gnome", "lab session desktop of the golden: gnome, cinnamon, cosmic or hyprland")
	flags.BoolVar(&options.Encrypted.TPMBoot, "tpm-boot", true, "golden built with a TPM2-capable unbound boot stack (must match the cached golden)")
	evidence := flags.String("evidence", "", "required new private directory for the record, screenshots and journal excerpts")
	scenarios := flags.String("scenarios", "", "comma-separated subset of the desktop's scenarios (gnome: control,view,decline,portal-cancel,lock,clipboard,clipboard-limited,clipboard-policy,clipboard-permission,keyboard,display,message,monitors; refusal-only desktops: view-unavailable,control-unavailable); -hold defaults to none")
	rebootPolicy := flags.Bool("reboot-policy", false, "qualify signed reboot windows and employee deferral on a disposable desktop; emits reboot-policy.json, not assistance qualification")
	hold := flags.Bool("hold", false, "hands-on demo: after the selected scenarios keep lindmd and the VM running until interrupted; writes owner access to EVIDENCE/owner-access, never a qualification record")
	name := flags.String("name", "", "persistent held demo name; Ctrl-C stops processes but keeps enrolled state")
	destroy := flags.Bool("destroy", false, "destroy the named stopped demo, its VM and fixture")
	demoRoot := flags.String("demo-root", "", "host-owned persistent demo root (internal scheduler input)")
	flags.BoolVar(&options.ConsoleTURNTCP, "console-turn-tcp", false, "restrict the operator Chromium to TURN over TCP (a remote console behind an SSH forward) and require a TCP relay pair")
	controlPlane := flags.String("control-plane", "", "private single-use controller handle (internal SSH lane input)")
	demoDevice := flags.String("demo-device", "", "private organization device handoff (internal runner input)")
	demoParent := flags.String("demo-parent", "", "owning organization demo name (internal runner input)")
	flags.Bool("colocated", false, "keep lindmd, PostgreSQL and TURN on the SSH lab host instead of the controller")
	flags.String("controller-address", "", "override the routed controller IPv4 address for an SSH-native split run")
	flags.StringVar(&options.AdvisoryCache, "advisory-cache", "", "persistent revalidating feed cache for held demos; defaults to the configured lab work directory")
	flags.StringVar(&options.RedHatTokenFile, "redhat-token-file", "", "protected Red Hat offline-token file for an entitled organization device (internal runner input): registers it, and unregisters its recorded consumer on -destroy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if options.RedHatTokenFile != "" && *demoParent == "" {
		return errors.New("-redhat-token-file is only valid for an organization demo device")
	}
	if err := validateRebootPolicyFlags(*rebootPolicy, *hold, *name, *scenarios); err != nil {
		return err
	}
	if *name != "" {
		if !*hold {
			return errors.New("-name requires -hold")
		}
		var root string
		root, err = labhost.DemoDirectory(options.Encrypted.WorkDir, *name)
		if err != nil {
			return err
		}
		if *demoRoot == "" {
			*demoRoot = root
		} else if expected, err := labhost.DemoDirectory(filepath.Dir(filepath.Dir(*demoRoot)), *name); err != nil || expected != *demoRoot {
			return errors.New("invalid persistent demo root")
		}
		if *destroy {
			if *demoParent != "" {
				return destroyOrganizationDevice(ctx, options.Repository, *demoRoot, *demoParent, options.RedHatTokenFile, stdout)
			}
			return destroyAssistanceDemo(ctx, options.Repository, *demoRoot, stdout)
		}
		if ctx.Value(assistanceDemoLockKey{}) != *demoRoot {
			var lock *os.File
			lock, err = lockAssistanceDemo(*demoRoot)
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, lock.Close()) }()
		}
		if err := openAssistanceDemoRoot(*demoRoot); err != nil {
			return err
		}
		if *demoParent != "" {
			if err := bindOrganizationDeviceRoot(*demoRoot, *demoParent, true); err != nil {
				return err
			}
		}
		options.PersistentDir = filepath.Join(*demoRoot, "desktop")
		options.FixtureDir = filepath.Join(*demoRoot, "control-plane")
		if *controlPlane != "" {
			options.FixtureDir = filepath.Join(*demoRoot, "authority")
		}
		options.ExistingOwner, err = persistentOwnerExists(*demoRoot)
		if err != nil {
			return err
		}
	} else if *destroy || *demoRoot != "" {
		return errors.New("-destroy requires -hold -name NAME")
	}
	if flags.NArg() != 0 || *manifestPath == "" || options.LabBinary == "" || options.LindmdBinary == "" || *evidence == "" {
		return errors.New("vm assistance requires -manifest, -lab, -lindmd and -evidence NEW_DIRECTORY; no positional arguments")
	}
	if *rebootPolicy {
		options.RebootPolicy = new(vmlab.VMRebootPolicyResult)
		options.Scenarios = []string{}
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
	if *controlPlane != "" {
		options.ControlPlane, err = vmlab.ReadAssistanceControlPlane(*controlPlane)
		if err != nil {
			return err
		}
	}
	options.Encrypted.Hardware = hardware
	if *demoDevice != "" {
		input, err := vmlab.ReadDemoDeviceInput(*demoDevice)
		if err != nil {
			return err
		}
		hardware.Desktop = input.Desktop
		if !input.Desktop {
			options.Encrypted.Desktop = ""
		}
		options.Hold = func(access *vmlab.AssistanceHold) error {
			return publishAssistanceHeld(*evidence, access)
		}
		options.RedHatRegistered = func(ctx context.Context, identity *labv1.RedHatRegistrationIdentity) error {
			return publishDemoRegistration(ctx, *evidence, identity, time.Second)
		}
		if ready, ok := ctx.Value(demoDeviceHeldKey{}).(func(*vmlab.AssistanceHold) error); ok {
			options.Hold = ready
		}
		if record, ok := ctx.Value(demoDeviceRegisteredKey{}).(func(context.Context, *labv1.RedHatRegistrationIdentity) error); ok {
			options.RedHatRegistered = record
		}
		return vmlab.DemoDeviceVM(ctx, manifest, options, input, stderr)
	}
	if *hold {
		options.Hold = func(access *vmlab.AssistanceHold) error {
			if *demoRoot != "" {
				access.OwnerAccessFile = filepath.Join(*demoRoot, "owner-access")
			}
			return writeAssistanceHold(stdout, *evidence, access)
		}
		if options.ControlPlane != nil {
			options.Hold = func(access *vmlab.AssistanceHold) error { return publishAssistanceHeld(*evidence, access) }
		}
		_, err := vmlab.AssistanceVM(ctx, manifest, options)
		return err
	}
	result, laneErr := vmlab.AssistanceVM(ctx, manifest, options)
	if result == nil {
		return laneErr
	}
	if options.RebootPolicy != nil {
		proof := options.RebootPolicy
		proof.Fixture = result
		proof.Passed = laneErr == nil
		if laneErr != nil {
			proof.Failure = laneErr.Error()
		}
		record := filepath.Join(*evidence, "reboot-policy.json")
		if err := writeLabEvidence(stdout, record, proof); err != nil {
			return errors.Join(laneErr, err)
		}
		return errors.Join(laneErr, os.Chmod(record, 0o400))
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
	if access.OwnerAccessFile != "" {
		path = access.OwnerAccessFile
	}
	if !access.ExistingAccount {
		if err := vmlab.WriteAssistanceOwnerAccess(path, access); err != nil {
			return err
		}
	}
	origin, err := url.Parse(access.ConsoleOrigin)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	relayAddress, controllerHost, labHost, respondDir := "localhost", "<this-host>", "<this-host>", dir
	if access.ControllerAddress != "" {
		relayAddress, controllerHost, labHost = access.ControllerAddress, "<controller-host>", "<lab-host>"
		executable, respondDir = access.RespondBinary, access.RemoteEvidenceDir
	}
	lifetime := "Ctrl-C stops lindmd and the VM and removes their state."
	if access.Persistent {
		lifetime = "Ctrl-C stops lindmd and the VM, keeping the named state; use -hold -name NAME -destroy to remove it."
	}
	owner := fmt.Sprintf("Owner enrollment: %s/enroll as %s, expires %s; the one-time secret is in %s", access.ConsoleOrigin, access.Username, access.ExpiresAt.Format(time.RFC3339), path)
	if access.ExistingAccount {
		owner = "The existing owner account remains valid; original private access: " + path
	}
	_, err = fmt.Fprintf(stdout, `Remote-assistance demo is running; %s
Console: %s (trust .cache/dev/transport-ca.crt in a dedicated browser profile)
Relay: TURN on %s port %d (UDP and TCP)
Remote browser: ssh -L %s:localhost:%s -L %d:%s:%d <user>@%s, then open the console URL; media uses TURN over TCP through the forward
%s
Device: %s (%s), GNOME Wayland, GDM autologin as %s; its password is in the same file
Guest display (TigerVNC >= 1.11, Unix socket, no TCP listener): vncviewer %s
On the lab host: %s vm assistance-respond -evidence %s {%s}
From another host: ssh <user>@%s %s vm assistance-respond -evidence %s {%s}
  allow = Allow + Share in the desktop dialog (+ Allow Remote Interaction for a Control request); decline; stop; screenshot.
Request assistance from the device page; consent is the guest user's own Allow/Decline.
`, lifetime, access.ConsoleOrigin, relayAddress, access.RelayPort, origin.Port(), origin.Port(), access.RelayPort, relayAddress, access.RelayPort, controllerHost, owner, access.Hostname, access.DeviceID, access.DesktopUser, access.DisplaySocket, executable, respondDir, strings.Join(vmlab.AssistanceRespondActions, "|"), labHost, executable, respondDir, strings.Join(vmlab.AssistanceRespondActions, "|"))
	if err == nil && access.Findings != nil {
		_, err = fmt.Fprintf(stdout, "Advisory evaluation ready: %d affected, %d accepted, %d unknown, %d clear findings (%s).\n", access.Findings.Affected, access.Findings.Accepted, access.Findings.Unknown, access.Findings.Clear, access.Findings.Freshness.GetState())
	}
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

func validateRebootPolicyFlags(enabled, held bool, name, scenarios string) error {
	if enabled && (held || name != "" || scenarios != "") {
		return errors.New("-reboot-policy requires a disposable non-held fixture and no assistance scenarios")
	}
	return nil
}
