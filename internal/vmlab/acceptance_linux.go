// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// AcceptanceGuestOptions boots one vendor image under a caller-held host lease.
// The parent keeps one real console fixture alive across sequential callbacks.
// The parent MUST acquire a labhost lease before calling RunAcceptanceGuest and
// retain it until return, after owned guest/helper teardown. Remote execution
// moves the entire parent to the selected host, not just an SSH placeholder.
type AcceptanceGuestOptions struct {
	Manifest   *labv1.ImageManifest
	Repository string
	LabBinary  string
	CacheDir   string
	WorkDir    string
	Encrypted  *EncryptedVMOptions
}

// AcceptanceGuestEvidence contains no enrollment secret, SSH key or unlock key.
// Completed means callback AND owned teardown succeeded, not physical validation.
type AcceptanceGuestEvidence struct {
	ImageID        string             `json:"image_id"`
	ImageSHA256    string             `json:"image_sha256"`
	Distribution   string             `json:"distribution"`
	Version        string             `json:"version"`
	Encrypted      bool               `json:"encrypted"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at"`
	Runtime        *vmRuntimeEvidence `json:"runtime,omitempty"`
	PackageSHA256  string             `json:"package_sha256,omitempty"`
	PackageSigner  string             `json:"package_signer,omitempty"`
	DeviceID       string             `json:"device_id,omitempty"`
	CredentialKind string             `json:"credential_kind,omitempty"`
	NativeTopology string             `json:"native_topology,omitempty"`
	ServiceEffect  bool               `json:"service_effect"`
	Completed      bool               `json:"completed"`
	Failure        string             `json:"failure,omitempty"`
}

// AcceptanceGuest is borrowed only for the RunAcceptanceGuest callback. All
// methods are sequential. It owns no authority fixture and cannot issue grants.
type AcceptanceGuest struct {
	vm         *guestVM
	manifest   *labv1.ImageManifest
	evidence   *AcceptanceGuestEvidence
	forwards   []*guestForward
	enrolled   bool
	probeReady bool
	closed     bool
	// diagnostics is the caller's private work directory for withheld guest
	// unit state when the control plane never observes the enrolled agent.
	diagnostics string
}

// RunAcceptanceGuest retains the guest through package installation, the browser
// follow-on callback, forward teardown and reaping under the caller's host lease.
// It never preconditions inventory or removes mapper nodes.
func RunAcceptanceGuest(ctx context.Context, options AcceptanceGuestOptions, visit func(context.Context, *AcceptanceGuest) error) (evidence *AcceptanceGuestEvidence, err error) {
	evidence = &AcceptanceGuestEvidence{StartedAt: time.Now().UTC()}
	defer func() {
		evidence.FinishedAt = time.Now().UTC()
		evidence.Completed = err == nil
		if err != nil {
			evidence.Failure = err.Error()
		}
	}()
	if visit == nil || options.Repository == "" || options.LabBinary == "" {
		return evidence, errors.New("acceptance requires source repository, lab binary and live-guest callback under a caller-held host lease")
	}
	m := options.Manifest
	if err := validateManifest(m); err != nil {
		return evidence, err
	}
	lane := platform.LaneAcceptance
	if options.Encrypted != nil {
		lane = platform.LaneEncryptedAcceptance
	}
	if err := platform.ForManifest(m.Distribution, m.Version).LabLane(lane); err != nil {
		return evidence, err
	}
	evidence.ImageID, evidence.ImageSHA256 = m.Id, m.Sha256
	evidence.Distribution, evidence.Version = m.Distribution, m.Version
	evidence.Encrypted = options.Encrypted != nil
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	g := &AcceptanceGuest{manifest: m, evidence: evidence, diagnostics: options.WorkDir}
	hardware := VMHardwareOptions{StorageBus: "virtio-blk", AllowNetwork: true, stockAcceptance: true}
	if options.Encrypted != nil {
		opts := *options.Encrypted
		// No desktop additions, extra disks or TPM-stack preconditioning.
		if opts.Desktop != "" || opts.TPMBoot || (opts.Hardware != nil && (opts.Hardware.ExtraDisks != 0 || opts.Hardware.Desktop || (opts.Hardware.StorageBus != "" && opts.Hardware.StorageBus != "virtio-blk"))) {
			return evidence, errors.New("encrypted acceptance forbids desktop, extra disks, TPM-stack and alternate storage preconditioning")
		}
		if opts.Hardware != nil {
			hardware.Architecture, hardware.Accelerator, hardware.TPM = opts.Hardware.Architecture, opts.Hardware.Accelerator, opts.Hardware.TPM
		}
		opts.CacheDir, opts.WorkDir, opts.Hardware = options.CacheDir, options.WorkDir, &hardware
		vm, openErr := NewEncryptedVM(ctx, m, opts)
		if openErr != nil {
			return evidence, openErr
		}
		defer func() { err = errors.Join(err, vm.Close()) }()
		boot, bootErr := vm.ColdBoot(ctx, vm.InitialUnlockSecret())
		if bootErr != nil {
			return evidence, bootErr
		}
		if !boot.Accepted || boot.BootID == "" {
			return evidence, errors.New("encrypted acceptance did not observe an unlocked boot")
		}
		g.vm = vm.guest
	} else {
		vm, _, openErr := newVerifiedGuestWithHardware(ctx, m, options.CacheDir, options.WorkDir, true, &hardware)
		if openErr != nil {
			return evidence, openErr
		}
		defer func() { err = errors.Join(err, vm.close()) }()
		g.vm = vm
		if err := vm.connect(ctx); err != nil {
			return evidence, err
		}
		if _, err := vm.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
			return evidence, fmt.Errorf("stock cloud-init readiness: %w", err)
		}
	}
	defer func() {
		g.closed = true
		err = errors.Join(err, closeLifecycleForwards(g.forwards))
	}()
	evidence.Runtime, err = g.vm.runtimeEvidence(ctx)
	if err != nil {
		return evidence, err
	}
	if evidence.Encrypted {
		evidence.Runtime.SeedDisk = false
	}
	if err := g.observeTopology(ctx); err != nil {
		return evidence, err
	}
	pkg, err := buildActionNativePackage(ctx, m, options.Repository, options.WorkDir)
	if err != nil {
		return evidence, err
	}
	defer func() { err = errors.Join(err, pkg.Close()) }()
	if err := pkg.Install(ctx, g.vm, options.LabBinary); err != nil {
		return evidence, err
	}
	evidence.PackageSHA256, evidence.PackageSigner = pkg.artifact.SHA256, pkg.fingerprint
	if err := visit(ctx, g); err != nil {
		return evidence, err
	}
	if !g.enrolled {
		return evidence, errors.New("acceptance callback did not enroll through the documented customer CLI")
	}
	return evidence, g.observeTopology(ctx)
}

// Run executes a bounded native command for independent observation, never as a
// replacement for a profile effect. Input is private SSH stdin, not evidence.
func (g *AcceptanceGuest) Run(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	if g.closed || g.vm == nil {
		return nil, errors.New("acceptance guest is closed")
	}
	return g.vm.run(ctx, command, input, maxGuestOutput, 5*time.Minute)
}

// Forward preserves end-to-end TLS to an existing fixture listener. Both ends
// are literal loopback; the listener is owned until the callback exits.
func (g *AcceptanceGuest) Forward(ctx context.Context, guestAddress, hostAddress string) (string, error) {
	if g.closed || g.vm == nil {
		return "", errors.New("acceptance guest is closed")
	}
	forward, err := newGuestForward(ctx, g.vm, guestAddress, hostAddress)
	if err != nil {
		return "", err
	}
	g.forwards = append(g.forwards, forward)
	return forward.Addr(), nil
}

func (g *AcceptanceGuest) observeTopology(ctx context.Context) error {
	// Read-only native proof: dm nodes must remain real block devices. Never
	// delete /dev/dm-* to make lsblk or identity projection appear simpler.
	command := `set -eu
 test -b /dev/vda
 case "$(readlink -f /sys/class/block/vda/device)" in */virtio*) ;; *) exit 1;; esac
 test -z "$(lsblk --nodeps --noheadings --output WWN /dev/vda | tr -d '[:space:]')"
 for node in /sys/class/block/dm-*; do
  test -e "$node" || continue
  test -b "/dev/${node##*/}"
 done
 lsblk --pairs --output NAME,KNAME,PKNAME,TYPE,SIZE,WWN,SERIAL,FSTYPE,MOUNTPOINT
`
	data, err := g.vm.run(ctx, "sudo -n sh -eu -c "+nativeQuote(command), nil, 1<<20, time.Minute)
	if err != nil {
		return fmt.Errorf("acceptance virtio-blk/no-WWN topology: %w", err)
	}
	if g.evidence.Encrypted {
		root, err := g.vm.run(ctx, `sudo -n sh -eu -c 'root=$(findmnt -n -o SOURCE /); root=${root%%\[*}; lsblk --inverse --noheadings --output TYPE "$root"'`, nil, 16<<10, time.Minute)
		if err != nil {
			return err
		}
		found := false
		for _, kind := range strings.Fields(string(root)) {
			found = found || kind == "crypt"
		}
		if !found {
			return errors.New("acceptance root does not retain an encrypted mapper ancestor")
		}
	}
	g.evidence.NativeTopology = string(data)
	return nil
}
