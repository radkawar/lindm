//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"lindm/internal/devlab"
	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

func runHosts(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "baseline-browser" {
		return runBrowserBaseline(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "baseline" {
		return runHostsBaseline(ctx, args[1:], stdout, stderr)
	}
	if len(args) != 0 {
		return errors.New("usage: lab hosts; lab hosts baseline -host NAME [-record NEW_FILE]; lab hosts baseline-browser [-host NAME] [-record NEW_FILE]")
	}
	cfg, err := labhost.Load()
	if err != nil {
		return err
	}
	statuses := make([]labhost.Status, len(cfg.Hosts))
	var pending sync.WaitGroup
	for i, host := range cfg.Hosts {
		pending.Go(func() { statuses[i] = labhost.InspectHost(ctx, host) })
	}
	pending.Wait()
	out := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if _, err = fmt.Fprintln(out, "NAME\tTRANSPORT\tREACHABLE\tARCHITECTURES\tKVM\tLEASES\tGUESTS\tFREE\tLIMIT\tRUNTIME"); err != nil {
		return err
	}
	for i, host := range cfg.Hosts {
		status := statuses[i]
		if _, err = fmt.Fprintf(out, "%s\t%s\t%t\t%s\t%t\t%d\t%d\t%d\t%d\t%s\n", host.Name, host.Transport, status.Reachable, strings.Join(host.Architectures, ","), status.KVM, status.ActiveLeases, status.Guests, status.Free, host.MaxGuests, host.Runtime); err != nil {
			return err
		}
		if status.Error != "" {
			if _, err = fmt.Fprintf(stderr, "%s: %s\n", host.Name, status.Error); err != nil {
				return err
			}
		}
	}
	return out.Flush()
}

// runScheduledVM is the only public CLI admission path. Lanes keep their existing
// resource requests; configuration is a ceiling, never an implicit resize.
func runScheduledVM(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
	defer cancel()
	name, arch := "", ""
	clean := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		key, value, hasValue := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if (key == "host" || key == "arch") && strings.HasPrefix(args[i], "-") {
			if !hasValue {
				i++
				if i >= len(args) {
					return fmt.Errorf("-%s requires a value", key)
				}
				value = args[i]
			}
			if value == "" {
				return fmt.Errorf("-%s requires a value", key)
			}
			if key == "host" {
				if name != "" {
					return errors.New("duplicate -host")
				}
				name = value
			} else {
				if arch != "" {
					return errors.New("duplicate -arch")
				}
				arch = value
			}
			continue
		}
		clean = append(clean, args[i])
	}
	manifestPath := labhost.FlagValue(clean, "manifest")
	if manifestPath == "" {
		return runUnscheduled(ctx, clean, stdout, stderr)
	}
	manifest, err := vmlab.LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	manifestArch, err := labhost.NormalizeArchitecture(manifest.Architecture)
	if err != nil {
		return err
	}
	if arch != "" {
		arch, err = labhost.NormalizeArchitecture(arch)
		if err != nil {
			return err
		}
		if arch != manifestArch {
			return errors.New("-arch must match the pinned image manifest architecture")
		}
	} else {
		arch = manifestArch
	}
	memory := uint32(2048)
	if clean[1] == "encrypted" || clean[1] == "inspect-storage" || clean[1] == "device-actions" || clean[1] == "assistance" {
		memory = 4096
	}
	cfg, err := labhost.Load()
	if err != nil {
		return err
	}
	requirements := &labhost.Requirements{Host: name, Architecture: arch, Vcpus: 2, MemoryMib: memory, RequireKVM: !vmHasHardwareFlags(clean[1]) || labhost.FlagValue(clean, "accelerator") == "kvm"}
	candidates, err := labhost.Select(cfg, requirements)
	if err != nil {
		return err
	}
	chosen := candidates[0]
	var failures []error
	found := false
	for _, candidate := range candidates {
		status := labhost.InspectHost(ctx, candidate)
		if !status.Reachable {
			failures = append(failures, fmt.Errorf("host %s: %s", candidate.Name, status.Error))
			continue
		}
		if !found {
			chosen = candidate
			found = true
		}
		if status.Free > 0 {
			chosen = candidate
			break
		}
	}
	if !found {
		return errors.Join(failures...)
	}
	if vmHasHardwareFlags(clean[1]) && labhost.FlagValue(clean, "accelerator") == "" {
		accelerator := "tcg"
		for _, native := range chosen.Architectures {
			if native == arch && chosen.Kvm {
				accelerator = "kvm"
			}
		}
		clean = labhost.SetFlag(clean, "accelerator", accelerator)
	}
	if _, err = fmt.Fprintf(stderr, "lab host %s (%s), guest %s, capacity %d\n", chosen.Name, chosen.Transport, arch, chosen.MaxGuests); err != nil {
		return err
	}
	if chosen.Transport == "ssh" || chosen.Runtime == "container" {
		repo := labhost.FlagValue(clean, "repo")
		if repo == "" {
			repo = "."
		}
		if buildRepo := labhost.FlagValue(clean, "build-repo"); buildRepo != "" {
			repo = buildRepo
		}
		return (labhost.RemoteRun{Host: chosen, Architecture: arch, Repository: repo, Args: clean, Stdout: stdout, Stderr: stderr}).Run(ctx)
	}
	slots, err := labhost.OpenSlots(chosen)
	if err != nil {
		return err
	}
	workFlag := "work-dir"
	if clean[1] == "enroll-unattended" {
		workFlag = "work"
	}
	if labhost.FlagValue(clean, workFlag) == "" {
		work, err := labhost.ResolveWorkDirectory(chosen)
		if err != nil {
			return err
		}
		clean = labhost.SetFlag(clean, workFlag, work)
	}
	leases, err := acquireLaneLeases(ctx, slots, vmGuestCount(clean[1], clean))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeLaneLeases(leases)) }()
	return runUnscheduled(ctx, clean, stdout, stderr)
}

func vmHasHardwareFlags(command string) bool {
	switch command {
	case "inspect", "inspect-storage", "lifecycle", "dispatch", "resources", "encrypted", "device-actions", "assistance":
		return true
	default:
		// These lanes retain their existing fixed native-KVM hardware contract.
		return false
	}
}

// vmGuestCount is the number of concurrent guests a lane boots. The firewall
// resource lane adds an independent probe-peer guest beside the device; every
// guest holds its own capacity slot for the lane's whole lifetime.
func vmGuestCount(lane string, args []string) int {
	if lane == "resources" && slices.Contains(strings.Split(labhost.FlagValue(args, "kinds"), ","), "firewall") {
		return 2
	}
	return 1
}

// acquireLaneLeases holds one capacity slot per concurrent lane guest until
// every guest has exited. A partial reservation is released on failure.
func acquireLaneLeases(ctx context.Context, slots *labhost.Slots, guests int) ([]*labhost.Lease, error) {
	leases := make([]*labhost.Lease, 0, guests)
	for range guests {
		lease, err := slots.Acquire(ctx)
		if err != nil {
			return nil, errors.Join(err, closeLaneLeases(leases))
		}
		leases = append(leases, lease)
	}
	return leases, nil
}

func closeLaneLeases(leases []*labhost.Lease) error {
	var err error
	for _, lease := range leases {
		err = errors.Join(err, lease.Close())
	}
	return err
}

// runHostExec is the staged binary's internal entrypoint. It takes the remote
// flock itself and watches the SSH stdin lifetime, so disconnect does not free a
// slot while a detached VM continues running. QEMU helpers also use Pdeathsig.
func runHostExec(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	if len(args) < 4 || args[1] != "vm" {
		return errors.New("invalid internal host-exec invocation")
	}
	cfg, err := labhost.LoadFile(args[0])
	if err != nil {
		return err
	}
	if len(cfg.Hosts) != 1 {
		return errors.New("host-exec requires exactly one host")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
	defer cancel()
	// Reopen as a pollable descriptor: closing a plain blocking inherited stdin
	// does not necessarily interrupt a concurrent read in the operating system.
	lifetime, err := os.OpenFile("/proc/self/fd/0", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(io.Discard, lifetime); cancel() }()
	defer func() { err = errors.Join(err, lifetime.Close()); <-done }()
	slots, err := labhost.OpenSlots(cfg.Hosts[0])
	if err != nil {
		return err
	}
	leases, err := acquireLaneLeases(ctx, slots, vmGuestCount(args[2], args))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeLaneLeases(leases)) }()
	lane := args[2]
	work, err := labhost.ResolveWorkDirectory(cfg.Hosts[0])
	if err != nil {
		return err
	}
	persistentCache := filepath.Join(work, "images")
	for _, name := range []string{"manifest", "recovery-manifest"} {
		path := labhost.FlagValue(args, name)
		if path == "" {
			continue
		}
		manifest, err := vmlab.LoadManifest(path)
		if err != nil {
			return err
		}
		if _, err := vmlab.ImportCache(ctx, manifest, labhost.FlagValue(args, "cache"), persistentCache); err != nil {
			return err
		}
	}
	args = labhost.SetFlag(args, "cache", persistentCache)
	if lane == "dispatch" || lane == "resources" || lane == "device-actions" || lane == "updates" || lane == "enroll-unattended" || lane == "lifecycle" {
		repo := labhost.FlagValue(args, "repo")
		if repo == "" {
			return errors.New("remote control-plane lane requires staged -repo")
		}
		repo, err = filepath.Abs(repo)
		if err != nil {
			return err
		}
		dependencies, e := devlab.OpenRemoteLabDependencies(ctx, repo)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, dependencies.Close()) }()
	}
	return runUnscheduled(ctx, args[1:], stdout, stderr)
}
