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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
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
	if len(clean) >= 2 && clean[1] == "assistance" && assistanceFlag(clean, "destroy") {
		return runDestroyNamedAssistance(ctx, clean, name, stdout, stderr)
	}
	if demoName := labhost.FlagValue(clean, "name"); len(clean) >= 2 && clean[1] == "assistance" && demoName != "" {
		root, rootErr := controllerDemoDirectory(demoName)
		if rootErr != nil {
			return rootErr
		}
		lock, lockErr := lockAssistanceDemo(root)
		if lockErr != nil {
			return lockErr
		}
		defer func() { err = errors.Join(err, lock.Close()) }()
		ctx = context.WithValue(ctx, assistanceDemoLockKey{}, root)
	}
	name, err = namedAssistanceHost(clean, name)
	if err != nil {
		return err
	}
	held := vmHolds(clean)
	manifestPath := labhost.FlagValue(clean, "manifest")
	if manifestPath == "" {
		if timing := laneTiming(held); timing.Lane > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timing.Lane)
			defer cancel()
		}
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
	if clean[1] == "snapshot" || clean[1] == "encrypted" || clean[1] == "inspect-storage" || clean[1] == "device-actions" || clean[1] == "assistance" {
		memory = 4096
	}
	cfg, err := labhost.Load()
	if err != nil {
		return err
	}
	requirements := &labhost.Requirements{Host: name, Architecture: arch, Vcpus: 2, MemoryMib: memory, RequireKVM: vmRequiresKVM(cfg, clean[1], labhost.FlagValue(clean, "accelerator"), arch)}
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
	if held && chosen.Runtime == "container" {
		return errors.New("a held lane requires a native lab host")
	}
	if err := bindAssistanceHost(clean, chosen); err != nil {
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
		if splitAssistance(chosen, clean) {
			return runSplitAssistance(ctx, chosen, arch, repo, clean, stdout, stderr)
		}
		var forwards []string
		if clean[1] == "enroll-from-console" && chosen.Transport == "ssh" {
			forwards, err = consoleEnrollmentReverseForwards(clean)
			if err != nil {
				return err
			}
		}
		return (labhost.RemoteRun{Host: chosen, Architecture: arch, Repository: repo, Args: clean, Hold: held, ReverseForwards: forwards, Stdout: stdout, Stderr: stderr}).Run(ctx)
	}
	if demoName := labhost.FlagValue(clean, "name"); clean[1] == "assistance" && demoName != "" {
		work, err := labhost.ResolveWorkDirectory(chosen)
		if err != nil {
			return err
		}
		root, err := labhost.DemoDirectory(work, demoName)
		if err != nil {
			return err
		}
		clean = labhost.SetFlag(clean, "demo-root", root)
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
	if held && labhost.FlagValue(clean, "advisory-cache") == "" {
		work, err := labhost.ResolveWorkDirectory(chosen)
		if err != nil {
			return err
		}
		clean = labhost.SetFlag(clean, "advisory-cache", filepath.Join(work, "advisory-cache"))
	}
	return slots.RunAdmitted(ctx, vmGuestCount(clean[1], clean), laneTiming(held), laneWaitReporter(stderr, chosen.Name), func(ctx context.Context) error {
		return runUnscheduled(ctx, clean, stdout, stderr)
	})
}

// laneTiming queues a lane for at most 12h and then gives it its full 3h; a
// held assistance lane keeps its lease until interrupted.
func laneTiming(held bool) labhost.LaneTiming {
	timing := labhost.LaneTiming{Admission: 12 * time.Hour, Lane: 3 * time.Hour}
	if held {
		timing.Lane = 0
	}
	return timing
}

func laneWaitReporter(stderr io.Writer, host string) func(string) {
	return func(reason string) {
		_, _ = fmt.Fprintf(stderr, "lab host %s: waiting for admission: %s\n", host, reason)
	}
}

// vmHolds reports a hands-on assistance lane that keeps its native host lease
// until interrupted, without a lane deadline.
func vmHolds(args []string) bool {
	held := false
	if len(args) < 2 || args[1] != "assistance" {
		return false
	}
	for _, arg := range args[2:] {
		name, value, explicit := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
		if !strings.HasPrefix(arg, "-") || name != "hold" {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		held = !explicit || (err == nil && parsed)
	}
	return held
}

func vmHasHardwareFlags(command string) bool {
	switch command {
	case "snapshot", "inspect", "inspect-storage", "lifecycle", "dispatch", "resources", "services", "encrypted", "device-actions", "assistance", "enroll-from-console", "updates", "advisories":
		return true
	default:
		// These lanes retain their existing fixed native-KVM hardware contract.
		return false
	}
}

// vmRequiresKVM keeps acceleration a lane decision, not a capacity fallback.
// A full native host must be waited for rather than replaced by a foreign
// TCG host. Lanes whose own -accelerator default is kvm are KVM-only unless
// explicitly told otherwise; architecture-defaulted lanes use TCG only when no
// configured host runs that architecture natively.
func vmRequiresKVM(cfg *labv1.LabConfig, command, accelerator, architecture string) bool {
	if !vmHasHardwareFlags(command) {
		return true
	}
	switch command {
	case "encrypted", "inspect-storage", "device-actions", "assistance":
		if accelerator == "" {
			accelerator = "kvm"
		}
	}
	if accelerator != "" {
		return accelerator == "kvm"
	}
	for _, host := range cfg.GetHosts() {
		if host.GetKvm() && slices.Contains(host.GetArchitectures(), architecture) {
			return true
		}
	}
	return false
}

// vmGuestCount is the number of concurrent guests a lane boots. The firewall
// resource lane adds an independent probe-peer guest beside the device; every
// guest holds its own capacity slot for the lane's whole lifetime.
func vmGuestCount(lane string, args []string) uint32 {
	if lane == "resources" && slices.Contains(strings.Split(labhost.FlagValue(args, "kinds"), ","), "firewall") {
		return 2
	}
	return 1
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
	ctx, cancel := context.WithCancel(ctx)
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
	return slots.RunAdmitted(ctx, vmGuestCount(args[2], args), laneTiming(vmHolds(args[1:])), laneWaitReporter(stderr, cfg.Hosts[0].Name), func(ctx context.Context) error {
		return runAdmittedHostExec(ctx, args, stdout, stderr, cfg.Hosts[0])
	})
}

func runAdmittedHostExec(ctx context.Context, args []string, stdout, stderr io.Writer, host *labv1.LabHost) (err error) {
	lane := args[2]
	work, err := labhost.ResolveWorkDirectory(host)
	if err != nil {
		return err
	}
	if name := labhost.FlagValue(args, "name"); lane == "assistance" && name != "" {
		root, err := labhost.DemoDirectory(work, name)
		if err != nil {
			return err
		}
		args = labhost.SetFlag(args, "demo-root", root)
		if assistanceFlag(args, "destroy") {
			return runUnscheduled(ctx, args[1:], stdout, stderr)
		}
	}
	// Ubuntu installs /boot kernels root-only; header oracles use the
	// baseline's private packaged copy of the running kernel instead.
	if err := labhost.ExportSuperminEnvironment(work); err != nil {
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
	if lane == "snapshot" {
		args = labhost.SetFlag(args, "snapshot-cache", persistentCache)
	}
	if lane == "assistance" && vmHolds(args[1:]) && labhost.FlagValue(args, "advisory-cache") == "" {
		args = labhost.SetFlag(args, "advisory-cache", filepath.Join(work, "advisory-cache"))
	}
	if (lane == "dispatch" || lane == "resources" || lane == "device-actions" || lane == "updates" || lane == "enroll-unattended" || lane == "lifecycle" || lane == "assistance" || lane == "advisories") && labhost.FlagValue(args, "control-plane") == "" {
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
