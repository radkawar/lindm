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

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/labhost"
	"lindm/internal/redhatimages"
)

// demoDestroy removes a stopped organization demo through its saved bindings.
// A device whose SSH host is unreachable keeps its VM and device root for a
// later destroy, while its controller-recorded RHSM consumer is removed by
// exact UUID and run name; the controller then retains its state, fixture and
// owner access and refuses to resume the demo.
type demoDestroy struct {
	options demoOptions
	root    string
	stdout  io.Writer
	// probe classifies an SSH host as reachable or labhost.ErrHostUnreachable.
	probe func(context.Context, *labv1.LabHost) error
	// device destroys one device on its host, including the RHSM consumer
	// recorded in the device root's receipt.
	device func(context.Context, *labv1.DemoBinding) error
	// removeSystem is redhatimages.Client.RemoveSystem.
	removeSystem func(ctx context.Context, uuid, name string) (redhatimages.SystemRemoval, error)
	// controller removes the controller's fixture and demo root.
	controller func(context.Context) error
}

func destroyOrganizationDemo(ctx context.Context, options demoOptions, root string, stdout, stderr io.Writer) error {
	var client *redhatimages.Client
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	destroy := &demoDestroy{
		options: options, root: root, stdout: stdout,
		probe: labhost.ProbeSSH,
		device: func(ctx context.Context, bound *labv1.DemoBinding) error {
			if bound.Host.GetTransport() == "ssh" {
				args := []string{"vm", "assistance", "-hold", "-name", bound.DemoName, "-demo-parent", options.name, "-destroy"}
				// The device host removes a recorded RHSM consumer before its VM.
				if options.redhatToken != "" {
					args = labhost.SetFlag(args, "redhat-token-file", options.redhatToken)
				}
				return labhost.RemoteRun{Host: bound.Host, Repository: options.build, Args: args, Stdout: stdout, Stderr: stderr}.Run(ctx)
			}
			work, err := labhost.ResolveWorkDirectory(bound.Host)
			if err != nil {
				return err
			}
			deviceRoot, err := labhost.DemoDirectory(work, bound.DemoName)
			if err != nil {
				return err
			}
			return destroyOrganizationDevice(ctx, options.repository, deviceRoot, options.name, options.redhatToken, stdout)
		},
		removeSystem: func(ctx context.Context, uuid, name string) (redhatimages.SystemRemoval, error) {
			if client == nil {
				opened, err := redhatimages.New(ctx, options.redhatToken)
				if err != nil {
					return redhatimages.SystemRemoval{UUID: uuid}, err
				}
				client = opened
			}
			return client.RemoveSystem(ctx, uuid, name)
		},
		controller: func(ctx context.Context) error {
			if err := devlab.DestroyPersistentFixture(ctx, options.repository, filepath.Join(root, "control-plane")); err != nil {
				return err
			}
			return os.RemoveAll(root)
		},
	}
	return destroy.run(ctx)
}

// run destroys every reachable device, then the controller once no device
// remains. Host cleanup left pending on an unreachable host is reported with
// the command that finishes it and is not a failure; an unremovable recorded
// consumer, an unconfirmed or unrecorded registration on an unreachable host,
// and any failed host or controller step are.
func (d *demoDestroy) run(ctx context.Context) error {
	if _, err := os.Lstat(d.root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := openAssistanceDemoRoot(d.root); err != nil {
		return err
	}
	state, err := readDemoState(d.root)
	if err != nil {
		return err
	}
	if !state.GetRecordsRedhatRegistrations() {
		if _, err := fmt.Fprintf(d.stdout, "Organization demo %s predates controller Red Hat records: only each device host's receipt records its RHSM consumer, so that host must be reachable to remove it.\n", d.options.name); err != nil {
			return err
		}
	}
	probes := make(map[string]error)
	var pending []*labv1.DemoBinding
	var failures []error
	for _, bound := range state.Bindings {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		host := bound.GetHost()
		if host.GetTransport() == "ssh" {
			probe, seen := probes[host.GetName()]
			if !seen {
				probe = d.probe(ctx, host)
				probes[host.GetName()] = probe
			}
			if errors.Is(probe, labhost.ErrHostUnreachable) {
				pending = append(pending, bound)
				if err := d.unregisterUnreachable(ctx, state, bound); err != nil {
					failures = append(failures, fmt.Errorf("device %s: %w", bound.GetKey(), err))
				}
				continue
			}
			if probe != nil {
				failures = append(failures, fmt.Errorf("device %s: %w", bound.GetKey(), probe))
				continue
			}
		}
		if err := d.device(ctx, bound); err != nil {
			failures = append(failures, fmt.Errorf("destroy device %s on %s: %w", bound.GetKey(), host.GetName(), err))
		}
	}
	if len(pending) == 0 {
		if len(failures) != 0 {
			return errors.Join(failures...)
		}
		if err := d.controller(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(d.stdout, "Destroyed organization demo:", d.options.name)
		return err
	}
	if !state.GetDestroying() {
		state.Destroying = true
		if err := writeDemoState(d.root, state); err != nil {
			return errors.Join(append(failures, err)...)
		}
	}
	return errors.Join(append(failures, d.reportPending(pending))...)
}

// unregisterUnreachable removes an unreachable device's controller-recorded
// RHSM consumer by exact UUID and run name and records its observed absence.
// It never resolves a consumer by name or hostname.
func (d *demoDestroy) unregisterUnreachable(ctx context.Context, state *labv1.DemoState, bound *labv1.DemoBinding) error {
	host := bound.GetHost().GetName()
	registration := bound.GetRedhatRegistration()
	switch {
	case registration == nil && !state.GetRecordsRedhatRegistrations():
		return fmt.Errorf("host %s is unreachable and the controller holds no Red Hat record for this device; any RHSM consumer is recorded only in its receipt on %s, so destroy again once %s is reachable", host, host, host)
	case registration == nil:
		// Never registered: only host cleanup remains.
		return nil
	case registration.GetConsumerUuid() == "":
		return fmt.Errorf("recorded Red Hat registration %s has no consumer UUID (lost registration reply or unrecorded consumer) and is never resolved by name or hostname; destroy again once %s is reachable to use its device receipt, or remove it with lab images redhat cleanup", registration.GetRunName(), host)
	case registration.GetRemoved():
		_, err := fmt.Fprintf(d.stdout, "Device %s: Red Hat system %s (%s) was already removed from controller records\n", bound.GetKey(), registration.GetConsumerUuid(), registration.GetRunName())
		return err
	case d.options.redhatToken == "":
		return fmt.Errorf("host %s is unreachable; removing recorded Red Hat system %s (%s) requires -redhat-token-file", host, registration.GetConsumerUuid(), registration.GetRunName())
	}
	removal, err := d.removeSystem(ctx, registration.GetConsumerUuid(), registration.GetRunName())
	if err != nil {
		return fmt.Errorf("remove recorded Red Hat system %s (%s): %w", registration.GetConsumerUuid(), registration.GetRunName(), err)
	}
	if removal.UUID != registration.GetConsumerUuid() || !removal.Absent {
		return fmt.Errorf("recorded Red Hat system %s (%s) was not observed absent", registration.GetConsumerUuid(), registration.GetRunName())
	}
	registration.Removed = true
	state.Destroying = true
	if err := writeDemoState(d.root, state); err != nil {
		return err
	}
	_, err = fmt.Fprintf(d.stdout, "Unregistered Red Hat system %s (%s) from controller records while %s is unreachable: deleted=%t absent=%t\n", removal.UUID, registration.GetRunName(), host, removal.Deleted, removal.Absent)
	return err
}

// reportPending names every device whose host cleanup remains and the exact
// command that finishes the destroy once its host is reachable.
func (d *demoDestroy) reportPending(pending []*labv1.DemoBinding) error {
	var hosts []string
	for _, bound := range pending {
		host := bound.GetHost().GetName()
		if !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
		if _, err := fmt.Fprintf(d.stdout, "Pending host cleanup: device %s (%s) on unreachable host %s keeps its VM and device root\n", bound.GetKey(), bound.GetDemoName(), host); err != nil {
			return err
		}
	}
	command, err := d.command()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(d.stdout, "Organization demo %s is NOT fully destroyed: its controller state, fixture and owner access are retained and it cannot be resumed. When %s is reachable, finish with: %s\n", d.options.name, strings.Join(hosts, ", "), command)
	return err
}

// command is the destroy invocation that finishes this one.
func (d *demoDestroy) command() (string, error) {
	binary, err := os.Executable()
	if err != nil {
		return "", err
	}
	repository, err := filepath.Abs(d.options.repository)
	if err != nil {
		return "", err
	}
	build, err := filepath.Abs(d.options.build)
	if err != nil {
		return "", err
	}
	args := []string{binary, "demo", "-name", d.options.name, "-destroy", "-repo", repository, "-build-repo", build}
	if d.options.redhatToken != "" {
		args = append(args, "-redhat-token-file", d.options.redhatToken)
	}
	return strings.Join(args, " "), nil
}
