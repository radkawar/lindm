//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

// packageVendorBusyScenario is the connected package scenario for releases
// whose vendor ships a background updater (platform.LabUpdater).
const packageVendorBusyScenario = "vendor-updater-native-busy"

// exercisePackageVendorBusy re-enables the vendor's own updater, which the lab
// otherwise masks, makes it run a full update through the native frontend, and
// assigns a package change while that updater holds dpkg's frontend lock. The
// device must refuse the change visibly as a retryable native-busy hold before
// any effect, never an unknown outcome. The updater needs guest egress to the
// vendor archive (-allow-network) to hold the lock long enough to be observed.
// Afterwards it waits for the updater to finish and masks it again.
func exercisePackageVendorBusy(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, updater platform.LabUpdater, evidence *VMResourceKindEvidence) (err error) {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: packageVendorBusyScenario, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	defer func() {
		if err != nil {
			s.Failure = err.Error()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Minute)
	defer cancel()
	unit := nativeQuote(updater.Unit)
	start, err := resourceOracle(ctx, r.vm, "vendor-updater-start", "systemctl unmask "+unit+"; systemctl start "+unit+"; systemctl is-active "+unit+"; "+updater.Trigger)
	if err != nil {
		return err
	}
	s.Native = append(s.Native, start)
	var holder string
	for {
		if holder, err = dpkgFrontendHolder(ctx, r.vm); err != nil {
			return err
		}
		if strings.HasPrefix(holder, "holder ") {
			break
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return fmt.Errorf("vendor updater never held the dpkg frontend lock (it needs -allow-network egress to its archive): %w", err)
		}
	}
	if strings.Contains(holder, "lindm") {
		return fmt.Errorf("dpkg frontend lock is held by lindm, not the vendor updater: %s", holder)
	}
	s.Native = append(s.Native, resourceNativeRecord("vendor-updater-lock-holder", []byte(holder+"\n")))
	assigned := time.Now().UTC()
	if err := r.assign(ctx, resourcePackageDesired(rpm, "2.0", true), resourceCreatePolicy()); err != nil {
		return err
	}
	for s.Action == nil {
		state, err := r.control.dispatchState(ctx, r.device)
		if err != nil {
			return err
		}
		for _, resource := range state.GetResources() {
			action := resource.GetLatestAction()
			if action.GetClosedAt() == nil || action.GetIssuedAt().AsTime().Before(assigned) {
				continue
			}
			s.Action = action
			if action.GetStatus().GetStartedAt() != nil {
				return fmt.Errorf("package change consumed its effect gate while the vendor updater held dpkg: %s", action)
			}
			if action.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || action.GetStatus().GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY ||
				resource.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED || resource.GetReason() != releaseUpgradeBusyReason {
				return fmt.Errorf("package change during the vendor updater's dpkg lock was not an explicit native-busy hold: %s %q %s", resource.GetDisposition(), resource.GetReason(), action.GetStatus())
			}
		}
		if s.Action == nil {
			if err := lifecycleDelay(ctx, 2*time.Second); err != nil {
				return fmt.Errorf("package change outcome was not recorded while the vendor updater held dpkg: %w", err)
			}
		}
	}
	after, err := dpkgFrontendHolder(ctx, r.vm)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(after, "holder ") {
		return errors.New("package action closed after the vendor updater released dpkg; collision not proven")
	}
	unchanged, err := packageOracle(ctx, r.vm, rpm, "1.0", true)
	if err != nil {
		return err
	}
	s.Native = append(s.Native, unchanged)
	for {
		state, err := dpkgFrontendHolder(ctx, r.vm)
		if err != nil {
			return err
		}
		if state == "free" {
			break
		}
		if err := lifecycleDelay(ctx, 5*time.Second); err != nil {
			return fmt.Errorf("vendor updater did not release the dpkg frontend lock: %w", err)
		}
	}
	stop, err := resourceOracle(ctx, r.vm, "vendor-updater-stop", "systemctl stop "+unit+"; systemctl mask "+unit+"; systemctl is-enabled "+unit+" || true")
	if err != nil {
		return err
	}
	s.Native = append(s.Native, stop)
	s.FinishedAt, s.Passed = time.Now().UTC(), true
	return nil
}

// dpkgFrontendHolder reports "holder PID CMDLINE" or "free" for dpkg's
// frontend lock.
func dpkgFrontendHolder(ctx context.Context, vm *guestVM) (string, error) {
	data, err := vm.run(ctx, "sudo -n /bin/sh -eu -c "+nativeQuote(releaseUpgradeLockCommand), nil, 4<<10, 15*time.Second)
	if err != nil {
		return "", fmt.Errorf("observe dpkg frontend lock: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
