//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// exerciseRollingOSUpdate uses the same signed resource dispatch, owned timer,
// durable journal and reboot boundary as the fixed-release policy lane. It never
// substitutes security package selection for a rolling whole-system upgrade.
func exerciseRollingOSUpdate(ctx context.Context, r *resourceDispatch, packages resourcePackaging, evidence *VMResourceKindEvidence) error {
	// Prerequisites were provisioned at the image's snapshot; the policy must
	// target a later registry pin or the window transaction changes nothing.
	if r.awaitReboot == nil || r.rollingSnapshot == nil || r.osUpdateTarget == nil {
		return errors.New("rolling update qualification requires a later os-update target snapshot pin and reboot boundary")
	}
	zone, err := time.LoadLocation(osUpdateLabZone)
	if err != nil {
		return err
	}
	if err := enableOSUpdateProvider(ctx, r.vm); err != nil {
		return err
	}
	baseline, err := osUpdateConfigOracle(packages)(ctx, r.vm)
	if err != nil {
		return err
	}
	names := []string{"partial-rolling-selection-refused", "policy-installs-window-timer", "start-outside-window-skipped", "window-installs-whole-system-snapshot", "scheduled-reboot-executes", "interrupted-transaction-recovery-hold", "repeat-after-recovery", "release-removes-policy"}
	// A schema-valid security-only policy is refused by the selected native
	// model before it can own files or replace an administrator's scheduler.
	partial := osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY, osUpdateWindowStart(time.Now()), 0)
	if err := resourceRefusalStep(ctx, r, evidence, names[0], partial, resourceCreatePolicy(), withVM(r.vm, osUpdateConfigOracle(packages))); err != nil {
		return err
	}
	r.fresh()
	start := osUpdateWindowStart(time.Now())
	desired := osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, start, 0)
	desired.GetOsUpdate().RollingSnapshot = proto.CloneOf(r.osUpdateTarget)
	if err := resourceStep(ctx, r, evidence, names[1], desired, resourceCreatePolicy(), false, withVM(r.vm, osUpdateInstalledOracle(packages, zone, start))); err != nil {
		return err
	}
	if err := osUpdateOutsideWindow(ctx, r, packages, evidence, start); err != nil {
		return err
	}
	if err := rollingWindowAndReboot(ctx, r, packages, evidence, start); err != nil {
		return err
	}
	// The package transaction is allowed to finish beyond the original
	// window. Open a fresh, signed window for the recovery-hold probe.
	start = time.Now().Add(-time.Minute).Truncate(time.Minute)
	desired = osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, start, 0)
	desired.GetOsUpdate().RollingSnapshot = proto.CloneOf(r.osUpdateTarget)
	if err := resourceStep(ctx, r, evidence, "policy-reconciles-recovery-window", desired, resourceCreatePolicy(), false, withVM(r.vm, osUpdateInstalledOracle(packages, zone, start))); err != nil {
		return err
	}
	names = append(names, "policy-reconciles-recovery-window")
	if err := rollingRecoveryHoldScenario(ctx, r, packages, evidence); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, names[6], desired, resourceCreatePolicy(), true, withVM(r.vm, osUpdateInstalledOracle(packages, zone, start))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, names[7], desired.GetRef(), withVM(r.vm, func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		record, err := osUpdateConfigOracle(packages)(ctx, vm)
		if err == nil && !bytes.Equal(record.Bytes, baseline.Bytes) {
			err = errors.New("rolling policy release changed the unowned native baseline")
		}
		return record, err
	})); err != nil {
		return err
	}
	evidence.Unproven = []string{
		"security-only classification unavailable on the native rolling transaction model; whole-system receipt is not a clean security status",
		"snapper pre-snapshot does not qualify boot recovery, user-data or database rollback; actual recovery requires independent native evidence",
		"power loss during package scriptlets (durable uncertain-outcome hold exercised with a retained marker)",
		"graphical reboot notification and physical hardware",
	}
	return qualifyResourceEvidence(evidence, names)
}

func rollingWindowAndReboot(ctx context.Context, r *resourceDispatch, packages resourcePackaging, evidence *VMResourceKindEvidence, start time.Time) error {
	s, fail := firewallScenario(ctx, r, evidence, "window-installs-whole-system-snapshot")
	before, err := osUpdatePackageOracle(packages)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	run, err := waitOSUpdateWindowRun(ctx, r.vm, start, osUpdateRunDeadline)
	if err != nil {
		return fail(err)
	}
	after, err := osUpdatePackageOracle(packages)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if bytes.Equal(before.Bytes, after.Bytes) {
		return fail(errors.New("pinned whole-system transaction installed no real package change"))
	}
	status, receipt, err := serverPatchStatus(ctx, r, s, "rolling-installed", func(p *agentv1.PatchStatusObservation) error {
		last := p.GetLastRun()
		if p.GetAvailable() || p.GetReason() != "rolling_security_classification_unavailable" || last.GetResult() != agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED || last.GetSelection() != resourcev1.UpdateSelection_UPDATE_SELECTION_ALL || last.GetUpdatedPackages() == 0 || last.GetStartedAt().AsTime().Before(start) || last.GetRepositorySnapshotDate() != r.osUpdateTarget.GetDate() || last.GetRebootScheduledFor() == nil {
			return fmt.Errorf("missing successful whole-system snapshot receipt: %v", p)
		}
		if last.GetRollbackStatus() != "unavailable" && last.GetRollbackStatus() != "snapper_pre_snapshot" {
			return errors.New("rolling receipt omitted rollback availability")
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	rollback, err := resourceOracle(ctx, r.vm, "native-rollback-boundary", rollingRollbackOracle(status.GetLastRun()))
	if err != nil {
		return fail(err)
	}
	schedule, kind, when, err := logindScheduleOracle(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if kind != "reboot" || when.IsZero() || when.Before(start) || when.After(time.Now().Add((osUpdateLabRebootMinutes+1)*time.Minute)) {
		return fail(errors.New("native reboot schedule does not follow rolling policy"))
	}
	if delta := status.GetLastRun().GetRebootScheduledFor().AsTime().Sub(when); delta < -time.Second || delta > time.Second {
		return fail(errors.New("reported rolling reboot differs from logind"))
	}
	before.Name, after.Name = "before-"+before.Name, "after-"+after.Name
	passScenario(s, before, run, after, rollback, receipt, schedule)
	rebooted, failReboot := firewallScenario(ctx, r, evidence, "scheduled-reboot-executes")
	lines := strings.Split(strings.TrimSpace(string(schedule.Bytes)), "\n")
	previous := lines[len(lines)-1]
	if err := r.awaitReboot(ctx, previous, time.Until(when)+8*time.Minute); err != nil {
		return failReboot(err)
	}
	if time.Now().Before(when.Add(-30 * time.Second)) {
		return failReboot(errors.New("guest rebooted before rolling policy schedule"))
	}
	if _, err := waitGuestExecutorReady(ctx, r.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return failReboot(err)
	}
	boot, err := resourceOracle(ctx, r.vm, "native-new-boot", "test \"$(cat /proc/sys/kernel/random/boot_id)\" != "+nativeQuote(previous)+"; cat /proc/sys/kernel/random/boot_id; test ! -e /run/lindm-os-update/reboot-required")
	if err != nil {
		return failReboot(err)
	}
	passScenario(rebooted, boot)
	return nil
}

func rollingRollbackOracle(run *agentv1.PatchRunSummary) string {
	if run.GetRollbackStatus() == "snapper_pre_snapshot" {
		return fmt.Sprintf("test \"$(stat -f -c %%T /)\" = btrfs; cat /etc/snapper/configs/root; snapper --config root list; snapper --config root status %[1]d..0; test -s /.snapshots/%[1]d/snapshot/etc/lindm/os-update/rolling-in-progress.binpb; printf 'snapper-pre-snapshot %[1]d\\n'", run.GetRollbackSnapshot())
	}
	return "printf 'rollback unavailable\\n'; stat -f -c '%T' /; if test -f /etc/snapper/configs/root; then cat /etc/snapper/configs/root; else printf 'snapper-root-config absent\\n'; fi; command -v snapper || true"
}

func rollingRecoveryHoldScenario(ctx context.Context, r *resourceDispatch, packages resourcePackaging, evidence *VMResourceKindEvidence) error {
	s, fail := firewallScenario(ctx, r, evidence, "interrupted-transaction-recovery-hold")
	before, err := osUpdatePackageOracle(packages)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	// Deliberately retain the uncertain-outcome sentinel. This does not claim
	// to be a power-cut test. The runner must refuse even a corrupt marker.
	marker := resource.OSUpdateRunStatePath + ".rolling-in-progress"
	command := "printf 'interrupted transaction fixture\\n' > " + nativeQuote(marker) + "; chmod 600 " + nativeQuote(marker) + "; systemctl start " + resource.OSUpdateServiceUnit + "; exit 1"
	result, runErr := r.vm.runResult(ctx, "sudo -n /bin/sh -eu -c "+nativeQuote(command), nil, 64<<10, 2*time.Minute)
	if runErr != nil {
		return fail(runErr)
	}
	if result.ExitCode == 0 {
		return fail(errors.New("runner accepted uncertain native outcome"))
	}
	_, receipt, err := serverPatchStatus(ctx, r, s, "rolling-recovery-hold", func(p *agentv1.PatchStatusObservation) error {
		last := p.GetLastRun()
		if last.GetResult() != agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED || last.GetFinishedAt().AsTime().Before(s.StartedAt) || !strings.Contains(strings.Join(last.GetDiagnostic().GetErrorLines(), " "), "requires native recovery") {
			return errors.New("missing recovery-hold receipt")
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	after, err := osUpdatePackageOracle(packages)(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(before.Bytes, after.Bytes) {
		return fail(errors.New("recovery hold changed native packages"))
	}
	retained, err := resourceOracle(ctx, r.vm, "native-retained-recovery-marker", "test -f "+nativeQuote(marker)+"; stat -c '%a %U %G %s' "+nativeQuote(marker))
	if err != nil {
		return fail(err)
	}
	// Only remove the deliberate fixture marker, not a real uncertain outcome.
	if err := lifecycleCommand(ctx, r.vm, "remove deliberate recovery-hold fixture", "test \"$(cat "+nativeQuote(marker)+")\" = 'interrupted transaction fixture'; rm -- "+nativeQuote(marker)); err != nil {
		return fail(err)
	}
	before.Name, after.Name = "before-"+before.Name, "after-"+after.Name
	passScenario(s, before, after, retained, receipt)
	return nil
}
