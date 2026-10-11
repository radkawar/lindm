//go:build linux

package osupdate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

const (
	policyLimit   = 64 << 10
	requestLimit  = 64 << 10
	statusLimit   = 64 << 10
	runStateLimit = 8 << 20
	logindTimeout = 15 * time.Second
	// notifyBudget bounds all desktop notifications of one run together
	// (each user additionally at notifyTimeout).
	notifyBudget = 2 * time.Minute
	maxCount     = 100000

	// Run and patch-now: unitRunTimeout is the units' TimeoutStartSec. The
	// overall run deadline leaves runTermGrace for a package manager that
	// received SIGTERM at a deadline to finish its transaction cleanly.
	unitRunTimeout = 6 * time.Hour
	runTermGrace   = 30 * time.Minute
	runBudget      = unitRunTimeout - runTermGrace
	runLockWait    = 10 * time.Minute
	// Status: lindm-os-update-status.service has TimeoutStartSec=5min; the
	// offline commands are capped together by statusBudget.
	statusBudget   = 4 * time.Minute
	statusLockWait = time.Minute
)

// osReleasePaths are read in this order: /usr/lib/os-release is the
// distribution's regular file, while /etc/os-release is usually a symlink
// to it and is used only when the former is absent. Final symlinks are
// never followed.
var osReleasePaths = []string{"/usr/lib/os-release", "/etc/os-release"}

// Config injects the runner's clock, logger and the executable started for
// desktop notifications.
type Config struct {
	Clock      func() time.Time
	Logger     *slog.Logger
	Executable string
}

// Runner executes one run, patch-now or status invocation.
type Runner struct {
	validator  protovalidate.Validator
	now        func() time.Time
	log        *slog.Logger
	executable string
}

// New validates the configuration and builds the protobuf validator.
func New(config Config) (*Runner, error) {
	if config.Clock == nil || config.Logger == nil || config.Executable == "" {
		return nil, errors.New("osupdate: missing clock, logger or executable")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(
		&agentv1.OSUpdateRunPolicy{}, &agentv1.OSUpdatePatchNowRequest{},
		&agentv1.OSUpdateRunState{}, &agentv1.PatchStatusObservation{},
	), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, fmt.Errorf("osupdate: validator: %w", err)
	}
	return &Runner{validator: validator, now: config.Clock, log: config.Logger, executable: config.Executable}, nil
}

// runSpec is one native update attempt, from the policy or a patch-now request.
type runSpec struct {
	trigger   agentv1.PatchRunTrigger
	actionID  string
	selection resourcev1.UpdateSelection
	reboot    *resourcev1.OSUpdateRebootPolicy
	// deferral is nil for patch now.
	deferral *deferral
	// windowStart anchors the deferral ledger of window runs.
	windowStart time.Time
	zone        *time.Location
}

func (r *Runner) loadPolicy() (*agentv1.OSUpdateRunPolicy, error) {
	data, err := readProtected(resource.OSUpdatePolicyPath, policyLimit)
	if err != nil {
		return nil, err
	}
	policy := &agentv1.OSUpdateRunPolicy{}
	if err := r.unmarshalValidated(data, policy); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return policy, nil
}

// loadRunState returns the root-only state. A missing file starts empty. An
// unreadable or invalid one also starts empty and is logged: the deferral
// clock restarts, which only ever delays updates.
func (r *Runner) loadRunState() *agentv1.OSUpdateRunState {
	state := &agentv1.OSUpdateRunState{FormatVersion: 1}
	data, err := readProtected(resource.OSUpdateRunStatePath, runStateLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return state
	}
	if err == nil {
		loaded := &agentv1.OSUpdateRunState{}
		if err = r.unmarshalValidated(data, loaded); err == nil {
			return loaded
		}
	}
	r.log.Warn("os-update run state discarded", "error", err)
	return state
}

// Run is the maintenance-window entrypoint (lindm-os-update.service).
func (r *Runner) Run(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, runBudget)
	defer cancel()
	started := r.now()
	policy, err := r.loadPolicy()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	spec := runSpec{trigger: agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_MAINTENANCE_WINDOW, zone: time.UTC}
	if err != nil {
		r.log.Error("os-update policy rejected", "error", err)
		return r.recordOnly(ctx, spec, started, agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED,
			runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "os-update policy invalid"))
	}
	desired := policy.GetDesired()
	spec.selection, spec.reboot = desired.GetSelection(), desired.GetRebootPolicy()
	zone, err := time.LoadLocation(desired.GetMaintenance().GetTimeZone())
	if err != nil {
		return r.recordOnly(ctx, spec, started, agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED,
			runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "maintenance window time zone unavailable"))
	}
	spec.zone = zone
	spec.deferral = &deferral{days: desired.GetDeferralDays(), zone: zone}
	start, open, err := openWindow(desired.GetMaintenance(), zone, started)
	if err != nil {
		return r.recordOnly(ctx, spec, started, agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED,
			runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "maintenance window invalid"))
	}
	if !open {
		// Persistent= catch-up or a manual start outside the window.
		return r.recordOnly(ctx, spec, started, agentv1.PatchRunResult_PATCH_RUN_RESULT_SKIPPED_OUTSIDE_WINDOW, nil)
	}
	spec.windowStart = start
	return r.execute(ctx, spec, started)
}

// RunNow is the patch-now entrypoint (lindm-os-update-now.service). The
// request is consumed (removed) before anything else, so a request is never
// replayed. Window gate and deferral do not apply.
func (r *Runner) RunNow(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, runBudget)
	defer cancel()
	started := r.now()
	data, readErr := readProtected(resource.OSUpdatePatchNowRequestPath, requestLimit)
	if err := unix.Unlink(resource.OSUpdatePatchNowRequestPath); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("consume patch-now request: %w", err)
	}
	if readErr != nil {
		return fmt.Errorf("patch-now request: %w", readErr)
	}
	request := &agentv1.OSUpdatePatchNowRequest{}
	validErr := r.unmarshalValidated(data, request)
	if id, err := uuid.Parse(request.GetActionId()); err != nil || id.String() != request.GetActionId() {
		// Without an action identity no patch-now result can be recorded.
		return fmt.Errorf("patch-now request without action identity: %w", errors.Join(validErr, err))
	}
	spec := runSpec{trigger: agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_PATCH_NOW, actionID: request.GetActionId(), zone: time.Local}
	if resourcev1.UpdateSelection_name[int32(request.GetSelection())] != "" {
		spec.selection = request.GetSelection()
	}
	if validErr != nil || !started.Before(request.GetNotAfter().AsTime()) {
		r.log.Warn("os-update patch-now request rejected", "action_id", spec.actionID, "error", validErr)
		return r.recordOnly(ctx, spec, started, agentv1.PatchRunResult_PATCH_RUN_RESULT_REJECTED, nil)
	}
	spec.reboot = request.GetRebootPolicy()
	// Messages use the maintenance window zone when a policy is installed.
	if policy, err := r.loadPolicy(); err == nil {
		if zone, err := time.LoadLocation(policy.GetDesired().GetMaintenance().GetTimeZone()); err == nil {
			spec.zone = zone
		}
	}
	return r.execute(ctx, spec, started)
}

func (r *Runner) summary(spec runSpec, started time.Time, result agentv1.PatchRunResult) *agentv1.PatchRunSummary {
	return &agentv1.PatchRunSummary{
		Trigger: spec.trigger, ActionId: spec.actionID, Selection: spec.selection,
		StartedAt: timestamppb.New(started), Result: result,
	}
}

// recordOnly records a run that performs no native work (skipped, rejected
// or invalid) and republishes the offline status, so a patch-now outcome is
// visible without waiting for a stale-status refresh.
func (r *Runner) recordOnly(ctx context.Context, spec runSpec, started time.Time, result agentv1.PatchRunResult, diagnostic *agentv1.PatchRunDiagnostic) (err error) {
	held, err := acquireLock(ctx, resource.OSUpdateLockPath, runLockWait)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, held.release()) }()
	summary := r.summary(spec, started, result)
	summary.Diagnostic = diagnostic
	summary.FinishedAt = timestamppb.New(r.now())
	state := r.loadRunState()
	state.LastRun = summary
	if err := r.writeRunState(state); err != nil {
		return err
	}
	if err := r.publish(ctx, state); err != nil {
		return err
	}
	if result == agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED {
		return errors.New(strings.Join(diagnostic.GetErrorLines(), "; "))
	}
	return nil
}

// publish recomputes and writes the offline status for state. The caller
// holds the run lock.
func (r *Runner) publish(ctx context.Context, state *agentv1.OSUpdateRunState) error {
	native, err := detect(osReleasePaths, 0)
	if err != nil {
		return r.writeStatus(r.unavailable(reasonPlatform, state))
	}
	status, _ := r.observe(ctx, native, state)
	return r.writeStatus(status)
}

func (r *Runner) writeRunState(state *agentv1.OSUpdateRunState) error {
	data, err := r.marshalValidated(state)
	if err != nil {
		return fmt.Errorf("run state: %w", err)
	}
	return writeAtomic(resource.OSUpdateRunStatePath, data)
}

func (r *Runner) writeStatus(status *agentv1.PatchStatusObservation) error {
	data, err := r.marshalValidated(status)
	if err != nil {
		return fmt.Errorf("patch status: %w", err)
	}
	if len(data) > statusLimit {
		return errFileSize
	}
	return writeAtomic(resource.OSUpdateStatusPath, data)
}

func failureDiagnostic(err error) *agentv1.PatchRunDiagnostic {
	var native *nativeFailure
	if errors.As(err, &native) && native.diagnostic != nil {
		return native.diagnostic
	}
	return runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "native step failed")
}

// failureReason is the status reason of a failed native step.
func failureReason(err error, fallback string) string {
	var native *nativeFailure
	if errors.As(err, &native) && native.reason != "" {
		return native.reason
	}
	return fallback
}

// detect reads the first existing os-release file of paths (owned by owner,
// never through a final symlink) and maps it to the native backend.
func detect(paths []string, owner uint32) (backend, error) {
	for _, path := range paths {
		data, err := readOwned(path, 64<<10, owner)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return detectBackend(data)
	}
	return nil, errors.New(reasonPlatform)
}

// execute performs the locked native run and always records its outcome.
func (r *Runner) execute(ctx context.Context, spec runSpec, started time.Time) (err error) {
	held, err := acquireLock(ctx, resource.OSUpdateLockPath, runLockWait)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, held.release()) }()
	summary := r.summary(spec, started, agentv1.PatchRunResult_PATCH_RUN_RESULT_UNSPECIFIED)
	state := r.loadRunState()
	native, detectErr := detect(osReleasePaths, 0)
	fail := func(phase error) {
		summary.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED
		summary.Diagnostic = failureDiagnostic(phase)
	}
	switch {
	case detectErr != nil:
		summary.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED
		summary.Diagnostic = runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "unsupported platform for os-update")
	default:
		if tool, pkg := native.missingTool(true); pkg != "" {
			summary.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED
			summary.Diagnostic = runnerDiagnostic(tool, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, "required native package "+pkg+" is not installed")
			break
		}
		r.native(ctx, native, spec, state, summary, fail)
	}
	summary.FinishedAt = timestamppb.New(r.now())
	if summary.GetResult() == agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED {
		state.LastSuccess = summary.GetFinishedAt()
	}
	state.LastRun = summary
	var status *agentv1.PatchStatusObservation
	if detectErr == nil {
		var pending []pendingPackage
		status, pending = r.observe(ctx, native, state)
		if status.GetAvailable() {
			// Prune and extend the ledger from the post-run listing.
			if ledger, ledgerErr := updateLedger(state.GetPendingSince(), pending, r.ledgerAnchor(spec)); ledgerErr == nil {
				state.PendingSince = ledger
			}
		}
	} else {
		status = r.unavailable(reasonPlatform, state)
	}
	if writeErr := r.writeRunState(state); writeErr != nil {
		return writeErr
	}
	if writeErr := r.writeStatus(status); writeErr != nil {
		return writeErr
	}
	if summary.GetResult() == agentv1.PatchRunResult_PATCH_RUN_RESULT_FAILED {
		return fmt.Errorf("os-update run failed: %s", strings.Join(summary.GetDiagnostic().GetErrorLines(), "; "))
	}
	return nil
}

// ledgerAnchor is the first-seen time of newly pending packages: the window
// start for window runs (independent of where in the window the run and its
// refresh happen), else the current time.
func (r *Runner) ledgerAnchor(spec runSpec) time.Time {
	if !spec.windowStart.IsZero() {
		return spec.windowStart
	}
	return r.now()
}

// native runs refresh, listing, deferral, installation, the reboot oracle and
// the reboot schedule, filling summary. fail records the first failure.
func (r *Runner) native(ctx context.Context, native backend, spec runSpec, state *agentv1.OSUpdateRunState, summary *agentv1.PatchRunSummary, fail func(error)) {
	if err := native.refresh(ctx); err != nil {
		fail(err)
		return
	}
	pending, err := native.pending(ctx)
	if err != nil {
		fail(err)
		return
	}
	anchor := r.ledgerAnchor(spec)
	ledger, err := updateLedger(state.GetPendingSince(), pending, anchor)
	if err != nil {
		fail(&nativeFailure{reason: reasonListFailed, diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LINDM_AGENT, agentv1.PatchRunPhase_PATCH_RUN_PHASE_LIST, "pending update count exceeds the deferral ledger")})
		return
	}
	state.PendingSince = ledger
	plan := planRun(spec.selection, pending, ledger, spec.deferral, anchor)
	summary.DeferredPackages = uint32(min(len(plan.deferred), maxCount))
	switch {
	case plan.selected == 0:
		summary.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED
	case plan.eligible == 0:
		summary.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_DEFERRED
	default:
		before, err := native.installed(ctx)
		if err != nil {
			fail(err)
			return
		}
		installErr := native.install(ctx, installRequest{selection: spec.selection, deferred: plan.deferred, patchNow: spec.trigger == agentv1.PatchRunTrigger_PATCH_RUN_TRIGGER_PATCH_NOW})
		if after, err := native.installed(ctx); err == nil {
			summary.UpdatedPackages = changedPackages(before, after)
		}
		if installErr != nil {
			fail(installErr)
			return
		}
		summary.Result = agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED
	}
	required, err := native.rebootRequired(ctx)
	if err != nil {
		fail(err)
		return
	}
	summary.RebootRequired = required
	if !required {
		return
	}
	if spec.reboot.GetMode() != resourcev1.OSUpdateRebootMode_OS_UPDATE_REBOOT_MODE_SCHEDULED {
		summary.RebootReason = "policy_never"
		return
	}
	users, message, err := r.requestReboot(ctx, spec, summary)
	if err != nil {
		fail(&nativeFailure{reason: "native_power_failed", diagnostic: runnerDiagnostic(agentv1.PatchRunTool_PATCH_RUN_TOOL_LOGIND, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REBOOT_SCHEDULE, "logind reboot schedule failed")})
		r.log.Error("os-update reboot schedule failed", "error", err)
		return
	}
	if len(users) != 0 {
		// The logind connection is closed; notification failures are counted,
		// never fatal.
		notifyCtx, cancel := context.WithTimeout(ctx, notifyBudget)
		summary.NotifiedSessions = min(notifyUsers(notifyCtx, r.executable, users, message), 1024)
		cancel()
	}
}

// requestReboot never replaces an existing schedule and defers to the next
// run while a blocking shutdown inhibitor is held. It returns the graphical
// session users to notify of an accepted schedule. The logind connection is
// closed before it returns; a close error after an accepted schedule is only
// logged, as the reboot is scheduled regardless.
func (r *Runner) requestReboot(ctx context.Context, spec runSpec, summary *agentv1.PatchRunSummary) (users []sessionUser, message string, err error) {
	ctx, cancel := context.WithTimeout(ctx, logindTimeout)
	defer cancel()
	bus, err := openLogind(ctx)
	if err != nil {
		return nil, "", err
	}
	scheduled := false
	defer func() {
		if closeErr := bus.close(); closeErr != nil {
			if scheduled {
				r.log.Warn("os-update logind close failed after scheduling", "error", closeErr)
			} else {
				err = errors.Join(err, closeErr)
			}
		}
	}()
	power, err := bus.power(ctx)
	if err != nil {
		return nil, "", err
	}
	switch {
	case power.pending:
		summary.RebootReason = "native_power_already_pending"
		if power.kind == "reboot" && !power.scheduled.IsZero() {
			summary.RebootScheduledFor = timestamppb.New(power.scheduled)
		}
		return nil, "", nil
	case power.inhibited:
		summary.RebootReason = "native_power_inhibited"
		return nil, "", nil
	}
	at := r.now().Add(time.Duration(spec.reboot.GetMaxDelayMinutes()) * time.Minute).Truncate(time.Second)
	message = rebootMessage(spec.reboot.GetNotice(), at, spec.zone)
	if err := bus.scheduleReboot(ctx, message, at); err != nil {
		return nil, "", err
	}
	scheduled = true
	summary.RebootScheduledFor = timestamppb.New(at)
	users, listErr := bus.graphicalUsers(ctx)
	if listErr != nil {
		r.log.Warn("os-update session listing failed", "error", listErr)
		return nil, message, nil
	}
	return users, message, nil
}

// Status recomputes the offline patch status (lindm-os-update-status.service).
// It reads the run state but never changes it.
func (r *Runner) Status(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, statusBudget)
	defer cancel()
	held, err := acquireLock(ctx, resource.OSUpdateLockPath, statusLockWait)
	if errors.Is(err, errLockBusy) {
		// A running update publishes the status when it finishes.
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, held.release()) }()
	return r.publish(ctx, r.loadRunState())
}

func bootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(data))
	if id, err := uuid.Parse(value); err != nil || id.String() != value {
		return ""
	}
	return value
}

func (r *Runner) unavailable(reason string, state *agentv1.OSUpdateRunState) *agentv1.PatchStatusObservation {
	_, policyErr := r.loadPolicy()
	return &agentv1.PatchStatusObservation{
		ObservedAt: timestamppb.New(r.now()), BootId: bootID(), Reason: reason,
		LastRun: state.GetLastRun(), LastSuccessfulUpdate: state.GetLastSuccess(),
		PolicyInstalled: policyErr == nil,
	}
}

// observe computes the patch status offline from the native cache. observed_at
// is taken first, after every native command of the run has finished, so a
// later database or metadata change marks the status stale. Missing metadata
// or any listing or oracle failure is unavailable, never zero counts.
func (r *Runner) observe(ctx context.Context, native backend, state *agentv1.OSUpdateRunState) (*agentv1.PatchStatusObservation, []pendingPackage) {
	status := r.unavailable("", state)
	if _, pkg := native.missingTool(false); pkg != "" {
		status.Reason = reasonToolMissing + ":" + pkg
		return status, nil
	}
	refreshed, ok := metadataRefreshedAt(native.metadataPatterns())
	if !ok {
		status.Reason = reasonMetadata
		return status, nil
	}
	pending, err := native.pending(ctx)
	if err != nil {
		status.Reason = failureReason(err, reasonListFailed)
		return status, nil
	}
	required, err := native.rebootRequired(ctx)
	if err != nil {
		status.Reason = failureReason(err, reasonOracleFailed)
		return status, nil
	}
	if status.GetBootId() == "" {
		status.Reason = "boot_identity_unavailable"
		return status, nil
	}
	var security uint32
	for _, p := range pending {
		if p.security {
			security++
		}
	}
	status.Available = true
	status.Backend = native.kind()
	status.MetadataRefreshedAt = timestamppb.New(refreshed)
	status.PendingUpdates = uint32(min(len(pending), maxCount))
	status.PendingSecurityUpdates = min(security, status.PendingUpdates)
	status.RebootRequired = required
	if policy, err := r.loadPolicy(); err == nil {
		desired := policy.GetDesired()
		if zone, err := time.LoadLocation(desired.GetMaintenance().GetTimeZone()); err == nil {
			plan := planRun(desired.GetSelection(), pending, state.GetPendingSince(), &deferral{days: desired.GetDeferralDays(), zone: zone}, r.now())
			status.DeferredUpdates = uint32(min(len(plan.deferred), maxCount))
		}
	}
	status.RebootScheduledFor = r.pendingReboot(ctx)
	return status, pending
}

// pendingReboot reports an accepted logind reboot schedule; a failure leaves
// it absent rather than making the whole status unavailable.
func (r *Runner) pendingReboot(ctx context.Context) (_ *timestamppb.Timestamp) {
	ctx, cancel := context.WithTimeout(ctx, logindTimeout)
	defer cancel()
	bus, err := openLogind(ctx)
	if err != nil {
		r.log.Warn("os-update logind unavailable", "error", err)
		return nil
	}
	defer func() { _ = bus.close() }()
	power, err := bus.power(ctx)
	if err != nil || power.kind != "reboot" || power.scheduled.IsZero() {
		return nil
	}
	return timestamppb.New(power.scheduled)
}
