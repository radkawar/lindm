//go:build linux

package definitionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

func sha256Bytes(data []byte) []byte { digest := sha256.Sum256(data); return digest[:] }

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	n := len(data)
	remaining := 32768 - b.Len()
	if len(data) > remaining {
		b.overflow = true
		data = data[:max(remaining, 0)]
	}
	_, _ = b.Buffer.Write(data)
	return n, nil
}

// verifyCandidate stages only bounded public definition bytes in the helper's
// root-private per-action directory. It never writes a live unit or executes
// service commands. SYSTEMD_UNIT_PATH overlays this candidate over native
// definitions; generators remain disabled (the opt-in flag is never supplied).
func verifyCandidate(ctx context.Context, scratch string, desired *resourcev1.ResourceDesiredState, target *agentv1.ResourceOwnershipSnapshot) (err error) {
	fd, _, err := directory(scratch)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if st.Mode&0077 != 0 {
		_ = unix.Close(fd)
		return ErrProtected
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(scratch, "definition-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	d := desired.GetSystemdDefinition()
	name := targetUnit(d)
	var candidate string
	if timer := d.GetTimer(); timer != nil {
		name = timer.GetUnit()
		candidate = filepath.Join(stage, name)
		if !target.GetDefinitionFile().GetState().GetExists() {
			return nil
		}
	} else {
		parent := filepath.Join(stage, name+".d")
		if err := os.Mkdir(parent, 0700); err != nil {
			return err
		}
		candidate = filepath.Join(parent, dropInName)
	}
	if target.GetDefinitionFile().GetState().GetExists() {
		// This is private validator input, not a live configuration write. Use
		// exclusive creation and never accept a transported pathname.
		file, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(target.GetDefinitionFile().GetContent())
		err = errors.Join(writeErr, file.Close())
		if err != nil {
			return err
		}
	} else {
		if err := os.Symlink("/dev/null", candidate); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	argument := name
	if d.GetTimer() != nil {
		argument = candidate
	}
	command := exec.CommandContext(ctx, "/usr/bin/systemd-analyze", "verify", "--man=no", "--recursive-errors=no", "--", argument)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_UNIT_PATH=" + stage + ":"}
	command.Dir = "/"
	command.WaitDelay = 2 * time.Second
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("%w: systemd-analyze verify: %w: %s", ErrUnsupported, err, output.String())
	}
	if output.overflow {
		return ErrUnsupported
	}
	return nil
}

// ExecuteNative is called only by the fixed transient native helper. It has no
// SQLite handle and recomputes its private target from the protected plan and
// ledger. beforeEffect is invoked once after candidate/native preconditions and
// descriptor custody, immediately before the first live filesystem or bus effect.
func ExecuteNative(ctx context.Context, config NativeConfig, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (_ *agentv1.ResourceOwnershipSnapshot, err error) {
	if ctx == nil || beforeEffect == nil || config.ScratchDirectory == "" {
		return nil, ErrUnsupported
	}
	if err := validateMessage(request); err != nil {
		return nil, err
	}
	if err := resource.ValidatePlan(request.GetPlan()); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(request.GetPlan())
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	p, err := nativeContext(ctx, config)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if !proto.Equal(request.GetPlan().GetBackend(), p.backend) || request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation() != config.ExecutorIncarnation {
		return nil, ErrConflict
	}
	if !proto.Equal(request.GetBefore().GetObservation(), request.GetPlan().GetBefore()) {
		// Apply uses a fresh timestamp, but every stable native field and the
		// retained plan observation's digest must still bind exactly.
		if !proto.Equal(request.GetBefore().GetObservation().GetSystemdDefinition(), request.GetPlan().GetBefore().GetSystemdDefinition()) || !bytes.Equal(request.GetBefore().GetObservation().GetMetadata().GetNativeRevision(), request.GetPlan().GetBefore().GetMetadata().GetNativeRevision()) || request.GetBefore().GetObservation().GetMetadata().GetBootId() != request.GetPlan().GetBefore().GetMetadata().GetBootId() {
			return nil, ErrConflict
		}
	}
	ledger := request.GetOwnership()
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	claimed := ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED && ledger.GetClaimActionId() == request.GetActionId()
	if !claimed && !bytes.Equal(ld[:], request.GetPlan().GetOwnershipRevisionSha256()) {
		return nil, ErrConflict
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN || !resource.RefEqual(ledger.GetRef(), request.GetPlan().GetRef()) {
		return nil, ErrConflict
	}
	before, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	if !sameObserved(before, request.GetBefore()) {
		return nil, ErrConflict
	}
	if err := acquisitionAllowed(ledger.GetOwner(), before, ledger, request.GetPlan().GetOperation()); err != nil {
		return nil, err
	}
	target, err := targetImage(ctx, desired, before, ledger, request.GetPlan().GetOperation())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(target.GetDefinitionFile(), request.GetTarget().GetDefinitionFile()) || !proto.Equal(target.GetObservation().GetSystemdDefinition(), request.GetTarget().GetObservation().GetSystemdDefinition()) || !bytes.Equal(sha256Bytes(target.GetDefinitionFile().GetContent()), request.GetPlan().GetSystemdDefinition().GetRenderedCandidateSha256()) {
		return nil, ErrConflict
	}
	if err := verifyCandidate(ctx, config.ScratchDirectory, desired, target); err != nil {
		return nil, err
	}
	return p.executePrepared(ctx, request.GetPlan(), before, target, ledger, beforeEffect)
}

func (p *Provider) executePrepared(ctx context.Context, plan *resourcev1.ResourcePlan, before, target *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, beforeEffect func(context.Context) error) (_ *agentv1.ResourceOwnershipSnapshot, err error) {
	desired := resource.PlanDesired(plan)
	path, err := DefinitionPath(desired)
	if err != nil {
		return nil, err
	}
	changeFile := !imageEqual(before, target)
	var transaction *nativefile.Transaction
	if changeFile && !before.GetDefinitionFile().GetParentMissing() {
		transaction, err = nativefile.Prepare(fileSnapshot(before), fileSnapshot(target))
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, transaction.Close()) }()
	}
	fresh, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh, before) {
		return nil, ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := beforeEffect(ctx); err != nil {
		return nil, err
	}
	// No effect below this point is retried, including a failed reload. The
	// executor has already durably marked the ownership effect UNKNOWN.
	effectErr := func(err error) (*agentv1.ResourceOwnershipSnapshot, error) {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := ctx.Err(); err != nil {
		return effectErr(err)
	}
	fresh, err = p.snapshot(ctx, desired)
	if err != nil {
		return effectErr(err)
	}
	if !sameObserved(fresh, before) {
		return effectErr(ErrConflict)
	}
	if !sameFileParent(path, before.GetDefinitionFile()) {
		return effectErr(ErrConflict)
	}
	d := desired.GetSystemdDefinition()
	a, b := before.GetObservation().GetSystemdDefinition(), target.GetObservation().GetSystemdDefinition()
	if timer := d.GetTimer(); timer != nil {
		if err := timerBefore(ctx, p.manager, timer.GetUnit(), a, b); err != nil {
			return effectErr(err)
		}
	}
	if changeFile {
		if before.GetDefinitionFile().GetParentMissing() {
			if !target.GetDefinitionFile().GetState().GetExists() {
				return effectErr(ErrConflict)
			}
			if err := createParent(path, before.GetDefinitionFile()); err != nil {
				return effectErr(err)
			}
			newBefore, err := nativefile.Capture(path, before.GetObservation())
			if err != nil {
				return effectErr(err)
			}
			newTarget := fileSnapshot(target)
			newTarget.Observation.GetManagedFile().AncestrySha256 = bytes.Clone(newBefore.GetObservation().GetManagedFile().GetAncestrySha256())
			if err := nativefile.CreationMetadata(ctx, newTarget); err != nil {
				return effectErr(err)
			}
			if !bytes.Equal(newTarget.GetObservation().GetManagedFile().GetSecurityMetadataSha256(), target.GetDefinitionFile().GetState().GetSecurityMetadataSha256()) {
				return effectErr(ErrConflict)
			}
			transaction, err = nativefile.Prepare(newBefore, newTarget)
			if err != nil {
				return effectErr(err)
			}
			defer func() { err = errors.Join(err, transaction.Close()) }()
		}
		if _, err := transaction.Commit(ctx, func(context.Context) error { return nil }); err != nil {
			return effectErr(err)
		}
	}
	if changeFile || (d.GetTimer() != nil && a.GetTimerEnabled() != b.GetTimerEnabled()) {
		if err := p.manager.Reload(ctx); err != nil {
			return effectErr(err)
		}
	}
	// Native reload must independently agree with the exact candidate before a
	// newly enabled timer is allowed to acquire links or enter active state.
	middle, err := p.snapshot(ctx, desired)
	if err != nil {
		return effectErr(err)
	}
	if !imageEqual(middle, target) || !bytes.Equal(middle.GetObservation().GetSystemdDefinition().GetTargetDefinitionSha256(), a.GetTargetDefinitionSha256()) || middle.GetObservation().GetSystemdDefinition().GetDaemonReloadPending() {
		return effectErr(ErrConflict)
	}
	if drop := d.GetDropIn(); drop != nil && target.GetDefinitionFile().GetState().GetExists() && plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && !optionsMatch(drop, middle.GetObservation().GetSystemdDefinition().GetEffectiveOptions()) {
		return effectErr(ErrNotConverged)
	}
	if timer := d.GetTimer(); timer != nil {
		if err := timerAfter(ctx, p.manager, timer.GetUnit(), middle.GetObservation().GetSystemdDefinition(), b); err != nil {
			return effectErr(err)
		}
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED && ledger.GetBaseline().GetDefinitionFile().GetParentMissing() && !target.GetDefinitionFile().GetState().GetExists() && !before.GetDefinitionFile().GetParentMissing() {
		if err := removeOwnedParent(path, before.GetDefinitionFile()); err != nil {
			return effectErr(err)
		}
	}
	after, err := p.snapshot(ctx, desired)
	if err != nil {
		return effectErr(err)
	}
	if !definitionChecks(desired, plan.GetOperation(), after, target).GetConverged() {
		return effectErr(ErrNotConverged)
	}
	return after, nil
}
func sameFileParent(path string, expected *agentv1.DefinitionFileSnapshot) bool {
	missing, digest, err := parentEvidence(path)
	return err == nil && missing == expected.GetParentMissing() && bytes.Equal(digest, expected.GetParentIdentitySha256())
}

func timerBefore(ctx context.Context, manager nativeManager, unit string, before, target *resourcev1.SystemdDefinitionObservation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if before.GetTimerActive() && !target.GetTimerActive() {
		if err := manager.Runtime(ctx, unit, false); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if before.GetTimerEnabled() && !target.GetTimerEnabled() {
		if err := manager.Enable(ctx, unit, false); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	return nil
}
func timerAfter(ctx context.Context, manager nativeManager, unit string, current, target *resourcev1.SystemdDefinitionObservation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if target.GetTimerEnabled() && !current.GetTimerEnabled() {
		if err := manager.Enable(ctx, unit, true); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		if err := manager.Reload(ctx); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if target.GetTimerActive() && !current.GetTimerActive() {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		if err := manager.Runtime(ctx, unit, true); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	return nil
}
