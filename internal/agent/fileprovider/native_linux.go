//go:build linux

package fileprovider

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

// ObserveNative reads the closed module template in a read-only helper whose
// module metadata is visible. The resident executor keeps ProtectKernelModules.
func ObserveNative(ctx context.Context, env resourceprovider.NativeEnv, desired *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
	if desired.GetManagedFile().GetKernelModuleBlocklist() == nil {
		return nil, ErrUnsupported
	}
	config := nativeConfig{Native: env.Config.GetFileProvider(), Platform: env.Platform, ExecutorIncarnation: env.ExecutorIncarnation, ProtectedPaths: env.ProtectedPaths}
	backend, boot, err := nativeContext(ctx, config)
	if err != nil {
		return nil, err
	}
	p := &Provider{config: Config{Native: config.Native, Platform: config.Platform, ExecutorIncarnation: config.ExecutorIncarnation}, backend: backend, boot: boot}
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	return p.snapshot(ctx, desired)
}

// ApplyNative is called only by the fixed root transient helper. It does not
// open the live journal. The parent authenticates the protected request and nonce,
// grants only filepath.Dir(plan.managed_file.desired.path) writable, and exchanges
// its single-use permit through beforeEffect. A successful response is still
// independently observed by the executor before journal completion.
func ApplyNative(ctx context.Context, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	config := nativeConfig{Native: env.Config.GetFileProvider(), Platform: env.Platform, ExecutorIncarnation: env.ExecutorIncarnation, ProtectedPaths: env.ProtectedPaths}
	if beforeEffect == nil || proto.Size(request) > 1<<20 {
		return nil, ErrUnsupported
	}
	if err := validateMessage(request); err != nil {
		return nil, err
	}
	plan := request.GetPlan()
	if plan.GetRef().GetKind() != resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE || plan.GetManagedFile() == nil {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	backend, boot, err := nativeContext(ctx, config)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(backend, plan.GetBackend()) || request.GetBefore().GetObservation().GetMetadata().GetBootId() != boot || request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation() != config.ExecutorIncarnation {
		return nil, ErrConflict
	}
	p := &Provider{config: Config{Native: config.Native, Platform: config.Platform, ExecutorIncarnation: config.ExecutorIncarnation}, backend: backend, boot: boot}
	desired := resource.PlanDesired(plan)
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if !sameObserved(request.GetBefore().GetObservation(), plan.GetBefore()) {
		return nil, ErrConflict
	}
	ledger := request.GetOwnership()
	if !resource.RefEqual(ledger.GetRef(), plan.GetRef()) {
		return nil, ErrConflict
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED {
		if plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE || ledger.GetClaimActionId() != request.GetActionId() || !proto.Equal(ledger.GetBaseline().GetObservation().GetManagedFile(), request.GetBefore().GetObservation().GetManagedFile()) || !bytes.Equal(ledger.GetBaseline().GetManagedFileContent(), request.GetBefore().GetManagedFileContent()) {
			return nil, ErrConflict
		}
		// The actual claim was authenticated and fenced by the protected journal
		// before this request. Recheck its acquisition policy independently.
		if err := acquisitionAllowed(ledger.GetOwner(), request.GetBefore(), nil, plan.GetOperation()); err != nil {
			return nil, err
		}
	} else {
		ld, err := journal.ResourceOwnershipDigest(ledger)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(ld[:], plan.GetOwnershipRevisionSha256()) {
			return nil, ErrConflict
		}
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED {
			return nil, ErrOutcomeUnknown
		}
		if err := acquisitionAllowed(ledger.GetOwner(), request.GetBefore(), ledger, plan.GetOperation()); err != nil {
			return nil, err
		}
	}
	target, err := p.target(ctx, desired.GetManagedFile(), request.GetBefore(), ledger, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(target, request.GetTarget()) {
		return nil, ErrConflict
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		inverse, err := inverseBinding(request.GetBefore(), target, ledger)
		if err != nil {
			return nil, err
		}
		if !proto.Equal(inverse, plan.GetManagedFile().GetInverse()) {
			return nil, ErrConflict
		}
	}
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil {
		fresh, err := p.snapshot(ctx, desired)
		if err != nil {
			return nil, err
		}
		if !sameObserved(fresh.GetObservation(), request.GetBefore().GetObservation()) {
			return nil, ErrConflict
		}
	}
	tx, err := nativefile.Prepare(moduleFileImage(request.GetBefore()), moduleFileImage(target))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, tx.Close()) }()
	after, err := tx.Commit(ctx, beforeEffect)
	if err != nil || desired.GetManagedFile().GetKernelModuleBlocklist() == nil {
		return after, err
	}
	tools, err := moduleTooling(config.Platform)
	if err != nil {
		return nil, err
	}
	args := tools.RebuildArgs
	if target.GetObservation().GetManagedFile().GetExists() && len(tools.RebuildWithFileArgs) != 0 {
		args = tools.RebuildWithFileArgs
	}
	command, rebuildErr := nativeexec.Run(ctx, nativeexec.Command{Path: tools.Rebuild, Args: args, Timeout: 10 * time.Minute, StdoutLimit: 1 << 20, StderrLimit: 1 << 20})
	if rebuildErr != nil {
		// The file commit is known, not an unknown helper loss. Preserve its
		// custody and expose failed rebuild evidence so reconciliation can retry.
		slog.Error("kernel module initramfs rebuild failed", "error", rebuildErr, "diagnostic", command.Diagnostic())
	}
	after, err = p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	after.ModuleInitramfsRebuildSucceeded = proto.Bool(rebuildErr == nil)
	return after, nil
}
