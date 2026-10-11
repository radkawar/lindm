//go:build linux

package fileprovider

import (
	"bytes"
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

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
	tx, err := nativefile.Prepare(request.GetBefore(), target)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, tx.Close()) }()
	return tx.Commit(ctx, beforeEffect)
}
