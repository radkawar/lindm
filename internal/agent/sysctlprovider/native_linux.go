//go:build linux

package sysctlprovider

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

type NativeConfig struct {
	Native              *agentv1.NativeSysctlProviderConfig
	Platform            *resourcev1.PlatformProduct
	ExecutorIncarnation string
}

// NeedsRuntimeWrite and NeedsPersistenceWrite let the fixed launcher derive
// writable paths from an already validated, protected typed request.
func NeedsRuntimeWrite(request *agentv1.NativeResourceTransactionRequest) bool {
	return normalizeValue(request.GetBefore().GetObservation().GetSysctl().GetValue()) != normalizeValue(request.GetTarget().GetObservation().GetSysctl().GetValue())
}
func NeedsPersistenceWrite(request *agentv1.NativeResourceTransactionRequest) bool {
	return !fileTargetMatches(request.GetBefore().GetSysctlPersistence(), request.GetTarget().GetSysctlPersistence())
}

// ExecuteNative is exclusively the fixed authenticated transient helper entry.
// The parent supplies root-local policy, makes only ProcPath(key) writable, and
// grants /etc/sysctl.d writable only if the target file image differs. CAP_LEASE
// is needed whenever persistent ownership is pinned, including unchanged files.
// ProtectKernelTunables=false belongs to this helper, NEVER the executor unit.
// CAP_NET_ADMIN applies to network keys; other approved keys may require
// CAP_SYS_ADMIN. The parent must keep all other proc/sys paths read-only.
// No writable file is opened before native preconditions are pinned. There is
// no compensating write: kernel effects cannot be rolled back transactionally.
func ExecuteNative(ctx context.Context, config NativeConfig, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if beforeEffect == nil || proto.Size(request) > 1<<20 {
		return nil, ErrUnsupported
	}
	if err := validateMessage(request); err != nil {
		return nil, err
	}
	if err := validateMessage(config.Native); err != nil {
		return nil, err
	}
	plan := request.GetPlan()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	d := plan.GetSysctl().GetDesired()
	if d == nil || authorityKey(d.GetKey()) || !slices.Contains(config.Native.GetAllowedKeys(), d.GetKey()) {
		return nil, ErrUnsupported
	}
	backend, err := nativeBackend(ctx, config.Platform)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBackend(), backend) || request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation() != config.ExecutorIncarnation || plan.GetBefore().GetMetadata().GetExecutorIncarnation() != config.ExecutorIncarnation {
		return nil, ErrConflict
	}
	if !proto.Equal(request.GetBefore().GetObservation().GetSysctl(), plan.GetSysctl().GetBefore()) {
		return nil, ErrConflict
	}
	ledger := request.GetOwnership()
	if !resource.RefEqual(ledger.GetRef(), plan.GetRef()) {
		return nil, ErrConflict
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_CLAIMED {
		if plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE || ledger.GetClaimActionId() != request.GetActionId() || !sameSnapshot(ledger.GetBaseline(), request.GetBefore()) {
			return nil, ErrConflict
		}
		if err := acquisitionAllowed(ledger.GetOwner(), nil, plan.GetOperation()); err != nil {
			return nil, err
		}
	} else {
		digest, err := journal.ResourceOwnershipDigest(ledger)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(digest[:], plan.GetOwnershipRevisionSha256()) {
			return nil, ErrConflict
		}
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED {
			return nil, ErrOutcomeUnknown
		}
	}
	p := &Provider{config: Config{Native: config.Native, Platform: config.Platform, ExecutorIncarnation: config.ExecutorIncarnation}, backend: backend}
	before, err := p.snapshot(ctx, d)
	if err != nil {
		return nil, err
	}
	if !sameSnapshot(before, request.GetBefore()) {
		return nil, ErrConflict
	}
	target, err := p.target(ctx, d, before, ledger, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	if !sameSnapshot(target, request.GetTarget()) {
		return nil, ErrConflict
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		inverse, err := inverseBinding(ledger, before, target)
		if err != nil {
			return nil, err
		}
		if !proto.Equal(inverse, plan.GetSysctl().GetInverse()) {
			return nil, ErrConflict
		}
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && d.GetPersistent() {
		graph, err := readPersistence(d.GetKey(), target.GetSysctlPersistence().GetContent(), true)
		if err != nil {
			return nil, err
		}
		if graph.conflict || graph.value == nil || *graph.value != normalizeValue(d.GetValue()) {
			return nil, ErrConflict
		}
	}
	proc, err := openProc(d.GetKey(), NeedsRuntimeWrite(request))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, proc.close()) }()
	if !bytes.Equal(proc.identity, before.GetObservation().GetSysctl().GetNativeIdentitySha256()) {
		return nil, ErrConflict
	}
	var transaction *nativefile.Transaction
	if d.GetPersistent() || owned(ledger, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SYSCTL_PERSISTENCE) || !fileTargetMatches(before.GetSysctlPersistence(), target.GetSysctlPersistence()) {
		// Capture supplies nativefile's own revision (including ctime), not the
		// enclosing sysctl revision. Compare the typed custody evidence again.
		fileBefore, err := nativefile.Capture(StanzaPath(d.GetKey()), before.GetObservation())
		if err != nil {
			return nil, err
		}
		if !proto.Equal(fileBefore.GetObservation().GetManagedFile(), before.GetSysctlPersistence().GetState()) || !bytes.Equal(fileBefore.GetManagedFileContent(), before.GetSysctlPersistence().GetContent()) {
			return nil, ErrConflict
		}
		transaction, err = nativefile.Prepare(fileBefore, fileSnapshot(target))
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, transaction.Close()) }()
	}
	preconditions := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := proc.unchanged(before.GetObservation().GetSysctl().GetValue()); err != nil {
			return err
		}
		graph, err := readPersistence(d.GetKey(), nil, false)
		if err != nil {
			return err
		}
		if !bytes.Equal(graph.graph, before.GetObservation().GetSysctl().GetPersistenceGraphSha256()) {
			return ErrConflict
		}
		return nil
	}
	gate := func(effectContext context.Context) error {
		if err := preconditions(); err != nil {
			return err
		}
		if err := beforeEffect(effectContext); err != nil {
			return err
		}
		return preconditions()
	}
	if transaction != nil {
		if _, err := transaction.Commit(ctx, gate); err != nil {
			return nil, err
		}
	} else {
		if err := gate(ctx); err != nil {
			return nil, err
		}
	}
	if normalizeValue(before.GetObservation().GetSysctl().GetValue()) != normalizeValue(target.GetObservation().GetSysctl().GetValue()) {
		if err := proc.unchanged(before.GetObservation().GetSysctl().GetValue()); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		if err := proc.write(target.GetObservation().GetSysctl().GetValue()); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	after, err := p.snapshot(ctx, d)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !targetMatches(after, target) {
		return after, errors.Join(ErrOutcomeUnknown, ErrNotConverged)
	}
	return after, nil
}
