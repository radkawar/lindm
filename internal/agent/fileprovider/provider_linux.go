//go:build linux

// Package fileprovider owns bounded public regular-file data, not command
// execution, secrets, directories or another native provider's authority. Observation and
// planning are read-only. Every write runs through the closed transient helper
// callback; the executor never widens its own writable filesystem sandbox.
// Interrupted effects leave protected ownership UNKNOWN and are never replayed.
package fileprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "managed.file.v1"

var (
	ErrUnsupported    = errors.New("fileprovider: unsupported")
	ErrUnsafePath     = errors.New("fileprovider: unsafe_path")
	ErrConflict       = errors.New("fileprovider: ownership_or_precondition_conflict")
	ErrOutcomeUnknown = errors.New("fileprovider: outcome_unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("fileprovider: not_converged"))
)

// nativeConfig is trusted local context, never accepted from an action payload.
// Native comes only from the protected executor configuration.
type nativeConfig struct {
	Native              *agentv1.NativeFileProviderConfig
	Platform            *resourcev1.PlatformProduct
	ExecutorIncarnation string
	ProtectedPaths      []string
}
type Config struct {
	Journal              *journal.Store
	Native               *agentv1.NativeFileProviderConfig
	Platform             *resourcev1.PlatformProduct
	ExecutorIncarnation  string
	Ownership            *agentv1.ResourceOwnershipBinding
	ActionID             string
	DeploymentID         string
	DeviceID             string
	EnrollmentGeneration string
	ProtectedPaths       []string
	ExecuteNative        func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)
	NativeObserve        func(context.Context, *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error)
}

// ownershipStore is the journal's consumer boundary, with a deterministic test
// implementation. Production constructors only accept the concrete protected store.
type ownershipStore interface {
	LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error)
	ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
	BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error)
	CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
}
type Provider struct {
	config  Config
	journal ownershipStore
	backend *resourcev1.BackendSelection
	boot    string
	gate    sync.Mutex
	closed  bool
}

var _ resourceprovider.Provider = (*Provider)(nil)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) { return protovalidate.New() })

func validateMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return ErrUnsupported
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return err
	}
	v, err := validator()
	if err != nil {
		return err
	}
	return v.Validate(message)
}
func Open(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil || config.Journal == nil || os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateMessage(config.Ownership); err != nil {
		return nil, err
	}
	backend, boot, err := nativeContext(ctx, nativeConfig{Native: config.Native, Platform: config.Platform, ExecutorIncarnation: config.ExecutorIncarnation, ProtectedPaths: config.ProtectedPaths})
	if err != nil {
		return nil, err
	}
	config.Native = proto.CloneOf(config.Native)
	config.Platform = proto.CloneOf(config.Platform)
	config.Ownership = proto.CloneOf(config.Ownership)
	config.ProtectedPaths = slices.Clone(config.ProtectedPaths)
	return &Provider{config: config, journal: config.Journal, backend: backend, boot: boot}, nil
}
func nativeContext(ctx context.Context, config nativeConfig) (*resourcev1.BackendSelection, string, error) {
	if os.Geteuid() != 0 {
		return nil, "", ErrUnsupported
	}
	if err := validateMessage(config.Native); err != nil {
		return nil, "", err
	}
	if err := validateMessage(config.Platform); err != nil {
		return nil, "", err
	}
	if len(config.ProtectedPaths) == 0 {
		return nil, "", ErrUnsupported
	}
	for _, protected := range config.ProtectedPaths {
		if !filepath.IsAbs(protected) || filepath.Clean(protected) != protected || protected == "/" {
			return nil, "", ErrUnsafePath
		}
		if config.Native.GetKernelModuleBlocklist() && (within(ModuleBlocklistPath, protected) || within(protected, ModuleBlocklistPath)) {
			return nil, "", ErrUnsafePath
		}
		for _, root := range config.Native.GetAllowedRoots() {
			if within(root, protected) || within(protected, root) {
				return nil, "", ErrUnsafePath
			}
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, "", err
	}
	actual, err := inventory.HostPlatform(ctx)
	if err != nil {
		return nil, "", err
	}
	if !proto.Equal(actual, config.Platform) {
		return nil, "", ErrConflict
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return nil, "", err
	}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_POSIX_FILE, NativeVersion: unix.ByteSliceToString(uts.Release[:]), ProviderVersion: "1", Product: actual}
	metadata := &resourcev1.ObservationMetadata{BootId: strings.TrimSpace(string(boot)), ExecutorIncarnation: config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: backend, NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}
	if err := validateMessage(metadata); err != nil {
		return nil, "", err
	}
	return backend, metadata.GetBootId(), nil
}
func (p *Provider) lock() (func(), error) {
	p.gate.Lock()
	if p.closed {
		p.gate.Unlock()
		return nil, ErrUnsupported
	}
	return p.gate.Unlock, nil
}
func (p *Provider) Close() error { p.gate.Lock(); defer p.gate.Unlock(); p.closed = true; return nil }
func (p *Provider) ledger(ctx context.Context, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.journal.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, ref)
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}
func (p *Provider) validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	if desired.GetManagedFile() == nil {
		return ErrUnsupported
	}
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil {
		if !p.config.Native.GetKernelModuleBlocklist() {
			return ErrUnsupported
		}
		return nil
	}
	if err := allowedPath(p.config.Native, desired.GetManagedFile().GetPath()); err != nil {
		return err
	}
	return nil
}
func observationTemplate(ref *resourcev1.ResourceRef, backend *resourcev1.BackendSelection, boot, incarnation string) *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{Ref: proto.CloneOf(ref), Metadata: &resourcev1.ObservationMetadata{BootId: boot, ExecutorIncarnation: incarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(backend), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
}
func (p *Provider) snapshot(ctx context.Context, desired *resourcev1.ResourceDesiredState) (snapshot *agentv1.ResourceOwnershipSnapshot, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil && p.config.NativeObserve != nil {
		return p.config.NativeObserve(ctx, desired)
	}
	snapshot, err = nativefile.Capture(desired.GetManagedFile().GetPath(), observationTemplate(desired.GetRef(), p.backend, p.boot, p.config.ExecutorIncarnation))
	if err != nil {
		return nil, err
	}
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil {
		modules, err := observeModules(ctx, desired.GetManagedFile(), p.config.Platform, p.backend.GetNativeVersion())
		if err != nil {
			return nil, err
		}
		snapshot.Observation.GetManagedFile().KernelModuleBlocklist = modules
	}
	if err := resource.ValidateObservation(snapshot.GetObservation()); err != nil {
		return nil, err
	}
	return snapshot, nil
}
func (p *Provider) Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	snapshot, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	return snapshot.GetObservation(), nil
}
func (p *Provider) target(ctx context.Context, desired *resourcev1.ManagedFileDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	target, err := targetImage(moduleTemplate(desired), before, ledger, operation)
	if err != nil {
		return nil, err
	}
	if !before.GetObservation().GetManagedFile().GetExists() && target.GetObservation().GetManagedFile().GetExists() && operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		if err := nativefile.CreationMetadata(ctx, target); err != nil {
			return nil, err
		}
	}
	return target, nil
}
func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	ledger, err := p.ledger(ctx, desired.GetRef())
	if err != nil {
		return nil, err
	}
	before, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, before, ledger, operation); err != nil {
		return nil, err
	}
	target, err := p.target(ctx, desired.GetManagedFile(), before, ledger, operation)
	if err != nil {
		return nil, err
	}
	return p.makePlan(desired, operation, before, target, ledger)
}
func (p *Provider) makePlan(desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation, before, target *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.ResourcePlan, error) {
	dd, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	od, err := resource.ObservationDigest(before.GetObservation())
	if err != nil {
		return nil, err
	}
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	change := resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_UPDATE
	if imageEqual(before, target) && (desired.GetManagedFile().GetKernelModuleBlocklist() == nil || (initramfsMatches(before.GetObservation().GetManagedFile().GetKernelModuleBlocklist(), target) && !moduleRebuildFailed(ledger.GetLastApplied()))) {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	} else if !target.GetObservation().GetManagedFile().GetExists() {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_REMOVE_OWNED
	} else if !before.GetObservation().GetManagedFile().GetExists() {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE
	}
	confirmation := resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED
	if before.GetObservation().GetManagedFile().GetExists() && (ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED) {
		confirmation = resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_INDEPENDENT_OPERATOR
	}
	native := &resourcev1.ManagedFilePlan{Desired: proto.CloneOf(desired.GetManagedFile()), Before: proto.CloneOf(before.GetObservation().GetManagedFile()), Change: change}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		native.Inverse, err = inverseBinding(before, target, ledger)
		if err != nil {
			return nil, err
		}
		if !imageEqual(before, target) {
			native.Change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_RESTORE_OWNED
		}
	}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: dd[:], ObservationSha256: od[:], Backend: proto.CloneOf(p.backend), Claims: claims, OwnershipRevisionSha256: ld[:], Before: proto.CloneOf(before.GetObservation()), Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: confirmation}, Plan: &resourcev1.ResourcePlan_ManagedFile{ManagedFile: native}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if beforeEffect == nil || p.config.ExecuteNative == nil || p.config.ActionID == "" {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBackend(), p.backend) {
		return nil, ErrConflict
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ld[:], plan.GetOwnershipRevisionSha256()) {
		return nil, ErrConflict
	}
	before, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	if !sameObserved(before.GetObservation(), plan.GetBefore()) {
		return nil, ErrConflict
	}
	if err := acquisitionAllowed(p.config.Ownership, before, ledger, plan.GetOperation()); err != nil {
		return nil, err
	}
	target, err := p.target(ctx, desired.GetManagedFile(), before, ledger, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	replanned, err := p.makePlan(desired, plan.GetOperation(), before, target, ledger)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(replanned.GetManagedFile(), plan.GetManagedFile()) || !proto.Equal(replanned.GetSafety(), plan.GetSafety()) || !equalClaims(replanned.GetClaims(), plan.GetClaims()) {
		return nil, ErrConflict
	}
	// Preserve the pre-transition ledger for independent helper target derivation.
	requestLedger := proto.CloneOf(ledger)
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger, err = p.journal.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), before)
		if err != nil {
			return nil, err
		}
		requestLedger = proto.CloneOf(ledger)
	}
	dimensions := fileDimensions(moduleTemplate(desired.GetManagedFile()), before)
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		dimensions = append([]agentv1.ResourceOwnedDimension(nil), ledger.GetOwnedDimensions()...)
	}
	ledger, err = p.journal.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), before, dimensions)
	if err != nil {
		return nil, err
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: requestLedger, ActionId: p.config.ActionID}
	consumed := false
	gate := func(effectContext context.Context) error {
		if consumed {
			return ErrOutcomeUnknown
		}
		consumed = true
		return beforeEffect(effectContext)
	}
	reported, err := p.config.ExecuteNative(ctx, request, gate)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !consumed || reported == nil {
		return nil, ErrOutcomeUnknown
	}
	finishTimeout := 30 * time.Second
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil {
		finishTimeout = 2 * time.Minute
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	after, err := p.snapshot(finish, desired)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !sameObserved(after.GetObservation(), reported.GetObservation()) || !imageEqual(after, target) {
		return nil, ErrOutcomeUnknown
	}
	if desired.GetManagedFile().GetKernelModuleBlocklist() != nil {
		if reported.ModuleInitramfsRebuildSucceeded == nil {
			return nil, ErrOutcomeUnknown
		}
		after.ModuleInitramfsRebuildSucceeded = proto.Bool(reported.GetModuleInitramfsRebuildSucceeded())
	}
	verification, err := fileVerification(plan, after, target)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	// Release is irreversible in the ownership ledger. A successful native
	// command is not proof that its boot-image postcondition took effect.
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && !verification.GetManagedFile().GetConverged() {
		return verification, ErrOutcomeUnknown
	}
	if _, err := p.journal.CompleteResourceOwnershipEffect(finish, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return verification, errors.Join(ErrOutcomeUnknown, err)
	}
	if !verification.GetManagedFile().GetConverged() {
		return verification, ErrNotConverged
	}
	return verification, nil
}
func equalClaims(a, b []*resourcev1.ResourceClaim) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
func sameObserved(a, b *resourcev1.ResourceObservation) bool {
	return proto.Equal(a.GetManagedFile(), b.GetManagedFile()) && bytes.Equal(a.GetMetadata().GetNativeRevision(), b.GetMetadata().GetNativeRevision()) && a.GetMetadata().GetBootId() == b.GetMetadata().GetBootId() && a.GetMetadata().GetExecutorIncarnation() == b.GetMetadata().GetExecutorIncarnation()
}

func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBackend(), p.backend) {
		return nil, ErrConflict
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	// An already satisfied resource has no before-image to acquire. Prove its
	// current state without inventing an ownership baseline or native effect.
	if (ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED) && plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && plan.GetManagedFile().GetChange() == resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE {
		after, err := p.snapshot(ctx, desired)
		if err != nil {
			return nil, err
		}
		if err := acquisitionAllowed(p.config.Ownership, after, ledger, plan.GetOperation()); err != nil {
			return nil, err
		}
		target, err := p.target(ctx, desired.GetManagedFile(), after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
		verification, err := fileVerification(plan, after, target)
		if err != nil {
			return nil, err
		}
		if !verification.GetManagedFile().GetConverged() {
			return verification, ErrNotConverged
		}
		return verification, nil
	}
	if ledger == nil || !sameOwner(p.config.Ownership, ledger.GetOwner()) || ledger.GetLastApplied() == nil {
		return nil, ErrConflict
	}
	after, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	var target *agentv1.ResourceOwnershipSnapshot
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED || ledger.GetClaimActionId() != p.config.ActionID {
			return nil, ErrConflict
		}
		target = ledger.GetLastApplied()
		if !managedMatch(target, after, ledger.GetOwnedDimensions()) {
			return nil, ErrConflict
		}
	} else {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED {
			return nil, ErrConflict
		}
		if err := acquisitionAllowed(p.config.Ownership, after, ledger, plan.GetOperation()); err != nil {
			return nil, err
		}
		target, err = p.target(ctx, desired.GetManagedFile(), after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
	}
	if moduleRebuildFailed(ledger.GetLastApplied()) {
		after.ModuleInitramfsRebuildSucceeded = proto.Bool(false)
	}
	verification, err := fileVerification(plan, after, target)
	if err != nil {
		return nil, err
	}
	if !verification.GetManagedFile().GetConverged() {
		return verification, ErrNotConverged
	}
	return verification, nil
}
func fileVerification(plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot) (*resourcev1.ResourceVerification, error) {
	a, b := after.GetObservation().GetManagedFile(), target.GetObservation().GetManagedFile()
	checks := &resourcev1.ManagedFileChecks{PresenceMatches: a.GetExists() == b.GetExists(), ContentMatches: bytes.Equal(a.GetFile().GetSha256(), b.GetFile().GetSha256()), ModeMatches: a.GetFile().GetMode() == b.GetFile().GetMode(), OwnerMatches: a.GetFile().GetUid() == b.GetFile().GetUid() && a.GetFile().GetGid() == b.GetFile().GetGid(), AncestrySafe: len(a.GetAncestrySha256()) == 32 && bytes.Equal(a.GetSecurityMetadataSha256(), b.GetSecurityMetadataSha256())}
	checks.Converged = checks.GetPresenceMatches() && checks.GetContentMatches() && checks.GetModeMatches() && checks.GetOwnerMatches() && checks.GetAncestrySafe()
	fileMatches := checks.GetConverged()
	if plan.GetManagedFile().GetDesired().GetKernelModuleBlocklist() != nil {
		modules := a.GetKernelModuleBlocklist()
		blocked, unloaded, builtIn := modules != nil, modules != nil, false
		for _, module := range modules.GetModules() {
			blocked = blocked && module.GetModprobeBlocked()
			unloaded = unloaded && !module.GetLoaded() && !module.GetBuiltIn()
			builtIn = builtIn || module.GetBuiltIn()
		}
		checks.InitramfsMatches = proto.Bool(initramfsMatches(modules, target))
		if plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
			checks.ModuleLoadsBlocked, checks.ModulesUnloaded = proto.Bool(blocked), proto.Bool(unloaded)
			checks.Converged = checks.Converged && blocked && unloaded && !builtIn
		}
		checks.Converged = checks.Converged && checks.GetInitramfsMatches()
		if after.ModuleInitramfsRebuildSucceeded != nil {
			checks.InitramfsRebuildSucceeded = proto.Bool(after.GetModuleInitramfsRebuildSucceeded())
			checks.Converged = checks.Converged && checks.GetInitramfsRebuildSucceeded()
		}
	}
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	} else if fileMatches && checks.GetInitramfsMatches() && checks.GetModuleLoadsBlocked() && !checks.GetModulesUnloaded() && (checks.InitramfsRebuildSucceeded == nil || checks.GetInitramfsRebuildSucceeded()) {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT
	}
	if fileMatches && checks.GetInitramfsMatches() && plan.GetOperation() != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && (checks.InitramfsRebuildSucceeded == nil || checks.GetInitramfsRebuildSucceeded()) {
		for _, module := range a.GetKernelModuleBlocklist().GetModules() {
			if module.GetBuiltIn() {
				disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE
				break
			}
		}
	}
	pd, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	verification := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: pd[:], After: proto.CloneOf(after.GetObservation()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_ManagedFile{ManagedFile: checks}}
	if err := resource.ValidatePlanVerification(plan, verification); err != nil {
		return nil, fmt.Errorf("verify managed file: %w", err)
	}
	return verification, nil
}
