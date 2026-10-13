//go:build linux

// Package sysctlprovider owns approved individual procfs values and derived
// sysctl.d stanzas. It does not execute sysctl, accept configuration text, load
// modules or grant power/security authority. Root approval is an exact key set.
// Writes run in a separately confined helper; the executor remains read-only.
// Kernel writes and persistent file replacement are not one atomic transaction:
// any uncertain/partial outcome leaves protected ownership UNKNOWN, never replayed.
package sysctlprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "sysctl.v1"

var (
	ErrUnsupported    = errors.New("sysctlprovider: unsupported")
	ErrConflict       = errors.New("sysctlprovider: precondition conflict")
	ErrOutcomeUnknown = errors.New("sysctlprovider: native outcome unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("sysctlprovider: not converged"))
	// ErrAdoptionRequired refuses CREATE_ONLY acquisition of a live kernel
	// setting (every key exists). It is also ErrConflict.
	ErrAdoptionRequired = fmt.Errorf("sysctlprovider: adoption_required: %w", ErrConflict)
)

// Config contains trusted signed execution context; Native is root-provisioned
// protobuf policy, never a remote resource's arbitrary capability declaration.
type Config struct {
	Journal              *journal.Store
	ExecutorIncarnation  string
	Ownership            *agentv1.ResourceOwnershipBinding
	Platform             *resourcev1.PlatformProduct
	ActionID             string
	DeploymentID         string
	DeviceID             string
	EnrollmentGeneration string
	Native               *agentv1.NativeSysctlProviderConfig
	NativeApply          func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) error
}
type ownershipStore interface {
	LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error)
	ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
	BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error)
	CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
}
type Provider struct {
	config  Config
	store   ownershipStore
	backend *resourcev1.BackendSelection
	observe func(context.Context, *resourcev1.SysctlDesired) (*agentv1.ResourceOwnershipSnapshot, error)
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
	if ctx == nil || config.Journal == nil || config.NativeApply == nil || config.Ownership == nil || config.Platform == nil || os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	for _, message := range []proto.Message{config.Native, config.Ownership, config.Platform} {
		if err := validateMessage(message); err != nil {
			return nil, err
		}
	}
	for _, key := range config.Native.GetAllowedKeys() {
		if authorityKey(key) {
			return nil, fmt.Errorf("%w: authority key %s", ErrUnsupported, key)
		}
	}
	backend, err := nativeBackend(ctx, config.Platform)
	if err != nil {
		return nil, err
	}
	p := &Provider{config: config, store: config.Journal, backend: backend}
	p.config.Native = proto.CloneOf(config.Native)
	p.config.Ownership = proto.CloneOf(config.Ownership)
	p.config.Platform = proto.CloneOf(config.Platform)
	p.observe = p.snapshot
	return p, nil
}
func (p *Provider) Close() error { p.gate.Lock(); defer p.gate.Unlock(); p.closed = true; return nil }
func (p *Provider) validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if p.closed {
		return ErrUnsupported
	}
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	d := desired.GetSysctl()
	if d == nil || authorityKey(d.GetKey()) || !slices.Contains(p.config.Native.GetAllowedKeys(), d.GetKey()) {
		return ErrUnsupported
	}
	return nil
}
func (p *Provider) ledger(ctx context.Context, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.store.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, ref)
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}
func sysctlRef(key string) *resourcev1.ResourceRef {
	return &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: key}
}
func desiredState(d *resourcev1.SysctlDesired) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: sysctlRef(d.GetKey()), State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: proto.CloneOf(d)}}
}
func (p *Provider) snapshot(ctx context.Context, d *resourcev1.SysctlDesired) (*agentv1.ResourceOwnershipSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proc, err := openProc(d.GetKey(), false)
	if err != nil {
		return nil, err
	}
	value, readErr := proc.read()
	closeErr := proc.close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	o := &resourcev1.ResourceObservation{Ref: sysctlRef(d.GetKey()), Metadata: &resourcev1.ObservationMetadata{BootId: proc.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.New(time.Now()), Backend: proto.CloneOf(p.backend), NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
	file, err := nativefile.Capture(StanzaPath(d.GetKey()), o)
	if err != nil {
		return nil, err
	}
	if err := validateOwnedStanza(d.GetKey(), file.GetManagedFileContent()); err != nil {
		return nil, err
	}
	graph, err := readPersistence(d.GetKey(), nil, false)
	if err != nil {
		return nil, err
	}
	state := file.GetObservation().GetManagedFile()
	observed := &resourcev1.SysctlObservation{Key: d.GetKey(), Value: proto.String(value), PersistentValue: graph.value, OwnedPersistenceFile: proto.CloneOf(state.GetFile()), PersistenceGraphSha256: graph.graph, NativeIdentitySha256: proc.identity, PersistenceFileState: proto.CloneOf(state), PersistentSource: graph.source, PersistenceConflict: graph.conflict}
	o.Observed = &resourcev1.ResourceObservation_Sysctl{Sysctl: observed}
	digest, err := messageDigest(observed)
	if err != nil {
		return nil, err
	}
	o.Metadata.NativeRevision = digest
	result := &agentv1.ResourceOwnershipSnapshot{Observation: o, SysctlPersistence: &agentv1.SysctlPersistenceSnapshot{State: proto.CloneOf(state), Content: bytes.Clone(file.GetManagedFileContent()), Xattrs: file.GetManagedFileXattrs()}}
	if err := resource.ValidateObservation(o); err != nil {
		return nil, err
	}
	return result, nil
}
func messageDigest(message proto.Message) ([]byte, error) {
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
func sameSnapshot(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	return proto.Equal(a.GetObservation().GetSysctl(), b.GetObservation().GetSysctl()) && proto.Equal(a.GetSysctlPersistence(), b.GetSysctlPersistence())
}

// Observe reads the runtime and persistent value without effects.
func (p *Provider) Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	before, err := p.observe(ctx, desired.GetSysctl())
	if err != nil {
		return nil, err
	}
	return before.GetObservation(), nil
}

func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return nil, ErrUnsupported
	}
	ledger, err := p.ledger(ctx, desired.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	before, err := p.observe(ctx, desired.GetSysctl())
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, ledger, operation); err != nil {
		return nil, err
	}
	target, err := p.target(ctx, desired.GetSysctl(), before, ledger, operation)
	if err != nil {
		return nil, err
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && desired.GetSysctl().GetPersistent() {
		graph, err := readPersistence(desired.GetSysctl().GetKey(), target.GetSysctlPersistence().GetContent(), true)
		if err != nil {
			return nil, err
		}
		if graph.conflict || graph.value == nil || *graph.value != normalizeValue(desired.GetSysctl().GetValue()) {
			source := "no effective assignment"
			switch {
			case graph.conflict:
				source = "conflicting assignments"
			case graph.source != nil:
				source = *graph.source
			}
			return nil, fmt.Errorf("%w: later effective sysctl.d assignment (%s)", ErrConflict, source)
		}
	}
	change := resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_UPDATE
	if targetMatches(before, target) {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	var inverse *resourcev1.OwnershipInverseBinding
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_RESTORE_OWNED
		inverse, err = inverseBinding(ledger, before, target)
		if err != nil {
			return nil, err
		}
	}
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	beforeDigest, err := resource.ObservationDigest(before.GetObservation())
	if err != nil {
		return nil, err
	}
	ledgerDigest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: desiredDigest[:], ObservationSha256: beforeDigest[:], Backend: proto.CloneOf(p.backend), Claims: claims, OwnershipRevisionSha256: ledgerDigest[:], Before: before.GetObservation(), Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSCTL}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED}, Plan: &resourcev1.ResourcePlan_Sysctl{Sysctl: &resourcev1.SysctlPlan{Desired: proto.CloneOf(desired.GetSysctl()), Before: proto.CloneOf(before.GetObservation().GetSysctl()), Change: change, Inverse: inverse}}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
