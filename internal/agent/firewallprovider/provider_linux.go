//go:build linux

// Package firewallprovider manages only dedicated nftables inet tables. It never
// adopts the global firewall, flushes foreign objects, runs nft text, or bypasses
// quarantine. Native effects require a fixed CAP_NET_ADMIN host-network helper.
// Kernel and durable file state cannot commit atomically: PENDING files and an
// UNKNOWN journal fence prohibit automatic replay after any uncertain outcome.
package firewallprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "firewall.zone.v1"

var (
	ErrUnsupported    = errors.New("firewallprovider: unsupported")
	ErrConflict       = errors.New("firewallprovider: ownership or native conflict")
	ErrOutcomeUnknown = errors.New("firewallprovider: native outcome unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("firewallprovider: not converged"))
	validator         = sync.OnceValues(func() (protovalidate.Validator, error) { return protovalidate.New() })
)

type Config struct {
	Journal              *journal.Store
	ExecutorIncarnation  string
	Ownership            *agentv1.ResourceOwnershipBinding
	Platform             *resourcev1.PlatformProduct
	ActionID             string
	DeploymentID         string
	DeviceID             string
	EnrollmentGeneration string
	Native               *agentv1.NativeFirewallProviderConfig
	NativeRead           func(context.Context, *resourcev1.ResourceObservation) (*agentv1.ResourceOwnershipSnapshot, error)
	NativeApply          func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) error
	// Receipts must come from fresh, independently observed allow/deny traffic.
	// Absence is explicitly UNKNOWN, never a successful synthetic packet probe.
	NativeProbe func(context.Context, *resourcev1.FirewallZoneDesired, *resourcev1.ResourceObservation) (*resourcev1.ProbeReceipt, *resourcev1.ProbeReceipt, error)
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
	gate    sync.Mutex
	closed  bool
}

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
func messageDigest(message proto.Message) ([]byte, error) {
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
func Open(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil || config.Journal == nil || config.NativeRead == nil || config.NativeApply == nil || os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	for _, m := range []proto.Message{config.Native, config.Ownership, config.Platform} {
		if err := validateMessage(m); err != nil {
			return nil, err
		}
	}
	if config.Platform.GetOsId() != "ubuntu" && config.Platform.GetOsId() != "fedora" {
		return nil, ErrUnsupported
	}
	for _, marker := range []string{"/run/ostree-booted", "/etc/NIXOS"} {
		if _, err := os.Stat(marker); err == nil {
			return nil, ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	version, err := smallRead("/proc/sys/kernel/osrelease", 128)
	if err != nil {
		return nil, err
	}
	config.Native = proto.CloneOf(config.Native)
	config.Ownership = proto.CloneOf(config.Ownership)
	config.Platform = proto.CloneOf(config.Platform)
	return &Provider{config: config, store: config.Journal, backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_NFTABLES, NativeVersion: strings.TrimSpace(string(version)), ProviderVersion: "1", Product: proto.CloneOf(config.Platform)}}, nil
}
func (p *Provider) Close() error { p.gate.Lock(); defer p.gate.Unlock(); p.closed = true; return nil }
func (p *Provider) ledger(ctx context.Context, ref *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.store.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, ref)
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}
func (p *Provider) observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
	if p.closed {
		return nil, ErrUnsupported
	}
	if err := resource.ValidateDesired(desired); err != nil {
		return nil, err
	}
	if desired.GetFirewallZone() == nil {
		return nil, ErrUnsupported
	}
	o := &resourcev1.ResourceObservation{Ref: proto.CloneOf(desired.GetRef()), Metadata: &resourcev1.ObservationMetadata{ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend)}}
	snapshot, err := p.config.NativeRead(ctx, o)
	if err != nil {
		return nil, err
	}
	if err := validateMessage(snapshot); err != nil {
		return nil, err
	}
	if !proto.Equal(snapshot.GetObservation().GetRef(), desired.GetRef()) || !proto.Equal(snapshot.GetObservation().GetMetadata().GetBackend(), p.backend) || snapshot.GetObservation().GetMetadata().GetExecutorIncarnation() != p.config.ExecutorIncarnation {
		return nil, ErrConflict
	}
	return snapshot, nil
}
func sameOwner(a, b *agentv1.ResourceOwnershipBinding) bool {
	if a == nil || b == nil || len(a.GetSources()) == 0 || len(a.GetSources()) != len(b.GetSources()) {
		return false
	}
	for _, source := range a.GetSources() {
		found := 0
		for _, other := range b.GetSources() {
			if source.GetProfileId() == other.GetProfileId() && source.GetResourceId() == other.GetResourceId() {
				found++
			}
		}
		if found != 1 {
			return false
		}
	}
	return true
}
func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) error {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if before.GetFirewall().GetConflict() || before.GetObservation().GetFirewallZone().GetConflict() {
		return ErrConflict
	}
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		if !sameOwner(owner, ledger.GetOwner()) {
			return ErrConflict
		}
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return ErrConflict
	}
	if (len(before.GetFirewall().GetUserdata()) != 0 || before.GetFirewall().GetPersistenceFile().GetExists()) && (owner.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION || owner.GetPolicy().GetAdoptionApprovalId() == "") {
		return ErrConflict
	}
	return nil
}
func managedMatch(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	return journal.FirewallOwnershipMatches(a, b)
}
func targetSnapshot(desired *resourcev1.FirewallZoneDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation, owner *agentv1.ResourceOwnershipBinding, config *agentv1.NativeFirewallProviderConfig, generation, deployment, device, enrollment string) (*agentv1.ResourceOwnershipSnapshot, error) {
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return nil, ErrUnsupported
	}
	if before.GetFirewall().GetConflict() {
		return nil, ErrConflict
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED || !managedMatch(ledger.GetLastApplied(), before) {
			return nil, ErrConflict
		}
		if ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN {
			return proto.CloneOf(before), nil
		}
		if ledger.GetOwner().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
			return nil, ErrUnsupported
		}
		baseline := proto.CloneOf(ledger.GetBaseline())
		if baseline.GetFirewall().GetConflict() {
			return nil, ErrConflict
		}
		return baseline, nil
	}
	// Keep the protected acquisition lineage across immutable profile revisions.
	// Updating a profile does not replace its signed baseline/release authority.
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		owner = ledger.GetOwner()
	}
	state := &agentv1.FirewallPersistentState{FormatVersion: 1, Desired: proto.CloneOf(desired), Owner: proto.CloneOf(owner), Generation: generation, AppliedBootId: before.GetObservation().GetMetadata().GetBootId(), Phase: agentv1.FirewallPersistencePhase_FIREWALL_PERSISTENCE_PHASE_COMMITTED, DeploymentId: deployment, DeviceId: device, EnrollmentGeneration: enrollment}
	digest, err := messageDigest(config)
	if err != nil {
		return nil, err
	}
	state.ConfigurationSha256 = digest
	if current := before.GetFirewall().GetPersistent(); current != nil && proto.Equal(current.GetDesired(), desired) && sameOwner(current.GetOwner(), owner) && bytes.Equal(current.GetConfigurationSha256(), digest) {
		return proto.CloneOf(before), nil
	}
	compiled, err := compile(state, config)
	if err != nil {
		return nil, err
	}
	target := proto.CloneOf(before)
	native := compiled.snapshot()
	native.PersistenceFile = proto.CloneOf(before.GetFirewall().GetPersistenceFile())
	native.PersistenceXattrs = before.GetFirewall().GetPersistenceXattrs()
	native.NetworkNamespaceSha256 = bytes.Clone(before.GetFirewall().GetNetworkNamespaceSha256())
	native.RulesetGeneration = before.GetFirewall().GetRulesetGeneration()
	var content []byte
	if desired.GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		content, err = (proto.MarshalOptions{Deterministic: true}).Marshal(state)
		if err != nil {
			return nil, err
		}
		if len(content) > 32768 {
			return nil, ErrUnsupported
		}
		native.Persistent = state
	}
	file := fileTarget(persistenceImage(before), content)
	if content != nil && !before.GetFirewall().GetPersistenceFile().GetExists() {
		file.ManagedFileXattrs = before.GetFirewall().GetCreationXattrs()
		file.Observation.GetManagedFile().SecurityMetadataSha256 = nativefile.XattrDigest(file.GetManagedFileXattrs())
	}
	native.PersistenceFile = file.GetObservation().GetManagedFile()
	native.PersistenceContent = content
	native.PersistenceXattrs = file.GetManagedFileXattrs()
	target.Firewall = native
	return target, nil
}
func targetDigest(target *agentv1.ResourceOwnershipSnapshot) ([]byte, error) {
	kernel, err := nativeDigest(target.GetFirewall())
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("lindm.firewall.target.v1\x00"))
	h.Write(kernel)
	h.Write(target.GetFirewall().GetPersistenceContent())
	return h.Sum(nil), nil
}
func (p *Provider) makePlan(desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation, before, target *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.ResourcePlan, error) {
	if proto.Size(before) > 256<<10 || proto.Size(target) > 256<<10 {
		return nil, fmt.Errorf("%w: protected snapshot capacity", ErrUnsupported)
	}
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
	kernel, err := nativeDigest(target.GetFirewall())
	if err != nil {
		return nil, err
	}
	persistent := sha256.Sum256(target.GetFirewall().GetPersistenceContent())
	configuration, err := messageDigest(p.config.Native)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	change := resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_UPDATE
	if len(before.GetFirewall().GetUserdata()) == 0 {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE
	}
	if len(target.GetFirewall().GetUserdata()) == 0 {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_REMOVE_OWNED
	}
	if nativeEqual(before.GetFirewall(), target.GetFirewall()) && bytes.Equal(before.GetFirewall().GetPersistenceContent(), target.GetFirewall().GetPersistenceContent()) {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	}
	var inverse *resourcev1.OwnershipInverseBinding
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_RESTORE_OWNED
		last, err := messageDigest(ledger.GetLastApplied())
		if err != nil {
			return nil, err
		}
		targetHash, err := targetDigest(target)
		if err != nil {
			return nil, err
		}
		inverse = &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last, NativeIdentitySha256: before.GetObservation().GetFirewallZone().GetNativeIdentitySha256(), InverseSha256: targetHash}
	}
	arm := &resourcev1.FirewallZonePlan{Desired: proto.CloneOf(desired.GetFirewallZone()), Before: proto.CloneOf(before.GetObservation().GetFirewallZone()), CompiledRulesetSha256: kernel, ExpectedPersistentSha256: before.GetObservation().GetFirewallZone().GetPersistentSha256(), ExpectedKernelSha256: before.GetObservation().GetFirewallZone().GetKernelRulesSha256(), Inverse: inverse, Change: change, Generation: p.config.ActionID, TargetPersistentSha256: persistent[:], ConfigurationSha256: configuration}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: dd[:], ObservationSha256: od[:], OwnershipRevisionSha256: ld[:], Backend: proto.CloneOf(p.backend), Claims: claims, Before: proto.CloneOf(before.GetObservation()), Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_INTERFACE, resourcev1.ClaimDomain_CLAIM_DOMAIN_FIREWALL_PORT}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_CONNECTIVITY}, Plan: &resourcev1.ResourcePlan_FirewallZone{FirewallZone: arm}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	before, err := p.observe(ctx, desired)
	if err != nil {
		return nil, err
	}
	if !before.GetObservation().GetFirewallZone().GetPersistentReady() {
		return nil, fmt.Errorf("%w: installed persistence helper custody", ErrUnsupported)
	}
	ledger, err := p.ledger(ctx, desired.GetRef())
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, before, ledger, operation); err != nil {
		return nil, err
	}
	target, err := targetSnapshot(desired.GetFirewallZone(), before, ledger, operation, p.config.Ownership, p.config.Native, p.config.ActionID, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
	if err != nil {
		return nil, err
	}
	return p.makePlan(desired, operation, before, target, ledger)
}
func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	if beforeEffect == nil {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	before, err := p.observe(ctx, desired)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(before.GetObservation().GetFirewallZone(), plan.GetBefore().GetFirewallZone()) || before.GetObservation().GetMetadata().GetBootId() != plan.GetBefore().GetMetadata().GetBootId() {
		return nil, ErrConflict
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, before, ledger, plan.GetOperation()); err != nil {
		return nil, err
	}
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil || !bytes.Equal(ld[:], plan.GetOwnershipRevisionSha256()) {
		return nil, errors.Join(ErrConflict, err)
	}
	target, err := targetSnapshot(desired.GetFirewallZone(), before, ledger, plan.GetOperation(), p.config.Ownership, p.config.Native, plan.GetFirewallZone().GetGeneration(), p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
	if err != nil {
		return nil, err
	}
	again, err := p.makePlan(desired, plan.GetOperation(), before, target, ledger)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(again.GetFirewallZone(), plan.GetFirewallZone()) || !proto.Equal(again.GetSafety(), plan.GetSafety()) || !proto.Equal(again.GetBackend(), plan.GetBackend()) || !slices.EqualFunc(again.GetClaims(), plan.GetClaims(), func(a, b *resourcev1.ResourceClaim) bool { return proto.Equal(a, b) }) {
		return nil, ErrConflict
	}
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger, err = p.store.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), before)
		if err != nil {
			return nil, err
		}
	}
	requestLedger := proto.CloneOf(ledger)
	ledger, err = p.store.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), before, []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_RULESET, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_FIREWALL_PERSISTENCE})
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: requestLedger, ActionId: p.config.ActionID, Nonce: nonce}
	consumed := false
	gate := func(effectCtx context.Context) error {
		if consumed {
			return ErrOutcomeUnknown
		}
		consumed = true
		return beforeEffect(effectCtx)
	}
	if err := p.config.NativeApply(ctx, request, gate); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !consumed {
		return nil, ErrOutcomeUnknown
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	after, err := p.observe(finish, desired)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !targetMatches(after, target) || !after.GetObservation().GetFirewallZone().GetPersistentReady() {
		return nil, ErrOutcomeUnknown
	}
	if _, err := p.store.CompleteResourceOwnershipEffect(finish, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return p.verification(finish, plan, after, target)
}
func targetMatches(after, target *agentv1.ResourceOwnershipSnapshot) bool {
	a, b := after.GetFirewall(), target.GetFirewall()
	if after == nil || target == nil || a.GetConflict() || !nativeEqual(a, b) || !bytes.Equal(a.GetPersistenceContent(), b.GetPersistenceContent()) || a.GetPersistenceFile().GetExists() != b.GetPersistenceFile().GetExists() || a.GetPersistenceFile().GetFile().GetUid() != b.GetPersistenceFile().GetFile().GetUid() || a.GetPersistenceFile().GetFile().GetGid() != b.GetPersistenceFile().GetFile().GetGid() || a.GetPersistenceFile().GetFile().GetMode() != b.GetPersistenceFile().GetFile().GetMode() || !bytes.Equal(a.GetPersistenceFile().GetSecurityMetadataSha256(), b.GetPersistenceFile().GetSecurityMetadataSha256()) {
		return false
	}
	if len(b.GetRules()) != 0 && len(b.GetRules()[0].GetRawExpressionsSha256()) != 0 {
		return rawExpressionsMatch(a.GetRules(), b.GetRules())
	}
	return true
}
func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	p.gate.Lock()
	defer p.gate.Unlock()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	after, err := p.observe(ctx, desired)
	if err != nil {
		return nil, err
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	if after.GetFirewall().GetConflict() && ledger.GetLastApplied() != nil {
		return p.verification(ctx, plan, after, ledger.GetLastApplied())
	}
	var target *agentv1.ResourceOwnershipSnapshot
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			return nil, ErrConflict
		}
		target = ledger.GetLastApplied()
	} else {
		target, err = targetSnapshot(desired.GetFirewallZone(), after, ledger, plan.GetOperation(), p.config.Ownership, p.config.Native, plan.GetFirewallZone().GetGeneration(), p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration)
		if err != nil {
			return nil, err
		}
	}
	return p.verification(ctx, plan, after, target)
}
func (p *Provider) verification(ctx context.Context, plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot) (*resourcev1.ResourceVerification, error) {
	unknown := func(reason string) *resourcev1.ProbeReceipt {
		digest := sha256.Sum256([]byte(reason))
		return &resourcev1.ProbeReceipt{ProbeId: p.config.ActionID, ObservedAt: timestamppb.Now(), EvidenceSha256: digest[:], Reason: reason}
	}
	allow, deny := unknown("independent allow packet probe unavailable"), unknown("independent deny packet probe unavailable")
	// Guard confirmation precedes the final COMMITTED-file readback. A receipt
	// must bind that exact native generation in NativeProbe, not be retimestamped
	// to pretend the later read happened first.
	if p.config.NativeProbe != nil {
		var err error
		allow, deny, err = p.config.NativeProbe(ctx, plan.GetFirewallZone().GetDesired(), after.GetObservation())
		if err != nil {
			return nil, err
		}
		now := time.Now()
		earliest := now.Add(-time.Minute)
		if planned := plan.GetBefore().GetMetadata().GetObservedAt().AsTime(); planned.After(earliest) {
			earliest = planned
		}
		for _, receipt := range []*resourcev1.ProbeReceipt{allow, deny} {
			if err := validateMessage(receipt); err != nil {
				return nil, err
			}
			if receipt.GetObservedAt().AsTime().Before(earliest) || receipt.GetObservedAt().AsTime().After(now.Add(time.Second)) {
				return nil, ErrConflict
			}
		}
	}
	checks := &resourcev1.FirewallZoneChecks{PersistentMatches: bytes.Equal(after.GetFirewall().GetPersistenceContent(), target.GetFirewall().GetPersistenceContent()) && after.GetObservation().GetFirewallZone().GetPersistentReady(), RuntimeMatches: !after.GetFirewall().GetConflict() && nativeEqual(after.GetFirewall(), target.GetFirewall()), InterfaceBindingsMatch: !after.GetFirewall().GetConflict(), AllowPacketProbe: allow, DenyPacketProbe: deny}
	checks.Converged = checks.GetPersistentMatches() && checks.GetRuntimeMatches() && checks.GetInterfaceBindingsMatch() && allow.GetPassed() && deny.GetPassed()
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	} else if p.config.NativeProbe == nil {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN
	}
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	verification := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: digest[:], After: proto.CloneOf(after.GetObservation()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_FirewallZone{FirewallZone: checks}}
	if err := resource.ValidatePlanVerification(plan, verification); err != nil {
		return nil, err
	}
	if !checks.GetConverged() {
		return verification, ErrNotConverged
	}
	return verification, nil
}
