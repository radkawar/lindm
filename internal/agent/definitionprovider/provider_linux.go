//go:build linux

// Package definitionprovider owns a closed systemd definition surface: UTC daily
// or monotonic timers targeting existing canonical services, and four service
// drop-in settings. It never supplies service commands or restarts target
// services. File writes use shared descriptor custody in nativefile; systemd
// effects use a root-pinned system bus connection in an exact-path helper.
// Baselines precede authorization and uncertain effects remain journal UNKNOWN.
// Release restores only unchanged owned file/link/runtime dimensions; it cannot
// undo service work already triggered by a timer, reverse a running process's
// NoNewPrivileges, or reconstruct historical service state.
package definitionprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "systemd.definition.v1"

var (
	ErrUnsupported     = errors.New("definitionprovider: unsupported")
	ErrProtected       = errors.New("definitionprovider: protected_unit_or_path")
	ErrConflict        = errors.New("definitionprovider: ownership_or_precondition_conflict")
	ErrBaselineUnknown = errors.New("definitionprovider: ownership_baseline_unknown")
	ErrOutcomeUnknown  = errors.New("definitionprovider: outcome_unknown")
	ErrNotConverged    = errors.Join(resource.ErrNotConverged, errors.New("definitionprovider: not_converged"))
)

type ownershipStore interface {
	LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error)
	ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
	BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error)
	CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
}

var _ ownershipStore = (*journal.Store)(nil)

// Config contains verified executor context and a fixed transient-helper call,
// never profile-supplied native paths, command strings or sandbox properties.
type Config struct {
	Journal                                                ownershipStore
	ExecutorIncarnation                                    string
	Ownership                                              *agentv1.ResourceOwnershipBinding
	Platform                                               *resourcev1.PlatformProduct
	ActionID, DeploymentID, DeviceID, EnrollmentGeneration string
	ExecuteNative                                          func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)
}

// NativeConfig is root-local helper context. ScratchDirectory must be a private
// per-action directory supplied by the fixed helper, not transported policy.
type NativeConfig struct {
	ExecutorIncarnation string
	Platform            *resourcev1.PlatformProduct
	ScratchDirectory    string
}
type Provider struct {
	config  Config
	manager nativeManager
	backend *resourcev1.BackendSelection
	boot    string
	gate    sync.Mutex
	closed  bool
}

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
func resourceObservationValid(snapshot *agentv1.ResourceOwnershipSnapshot) error {
	if err := resource.ValidateObservation(snapshot.GetObservation()); err != nil {
		return err
	}
	return validateMessage(snapshot)
}
func canonicalID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
func nativeContext(ctx context.Context, config NativeConfig) (*Provider, error) {
	if ctx == nil || os.Geteuid() != 0 || !canonicalID(config.ExecutorIncarnation) {
		return nil, ErrUnsupported
	}
	if err := validateMessage(config.Platform); err != nil {
		return nil, err
	}
	for _, path := range []string{"/run/ostree-booted", "/etc/NIXOS", "/etc/transactional-update.conf"} {
		if _, err := os.Stat(path); err == nil {
			return nil, ErrUnsupported
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	// Ubuntu 24.04 and Fedora 44 were qualified on systemd 255 and newer; EL 9
	// ships systemd 252 for its whole life, whose timer and unit-file D-Bus
	// interface and systemd-analyze verify options this provider uses.
	minimum := 255
	switch config.Platform.GetOsId() {
	case "ubuntu", "fedora", "debian":
	case "rhel", "almalinux":
		if !strings.HasPrefix(config.Platform.GetVersion(), "9.") {
			return nil, ErrUnsupported
		}
		minimum = 252
	default:
		return nil, ErrUnsupported
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	bootID := strings.TrimSpace(string(boot))
	if !canonicalID(bootID) {
		return nil, ErrUnsupported
	}
	manager, err := openBus(ctx, minimum)
	if err != nil {
		return nil, err
	}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SYSTEMD, NativeVersion: manager.Version(), ProviderVersion: Capability, Product: proto.CloneOf(config.Platform)}
	if err := validateMessage(backend); err != nil {
		_ = manager.Close()
		return nil, err
	}
	return &Provider{config: Config{ExecutorIncarnation: config.ExecutorIncarnation, Platform: proto.CloneOf(config.Platform)}, manager: manager, backend: backend, boot: bootID}, nil
}
func Open(ctx context.Context, config Config) (*Provider, error) {
	if config.Journal == nil || config.Ownership == nil || config.ExecuteNative == nil {
		return nil, ErrUnsupported
	}
	for _, id := range []string{config.ActionID, config.DeploymentID, config.DeviceID, config.EnrollmentGeneration} {
		if !canonicalID(id) {
			return nil, ErrUnsupported
		}
	}
	if err := validateMessage(config.Ownership); err != nil {
		return nil, err
	}
	p, err := nativeContext(ctx, NativeConfig{ExecutorIncarnation: config.ExecutorIncarnation, Platform: config.Platform})
	if err != nil {
		return nil, err
	}
	p.config = config
	return p, nil
}
func (p *Provider) Close() error {
	p.gate.Lock()
	defer p.gate.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.manager.Close()
}
func (p *Provider) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrUnsupported
	}
	p.gate.Lock()
	if p.closed {
		p.gate.Unlock()
		return nil, nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	if err := ctx.Err(); err != nil {
		cancel()
		p.gate.Unlock()
		return nil, nil, err
	}
	return ctx, func() { cancel(); p.gate.Unlock() }, nil
}
func (p *Provider) observationTemplate(ref *resourcev1.ResourceRef) *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{Ref: proto.CloneOf(ref), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
}
func (p *Provider) Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	s, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	return s.GetObservation(), nil
}
func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := validateDesired(desired); err != nil {
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
	target, err := targetImage(ctx, desired, before, ledger, operation)
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
	checks := definitionChecks(desired, operation, before, target)
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && imageEqual(before, target) && !checks.GetEffectiveOptionsMatch() {
		return nil, fmt.Errorf("%w: another native definition overrides the owned options", ErrConflict)
	}
	change := resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_UPDATE
	if checks.GetConverged() {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE
	} else if !target.GetDefinitionFile().GetState().GetExists() {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_REMOVE_OWNED
	} else if !before.GetDefinitionFile().GetState().GetExists() {
		change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE
	}
	candidate := sha256Bytes(target.GetDefinitionFile().GetContent())
	native := &resourcev1.SystemdDefinitionPlan{Desired: proto.CloneOf(desired.GetSystemdDefinition()), Before: proto.CloneOf(before.GetObservation().GetSystemdDefinition()), Change: change, RenderedCandidateSha256: candidate, DaemonReload: !imageEqual(before, target)}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		native.Inverse, err = inverseBinding(before, target, ledger)
		if err != nil {
			return nil, err
		}
		if change != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE {
			native.Change = resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_RESTORE_OWNED
		}
	}
	confirmation := resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED
	if before.GetDefinitionFile().GetState().GetExists() && (ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED) {
		confirmation = resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_INDEPENDENT_OPERATOR
	}
	plan := &resourcev1.ResourcePlan{Ref: proto.CloneOf(desired.GetRef()), Operation: operation, DesiredSha256: dd[:], ObservationSha256: od[:], Backend: proto.CloneOf(p.backend), Claims: claims, OwnershipRevisionSha256: ld[:], Before: proto.CloneOf(before.GetObservation()), Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE, resourcev1.ClaimDomain_CLAIM_DOMAIN_SERVICE_RUNTIME}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: confirmation}, Plan: &resourcev1.ResourcePlan_SystemdDefinition{SystemdDefinition: native}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if beforeEffect == nil {
		return nil, ErrUnsupported
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	if !proto.Equal(plan.GetBackend(), p.backend) {
		return nil, ErrConflict
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
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
	if !proto.Equal(before.GetObservation().GetSystemdDefinition(), plan.GetBefore().GetSystemdDefinition()) || !bytes.Equal(before.GetObservation().GetMetadata().GetNativeRevision(), plan.GetBefore().GetMetadata().GetNativeRevision()) || before.GetObservation().GetMetadata().GetBootId() != plan.GetBefore().GetMetadata().GetBootId() {
		return nil, ErrConflict
	}
	if err := acquisitionAllowed(p.config.Ownership, before, ledger, plan.GetOperation()); err != nil {
		return nil, err
	}
	target, err := targetImage(ctx, desired, before, ledger, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	replanned, err := p.makePlan(desired, plan.GetOperation(), before, target, ledger)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(replanned.GetSystemdDefinition(), plan.GetSystemdDefinition()) || !proto.Equal(replanned.GetSafety(), plan.GetSafety()) || !sameClaims(replanned.GetClaims(), plan.GetClaims()) {
		return nil, ErrConflict
	}
	requestLedger := proto.CloneOf(ledger)
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger, err = p.config.Journal.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), before)
		if err != nil {
			return nil, err
		}
		requestLedger = proto.CloneOf(ledger)
	}
	owned := dimensions(desired.GetSystemdDefinition())
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		owned = append([]agentv1.ResourceOwnedDimension(nil), ledger.GetOwnedDimensions()...)
	}
	ledger, err = p.config.Journal.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), before, owned)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: requestLedger, ActionId: p.config.ActionID, Nonce: nonce}
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
	finishContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	after, err := p.snapshot(finishContext, desired)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !sameObserved(after, reported) {
		return nil, ErrOutcomeUnknown
	}
	verification, err := definitionVerification(plan, after, target)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !verification.GetSystemdDefinition().GetConverged() {
		return verification, ErrOutcomeUnknown
	}
	if _, err := p.config.Journal.CompleteResourceOwnershipEffect(finishContext, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return verification, errors.Join(ErrOutcomeUnknown, err)
	}
	return verification, nil
}
func sameClaims(a, b []*resourcev1.ResourceClaim) bool {
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
func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	ledger, err := p.ledger(ctx, plan.GetRef())
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	after, err := p.snapshot(ctx, desired)
	if err != nil {
		return nil, err
	}
	var target *agentv1.ResourceOwnershipSnapshot
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED || ledger.GetClaimActionId() != p.config.ActionID || !journal.DefinitionOwnershipMatches(ledger.GetLastApplied(), after, ledger.GetOwnedDimensions()) {
			return nil, ErrConflict
		}
		target = ledger.GetLastApplied()
	} else {
		if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED && !journal.DefinitionOwnershipMatches(ledger.GetLastApplied(), after, ledger.GetOwnedDimensions()) {
			return nil, ErrConflict
		}
		target, err = targetImage(ctx, desired, after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
	}
	verification, err := definitionVerification(plan, after, target)
	if err != nil {
		return nil, err
	}
	if !verification.GetSystemdDefinition().GetConverged() {
		return verification, ErrNotConverged
	}
	return verification, nil
}
func definitionChecks(desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation, after, target *agentv1.ResourceOwnershipSnapshot) *resourcev1.SystemdDefinitionChecks {
	a, b := after.GetObservation().GetSystemdDefinition(), target.GetObservation().GetSystemdDefinition()
	checks := &resourcev1.SystemdDefinitionChecks{DefinitionMatches: imageEqual(after, target), TargetServiceExists: a.GetTargetServiceExists(), DaemonReloadCompleted: !a.GetDaemonReloadPending(), TimerStateMatches: true, EffectiveOptionsMatch: true}
	if desired.GetSystemdDefinition().GetTimer() != nil {
		checks.TimerStateMatches = a.TimerEnabled != nil && a.TimerActive != nil && a.GetTimerEnabled() == b.GetTimerEnabled() && a.GetTimerActive() == b.GetTimerActive() && !a.GetTimerJobPending() && a.GetTimerInstallProjectionComplete()
		if b.GetExists() {
			checks.EffectiveOptionsMatch = proto.Equal(a.GetEffective().GetTimer().GetSchedule(), b.GetEffective().GetTimer().GetSchedule()) && proto.Equal(a.GetEffective().GetTimer().GetService(), b.GetEffective().GetTimer().GetService())
		}
	} else if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		checks.EffectiveOptionsMatch = proto.Equal(a.GetEffectiveOptions(), b.GetEffectiveOptions())
	} else if desired.GetSystemdDefinition().GetPresence() == resourcev1.Presence_PRESENCE_PRESENT {
		checks.EffectiveOptionsMatch = optionsMatch(desired.GetSystemdDefinition().GetDropIn(), a.GetEffectiveOptions())
	}
	checks.Converged = checks.GetDefinitionMatches() && checks.GetEffectiveOptionsMatch() && checks.GetTargetServiceExists() && checks.GetTimerStateMatches() && checks.GetDaemonReloadCompleted()
	return checks
}
func definitionVerification(plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot) (*resourcev1.ResourceVerification, error) {
	checks := definitionChecks(resource.PlanDesired(plan), plan.GetOperation(), after, target)
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	pd, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	verification := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: pd[:], After: proto.CloneOf(after.GetObservation()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_SystemdDefinition{SystemdDefinition: checks}}
	if err := resource.ValidatePlanVerification(plan, verification); err != nil {
		return nil, fmt.Errorf("verify systemd definition: %w", err)
	}
	return verification, nil
}
