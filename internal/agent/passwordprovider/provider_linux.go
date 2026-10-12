//go:build linux

package passwordprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "password.policy.v1"

type Config struct {
	Journal              *journal.Store
	ExecutorIncarnation  string
	Ownership            *agentv1.ResourceOwnershipBinding
	Platform             *resourcev1.PlatformProduct
	ActionID             string
	DeploymentID         string
	DeviceID             string
	EnrollmentGeneration string
	Native               *agentv1.NativePasswordProviderConfig
	ExecuteNative        func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)
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
	run     commandRunner
	observe func(context.Context, *resourcev1.PasswordPolicyDesired) (*agentv1.ResourceOwnershipSnapshot, error)
	dropins func() (map[string]string, []byte, error)
	mu      sync.Mutex
	closed  bool
}

var _ resourceprovider.Provider = (*Provider)(nil)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) { return protovalidate.New() })

func validateMessage(m proto.Message) error {
	if m == nil || !m.ProtoReflect().IsValid() {
		return ErrUnsupported
	}
	if err := protodata.ValidateClosed(m.ProtoReflect()); err != nil {
		return err
	}
	v, err := validator()
	if err != nil {
		return err
	}
	return v.Validate(m)
}
func Open(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil || config.Journal == nil || config.ExecuteNative == nil || config.ActionID == "" || os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	for _, m := range []proto.Message{config.Native, config.Ownership, config.Platform} {
		if err := validateMessage(m); err != nil {
			return nil, err
		}
	}
	if err := checkPlatform(config.Platform); err != nil {
		return nil, err
	}
	if err := accessGuard(ctx, config.Native, runNative); err != nil {
		return nil, err
	}
	backend := passwordBackend(config.Platform)
	version, err := managerVersion(ctx, config.Platform, runNative)
	if err != nil {
		return nil, err
	}
	p := &Provider{config: config, store: config.Journal, run: runNative, dropins: readQualityDropins, backend: &resourcev1.BackendSelection{Backend: backend, NativeVersion: version, ProviderVersion: "1", Product: proto.CloneOf(config.Platform)}}
	p.config.Native = proto.CloneOf(config.Native)
	p.config.Platform = proto.CloneOf(config.Platform)
	p.config.Ownership = proto.CloneOf(config.Ownership)
	p.observe = p.snapshot
	return p, nil
}
func (p *Provider) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; return nil }
func passwordRef() *resourcev1.ResourceRef {
	return &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY, CanonicalKey: "system/local-auth"}
}
func (p *Provider) validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if p.closed {
		return ErrUnsupported
	}
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	if desired.GetPasswordPolicy() == nil {
		return ErrUnsupported
	}
	return policySupported(desired.GetPasswordPolicy(), p.config.Platform)
}
func (p *Provider) ledger(ctx context.Context) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.store.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, passwordRef())
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}
func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) error {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		if owner == nil || len(owner.GetSources()) != len(ledger.GetOwner().GetSources()) {
			return ErrConflict
		}
		for _, source := range owner.GetSources() {
			found := false
			for _, other := range ledger.GetOwner().GetSources() {
				if source.GetProfileId() == other.GetProfileId() && source.GetResourceId() == other.GetResourceId() {
					found = true
					break
				}
			}
			if !found {
				return ErrConflict
			}
		}
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE || owner.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION || owner.GetPolicy().GetAdoptionApprovalId() == "" {
		return ErrConflict
	}
	return nil
}
func (p *Provider) target(ctx context.Context, d *resourcev1.PasswordPolicyDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger = nil
	}
	target, err := targetSnapshot(d, before, ledger, operation)
	if err != nil {
		return nil, err
	}
	if nativePAMProduct(p.config.Platform) {
		if err := targetNativePAM(before, target, ledger); err != nil {
			return nil, err
		}
	}
	if pamConfigProduct(p.config.Platform) {
		if err := targetPamConfig(ctx, before, target, p.run); err != nil {
			return nil, err
		}
	}
	for _, file := range target.GetPasswordPolicy().GetFiles() {
		if file.GetState().GetExists() && !nativeFile(before, file.GetKind()).GetState().GetExists() {
			image := fileSnapshot(target, file)
			if err := nativefile.CreationMetadata(ctx, image); err != nil {
				return nil, err
			}
			file.State = proto.CloneOf(image.GetObservation().GetManagedFile())
			file.Xattrs = image.GetManagedFileXattrs()
		}
	}
	dropins, dropHash, err := p.dropins()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(dropHash, target.GetPasswordPolicy().GetQualityDropinsSha256()) {
		return nil, ErrConflict
	}
	effective, err := effectivePolicy(target, dropins)
	if err != nil {
		return nil, err
	}
	target.Observation.GetPasswordPolicy().Effective = effective
	if err := validateMessage(effective); err != nil {
		return nil, err
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE && ledger.GetOwner().GetPolicy().GetRelease() == resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED && !journal.PasswordOwnershipMatches(ledger.GetBaseline(), target, ledger.GetOwnedDimensions()) {
		return nil, ErrConflict
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && !desiredMatches(d, effective) {
		return nil, ErrConflict
	}
	if err := managerChangeSupported(ctx, p.config.Platform, before, target, p.run); err != nil {
		return nil, err
	}
	return target, nil
}
func desiredMatches(d, effective *resourcev1.PasswordPolicyDesired) bool {
	if d == nil || effective == nil {
		return false
	}
	a, b := d.ProtoReflect(), effective.ProtoReflect()
	for _, field := range fields(d) {
		fd := a.Descriptor().Fields().ByNumber(protoreflect.FieldNumber(field))
		if !b.Has(fd) || a.Get(fd).Interface() != b.Get(fd).Interface() {
			return false
		}
	}
	return true
}

// Observe reads the native password policy without effects.
func (p *Provider) Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	before, err := p.observe(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	return before.GetObservation(), nil
}

func (p *Provider) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return nil, ErrUnsupported
	}
	ledger, err := p.ledger(ctx)
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, ledger, operation); err != nil {
		return nil, err
	}
	before, err := p.observe(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	target, err := p.target(ctx, desired.GetPasswordPolicy(), before, ledger, operation)
	if err != nil {
		return nil, err
	}
	if err := managerChangeSupported(ctx, p.config.Platform, before, target, p.run); err != nil {
		return nil, err
	}
	return p.makePlan(desired, operation, before, target, ledger)
}
func candidateDigest(target *agentv1.ResourceOwnershipSnapshot) ([]byte, error) {
	return digestMessage(target.GetPasswordPolicy())
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
	candidate, err := candidateDigest(target)
	if err != nil {
		return nil, err
	}
	native := &resourcev1.PasswordPolicyPlan{Desired: proto.CloneOf(desired.GetPasswordPolicy()), Fields: fields(desired.GetPasswordPolicy()), PamOwner: before.GetPasswordPolicy().GetManagerProfile(), CandidateSha256: candidate}
	for _, file := range target.GetPasswordPolicy().GetFiles() {
		if file.GetState().GetExists() {
			native.OwnedProfileObjects = append(native.OwnedProfileObjects, proto.CloneOf(file.GetState().GetFile()))
		}
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && targetMatches(before, target) {
		// Converged native policy needs no effect or start grant.
		native.Fields = nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		native.Fields = dimensionFields(ledger.GetOwnedDimensions())
		last, err := digestMessage(ledger.GetLastApplied())
		if err != nil {
			return nil, err
		}
		native.Inverse = &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last, NativeIdentitySha256: bytes.Clone(before.GetPasswordPolicy().GetManagerGenerationSha256()), InverseSha256: bytes.Clone(candidate)}
	}
	plan := &resourcev1.ResourcePlan{Ref: passwordRef(), Operation: operation, DesiredSha256: dd[:], ObservationSha256: od[:], Backend: proto.CloneOf(p.backend), Claims: claims, OwnershipRevisionSha256: ld[:], Before: proto.CloneOf(before.GetObservation()), Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_PAM_OWNER}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_INDEPENDENT_OPERATOR}, Plan: &resourcev1.ResourcePlan_PasswordPolicy{PasswordPolicy: native}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
func sameObserved(a, b *resourcev1.ResourceObservation) bool {
	return proto.Equal(a.GetPasswordPolicy(), b.GetPasswordPolicy()) && a.GetMetadata().GetBootId() == b.GetMetadata().GetBootId() && a.GetMetadata().GetExecutorIncarnation() == b.GetMetadata().GetExecutorIncarnation() && bytes.Equal(a.GetMetadata().GetNativeRevision(), b.GetMetadata().GetNativeRevision())
}
func targetMatches(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	if a.GetPasswordPolicy().GetManagerProfile() != b.GetPasswordPolicy().GetManagerProfile() || !slices.Equal(a.GetPasswordPolicy().GetEnabledFeatures(), b.GetPasswordPolicy().GetEnabledFeatures()) || len(a.GetPasswordPolicy().GetFiles()) != len(b.GetPasswordPolicy().GetFiles()) {
		return false
	}
	if !bytes.Equal(a.GetPasswordPolicy().GetManagerProfileSha256(), b.GetPasswordPolicy().GetManagerProfileSha256()) || !bytes.Equal(a.GetPasswordPolicy().GetQualityDropinsSha256(), b.GetPasswordPolicy().GetQualityDropinsSha256()) {
		return false
	}
	if a.GetPasswordPolicy().GetManagerProfile() == "pam-config" && !bytes.Equal(a.GetPasswordPolicy().GetManagerGenerationSha256(), b.GetPasswordPolicy().GetManagerGenerationSha256()) {
		return false
	}
	for _, f := range a.GetPasswordPolicy().GetFiles() {
		other := nativeFile(b, f.GetKind())
		if other == nil || f.GetState().GetExists() != other.GetState().GetExists() || !bytes.Equal(f.GetContent(), other.GetContent()) || f.GetState().GetFile().GetMode() != other.GetState().GetFile().GetMode() || f.GetState().GetFile().GetUid() != other.GetState().GetFile().GetUid() || f.GetState().GetFile().GetGid() != other.GetState().GetFile().GetGid() || !bytes.Equal(f.GetState().GetSecurityMetadataSha256(), other.GetState().GetSecurityMetadataSha256()) {
			return false
		}
	}
	return true
}
func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if beforeEffect == nil || p.config.ExecuteNative == nil {
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
	ledger, err := p.ledger(ctx)
	if err != nil {
		return nil, err
	}
	if err := acquisitionAllowed(p.config.Ownership, ledger, plan.GetOperation()); err != nil {
		return nil, err
	}
	ld, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ld[:], plan.GetOwnershipRevisionSha256()) {
		return nil, ErrConflict
	}
	before, err := p.observe(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	if !sameObserved(before.GetObservation(), plan.GetBefore()) {
		return nil, ErrConflict
	}
	target, err := p.target(ctx, desired.GetPasswordPolicy(), before, ledger, plan.GetOperation())
	if err != nil {
		return nil, err
	}
	replanned, err := p.makePlan(desired, plan.GetOperation(), before, target, ledger)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(replanned.GetPasswordPolicy(), plan.GetPasswordPolicy()) || !proto.Equal(replanned.GetSafety(), plan.GetSafety()) || !equalClaims(replanned.GetClaims(), plan.GetClaims()) {
		return nil, ErrConflict
	}
	requestLedger := proto.CloneOf(ledger)
	if ledger == nil || ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
		ledger, err = p.store.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), before)
		if err != nil {
			return nil, err
		}
		requestLedger = proto.CloneOf(ledger)
	}
	dimensions := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_PASSWORD_MANAGER}
	for _, field := range fields(desired.GetPasswordPolicy()) {
		dimensions = append(dimensions, dimension(field))
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		dimensions = ledger.GetOwnedDimensions()
	}
	ledger, err = p.store.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), before, dimensions)
	if err != nil {
		return nil, err
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: requestLedger, ActionId: p.config.ActionID}
	consumed := false
	gate := func(c context.Context) error {
		if consumed {
			return ErrOutcomeUnknown
		}
		consumed = true
		return beforeEffect(c)
	}
	reported, err := p.config.ExecuteNative(ctx, request, gate)
	if err != nil || !consumed || reported == nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	after, err := p.observe(finish, desired.GetPasswordPolicy())
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !sameObserved(after.GetObservation(), reported.GetObservation()) || !targetMatches(after, target) {
		return nil, ErrOutcomeUnknown
	}
	verification, err := verification(plan, after, target)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	after.PasswordPolicy.AcquiredFeatures = append([]agentv1.PasswordNativeFeature(nil), target.GetPasswordPolicy().GetAcquiredFeatures()...)
	if _, err := p.store.CompleteResourceOwnershipEffect(finish, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return verification, errors.Join(ErrOutcomeUnknown, err)
	}
	return verification, nil
}
func (p *Provider) Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if err := p.validateDesired(desired); err != nil {
		return nil, err
	}
	ledger, err := p.ledger(ctx)
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	after, err := p.observe(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	var target *agentv1.ResourceOwnershipSnapshot
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
			return nil, ErrConflict
		}
		target = ledger.GetLastApplied()
	} else {
		target, err = p.target(ctx, desired.GetPasswordPolicy(), after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
	}
	result, err := verification(plan, after, target)
	if err != nil {
		return nil, err
	}
	if !result.GetPasswordPolicy().GetConverged() {
		return result, ErrNotConverged
	}
	return result, nil
}
func verification(plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot) (*resourcev1.ResourceVerification, error) {
	matches := targetMatches(after, target)
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		matches = matches && desiredMatches(plan.GetPasswordPolicy().GetDesired(), after.GetObservation().GetPasswordPolicy().GetEffective())
	}
	checks := &resourcev1.PasswordPolicyChecks{EffectiveSettingsMatch: matches, InstalledModulesReady: true, NativePrecedenceVerified: true, NativePamOwnerMatches: after.GetPasswordPolicy().GetManagerProfile() == plan.GetPasswordPolicy().GetPamOwner(), Converged: matches && after.GetPasswordPolicy().GetManagerProfile() == plan.GetPasswordPolicy().GetPamOwner()}
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	pd, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	result := &resourcev1.ResourceVerification{Ref: passwordRef(), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: pd[:], After: proto.CloneOf(after.GetObservation()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_PasswordPolicy{PasswordPolicy: checks}}
	if err := resource.ValidatePlanVerification(plan, result); err != nil {
		return nil, err
	}
	return result, nil
}

func equalClaims(a, b []*resourcev1.ResourceClaim) bool {
	if len(a) != len(b) {
		return false
	}
	for i, claim := range a {
		if !proto.Equal(claim, b[i]) {
			return false
		}
	}
	return true
}
