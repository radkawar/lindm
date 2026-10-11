//go:build linux

// Package sshprovider owns the typed SSH login banner, not authentication,
// listeners or arbitrary sshd directives. It uses existing sshd Includes,
// descriptor-bound nativefile transactions and the protected ownership journal.
// Existing issue.net requires approved adoption. Foreign Banner directives,
// replaced inodes and uncertain effects fail closed. Release restores the exact
// captured baseline only while owned files still match their last applied image.
package sshprovider

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/platform"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

var (
	ErrUnsupported    = errors.New("sshprovider: banner_only_native_capability_unavailable")
	ErrConflict       = errors.New("sshprovider: ownership_or_native_precondition_conflict")
	ErrOutcomeUnknown = errors.New("sshprovider: native_outcome_unknown")
	ErrNotConverged   = errors.Join(resource.ErrNotConverged, errors.New("sshprovider: banner_not_converged"))
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
	ObserveNative        func(context.Context) (*agentv1.ResourceOwnershipSnapshot, error)
	ExecuteNative        func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)
}

type ownershipStore interface {
	LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error)
	ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
	BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error)
	CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
}

type Provider struct {
	config     Config
	store      ownershipStore
	backend    *resourcev1.BackendSelection
	boot, unit string
	run        commandRunner
	capture    func(string, *resourcev1.ResourceObservation) (*agentv1.ResourceOwnershipSnapshot, error)
	creation   func(context.Context, *agentv1.ResourceOwnershipSnapshot) error
	witness    func(context.Context, uint32, *resourcev1.ResourceObservation) (*resourcev1.ProbeReceipt, []byte, error)
	resolve    func(string) (string, error)
	glob       func(string) ([]string, error)
	mu         sync.Mutex
	closed     bool
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
	if ctx == nil || config.Journal == nil || config.ObserveNative == nil || config.ExecuteNative == nil || platform.Of(config.Platform).Quirks.SSHBannerUnit == "" {
		return nil, ErrUnsupported
	}
	if err := validateMessage(config.Ownership); err != nil {
		return nil, err
	}
	initial, err := config.ObserveNative(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateMessage(initial); err != nil {
		return nil, err
	}
	backend := initial.GetObservation().GetMetadata().GetBackend()
	if backend.GetBackend() != resourcev1.Backend_BACKEND_OPENSSH || !proto.Equal(backend.GetProduct(), config.Platform) {
		return nil, ErrConflict
	}
	config.Ownership = proto.CloneOf(config.Ownership)
	config.Platform = proto.CloneOf(config.Platform)
	return &Provider{config: config, store: config.Journal, backend: proto.CloneOf(backend), boot: initial.GetObservation().GetMetadata().GetBootId(), unit: platform.Of(config.Platform).Quirks.SSHBannerUnit, creation: nativefile.CreationMetadata}, nil
}

func (p *Provider) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; return nil }
func (p *Provider) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrUnsupported
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	return ctx, func() { cancel(); p.mu.Unlock() }, nil
}
func sshRef() *resourcev1.ResourceRef {
	return &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}
}
func validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	if !resource.SSHBannerOnly(desired.GetSshServer()) {
		return ErrUnsupported
	}
	return nil
}
func (p *Provider) ledger(ctx context.Context) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.store.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, sshRef())
	if errors.Is(err, journal.ErrResourceOwnershipNotFound) {
		return nil, nil
	}
	return ledger, err
}
func ledgerActive(ledger *agentv1.ResourceOwnershipLedger) bool {
	return ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED
}
func sameOwner(a, b *agentv1.ResourceOwnershipBinding) bool {
	if a == nil || b == nil || len(a.GetSources()) == 0 || len(a.GetSources()) != len(b.GetSources()) {
		return false
	}
	for _, source := range a.GetSources() {
		count := 0
		for _, other := range b.GetSources() {
			if source.GetProfileId() == other.GetProfileId() && source.GetResourceId() == other.GetResourceId() {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}
func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, ledger *agentv1.ResourceOwnershipLedger, before *agentv1.ResourceOwnershipSnapshot, operation resourcev1.ResourceOperation) error {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if ledgerActive(ledger) {
		if !sameOwner(owner, ledger.GetOwner()) {
			return ErrConflict
		}
		if ledger.GetLastApplied() != nil && !journal.SSHOwnershipIdentityMatches(ledger.GetLastApplied(), before) {
			return ErrConflict
		}
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE || before.GetSshServer().GetDirective().GetState().GetExists() {
		return ErrConflict
	}
	if before.GetSshServer().GetBanner().GetState().GetExists() && (owner.GetPolicy().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION || owner.GetPolicy().GetAdoptionApprovalId() == "") {
		return ErrConflict
	}
	return nil
}

func fileSnapshot(parent *agentv1.ResourceOwnershipSnapshot, file *agentv1.SSHNativeFileSnapshot) *agentv1.ResourceOwnershipSnapshot {
	observation := proto.CloneOf(parent.GetObservation())
	observation.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: proto.CloneOf(file.GetState())}
	return &agentv1.ResourceOwnershipSnapshot{Observation: observation, ManagedFileContent: bytes.Clone(file.GetContent()), ManagedFileXattrs: file.GetXattrs()}
}
func sameFileImage(a, b *agentv1.SSHNativeFileSnapshot) bool {
	x, y := a.GetState(), b.GetState()
	return x != nil && y != nil && x.GetPath() == y.GetPath() && x.GetExists() == y.GetExists() && bytes.Equal(a.GetContent(), b.GetContent()) && x.GetFile().GetMode() == y.GetFile().GetMode() && x.GetFile().GetUid() == y.GetFile().GetUid() && x.GetFile().GetGid() == y.GetFile().GetGid() && bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256())
}
func targetMatches(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	return sameFileImage(a.GetSshServer().GetDirective(), b.GetSshServer().GetDirective()) && sameFileImage(a.GetSshServer().GetBanner(), b.GetSshServer().GetBanner())
}
func sameObserved(a, b *resourcev1.ResourceObservation) bool {
	return a.GetSshServer() != nil && b.GetSshServer() != nil && a.GetMetadata().GetBootId() == b.GetMetadata().GetBootId() && a.GetMetadata().GetExecutorIncarnation() == b.GetMetadata().GetExecutorIncarnation() && proto.Equal(a.GetMetadata().GetBackend(), b.GetMetadata().GetBackend()) && bytes.Equal(a.GetMetadata().GetNativeRevision(), b.GetMetadata().GetNativeRevision()) && bytes.Equal(a.GetSshServer().GetReceivedBannerSha256(), b.GetSshServer().GetReceivedBannerSha256())
}
func (p *Provider) target(ctx context.Context, desired *resourcev1.SSHServerDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	target := proto.CloneOf(before)
	if target.GetSshServer() == nil {
		return nil, ErrUnsupported
	}
	switch operation {
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE:
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED || !journal.SSHOwnershipMatches(ledger.GetLastApplied(), before) || ledger.GetBaseline() == nil {
			return nil, ErrConflict
		}
		if ledger.GetOwner().GetPolicy().GetRelease() != resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED {
			return nil, ErrUnsupported
		}
		target.SshServer = proto.CloneOf(ledger.GetBaseline().GetSshServer())
		// Baseline file bytes/labels are restored into the currently held parent.
		for i, file := range []*agentv1.SSHNativeFileSnapshot{target.SshServer.Directive, target.SshServer.Banner} {
			current := []*agentv1.SSHNativeFileSnapshot{before.SshServer.Directive, before.SshServer.Banner}[i]
			file.State.AncestrySha256 = bytes.Clone(current.GetState().GetAncestrySha256())
		}
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE:
		for i, file := range []*agentv1.SSHNativeFileSnapshot{target.SshServer.Directive, target.SshServer.Banner} {
			content := []byte(bannerDirective)
			if i == 1 {
				content = []byte(desired.GetBannerText())
			}
			file.Content = content
			file.State.File = &resourcev1.FileIdentity{Path: file.State.GetPath(), Mode: 0644, Sha256: sum(content)}
			if !file.State.GetExists() {
				file.State.Exists = true
				image := fileSnapshot(target, file)
				if err := p.creation(ctx, image); err != nil {
					return nil, err
				}
				file.State.SecurityMetadataSha256 = bytes.Clone(image.GetObservation().GetManagedFile().GetSecurityMetadataSha256())
				file.Xattrs = image.GetManagedFileXattrs()
			}
		}
	default:
		return nil, ErrUnsupported
	}
	public := target.Observation.GetSshServer()
	public.DirectiveFile = proto.CloneOf(target.SshServer.Directive.State)
	public.BannerFile = proto.CloneOf(target.SshServer.Banner.State)
	return target, nil
}

func (p *Provider) plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.ResourcePlan, *agentv1.ResourceOwnershipSnapshot, error) {
	if err := acquisitionAllowed(p.config.Ownership, ledger, before, operation); err != nil {
		return nil, nil, err
	}
	target, err := p.target(ctx, desired.GetSshServer(), before, ledger, operation)
	if err != nil {
		return nil, nil, err
	}
	plan, err := p.makePlan(desired, operation, before, target, ledger)
	return plan, target, err
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
	candidate, err := digestMessage(target.GetSshServer())
	if err != nil {
		return nil, err
	}
	native := &resourcev1.SSHServerPlan{Desired: proto.CloneOf(desired.GetSshServer()), CandidateGraphSha256: candidate, Reload: resourcev1.ReloadMechanism_RELOAD_MECHANISM_NONE, SyntaxValidation: proto.CloneOf(before.GetObservation().GetSshServer().GetSyntax())}
	if !targetMatches(before, target) || (operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE && !bannerConverged(desired.GetSshServer(), before)) {
		native.ChangedDirectives = []resourcev1.SSHDirective{resourcev1.SSHDirective_SSH_DIRECTIVE_BANNER}
		native.Reload = resourcev1.ReloadMechanism_RELOAD_MECHANISM_SYSTEMD_RELOAD
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		last, err := digestMessage(ledger.GetLastApplied())
		if err != nil {
			return nil, err
		}
		identity, err := digestMessage(before.GetSshServer())
		if err != nil {
			return nil, err
		}
		native.Inverse = &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last, NativeIdentitySha256: identity, InverseSha256: bytes.Clone(candidate)}
	}
	plan := &resourcev1.ResourcePlan{Ref: sshRef(), Operation: operation, DesiredSha256: dd[:], ObservationSha256: od[:], Backend: proto.CloneOf(p.backend), Claims: claims, OwnershipRevisionSha256: ld[:], Before: proto.CloneOf(before.GetObservation()), Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED}, Plan: &resourcev1.ResourcePlan_SshServer{SshServer: native}}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
func samePlan(a, b *resourcev1.ResourcePlan) bool {
	x, y := proto.CloneOf(a.GetSshServer()), proto.CloneOf(b.GetSshServer())
	x.SyntaxValidation = nil
	y.SyntaxValidation = nil
	if len(a.GetClaims()) != len(b.GetClaims()) {
		return false
	}
	for i, claim := range a.GetClaims() {
		if !proto.Equal(claim, b.GetClaims()[i]) {
			return false
		}
	}
	return proto.Equal(x, y) && proto.Equal(a.GetSafety(), b.GetSafety())
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
	before, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return before.GetObservation(), nil
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
	ledger, err := p.ledger(ctx)
	if err != nil {
		return nil, err
	}
	before, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	plan, _, err := p.plan(ctx, desired, operation, before, ledger)
	return plan, err
}

func (p *Provider) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if beforeEffect == nil || p.config.ExecuteNative == nil {
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
	ledger, err := p.ledger(ctx)
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
	before, err := p.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !sameObserved(before.GetObservation(), plan.GetBefore()) {
		return nil, ErrConflict
	}
	replanned, target, err := p.plan(ctx, desired, plan.GetOperation(), before, ledger)
	if err != nil {
		return nil, err
	}
	if !samePlan(replanned, plan) {
		return nil, ErrConflict
	}
	requestLedger := proto.CloneOf(ledger)
	if !ledgerActive(ledger) {
		ledger, err = p.store.ClaimResourceOwnership(ctx, p.config.ActionID, int64(ledger.GetRevision()), before)
		if err != nil {
			return nil, err
		}
		requestLedger = proto.CloneOf(ledger)
	}
	dimensions := []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SSH_BANNER}
	ledger, err = p.store.BeginResourceOwnershipEffect(ctx, p.config.ActionID, int64(ledger.GetRevision()), before, dimensions)
	if err != nil {
		return nil, err
	}
	request := &agentv1.NativeResourceTransactionRequest{Plan: proto.CloneOf(plan), Before: before, Target: target, Ownership: requestLedger, ActionId: p.config.ActionID}
	consumed := false
	reported, err := p.config.ExecuteNative(ctx, request, func(c context.Context) error {
		if consumed {
			return ErrOutcomeUnknown
		}
		consumed = true
		return beforeEffect(c)
	})
	if err != nil || !consumed || reported == nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	completion, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	after, err := p.snapshot(completion)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !sameObserved(after.GetObservation(), reported.GetObservation()) || !targetMatches(after, target) {
		return nil, ErrOutcomeUnknown
	}
	result, err := verification(plan, after, target)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if _, err := p.store.CompleteResourceOwnershipEffect(completion, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return result, errors.Join(ErrOutcomeUnknown, err)
	}
	if !result.GetSshServer().GetConverged() {
		return result, ErrNotConverged
	}
	return result, nil
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
	ledger, err := p.ledger(ctx)
	if err != nil {
		return nil, err
	}
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrOutcomeUnknown
	}
	after, err := p.snapshot(ctx)
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
		if err := acquisitionAllowed(p.config.Ownership, ledger, after, plan.GetOperation()); err != nil {
			return nil, err
		}
		target, err = p.target(ctx, desired.GetSshServer(), after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
	}
	result, err := verification(plan, after, target)
	if err != nil {
		return nil, err
	}
	if !result.GetSshServer().GetConverged() {
		return result, ErrNotConverged
	}
	return result, nil
}
func bannerConverged(desired *resourcev1.SSHServerDesired, after *agentv1.ResourceOwnershipSnapshot) bool {
	o := after.GetObservation().GetSshServer()
	digest := sum([]byte(desired.GetBannerText()))
	return o.GetBannerPath() == resource.SSHBannerPath && bytes.Equal(o.GetBannerFile().GetFile().GetSha256(), digest) && bytes.Equal(o.GetReceivedBannerSha256(), digest)
}
func verification(plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot) (*resourcev1.ResourceVerification, error) {
	o := after.GetObservation().GetSshServer()
	if o.GetConnection() == nil || o.GetSyntax() == nil {
		return nil, ErrUnsupported
	}
	match := targetMatches(after, target)
	exchange := proto.CloneOf(o.GetConnection())
	effective := bannerConverged(plan.GetSshServer().GetDesired(), after)
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		effective = o.GetBannerPath() == "none" && bytes.Equal(o.GetReceivedBannerSha256(), sum(nil))
	}
	exchange.Passed = exchange.GetPassed() && effective
	exchange.Reason = "fresh pre-authentication banner matches the managed effect"
	checks := &resourcev1.SSHServerChecks{Syntax: proto.CloneOf(o.GetSyntax()), EffectiveSettingsMatch: effective, MatchContextsMatch: true, Connectivity: proto.CloneOf(o.GetConnection()), BannerExchange: exchange, BannerContentMatch: match}
	checks.Converged = match && effective && checks.GetSyntax().GetPassed() && checks.GetConnectivity().GetPassed()
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.Converged {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	pd, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	result := &resourcev1.ResourceVerification{Ref: sshRef(), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: pd[:], After: proto.CloneOf(after.GetObservation()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_SshServer{SshServer: checks}}
	if err := resource.ValidatePlanVerification(plan, result); err != nil {
		return nil, err
	}
	return result, nil
}
