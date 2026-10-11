//go:build linux

// Package osupdateprovider is the os.update.v1 native resource provider. It
// owns only the lindm runner policy, the maintenance-window timer, the timer
// pull-in drop-in and the backend's native automatic-update configuration
// (APT periodic override or /etc/dnf/automatic.conf). It never installs
// updates, packages or repositories itself, never adopts an existing native
// file and never creates or removes the package-provided parent directories:
// the native transaction runs later inside the window under the lindm runner.
package osupdateprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	"lindm/internal/agent/osupdate"
	"lindm/internal/protodata"
	"lindm/internal/resource"
)

const Capability = "os.update.v1"

var (
	ErrUnsupported         = errors.New("osupdateprovider: unsupported_native_policy")
	ErrMissingPrerequisite = errors.New("osupdateprovider: native_prerequisite_missing")
	ErrConflict            = errors.New("osupdateprovider: ownership_or_native_precondition_conflict")
	ErrOutcomeUnknown      = errors.New("osupdateprovider: native_outcome_unknown")
	// ErrBusy refuses an effect before the ownership effect begins while a
	// window, patch-now or status run holds the run lock: a package
	// transaction can upgrade the native tools and systemd and leave the timer
	// transiently reload-pending. Nothing changed; the server retries.
	ErrBusy         = errors.New("osupdateprovider: os_update_run_in_progress")
	ErrNotConverged = errors.Join(resource.ErrNotConverged, errors.New("osupdateprovider: policy_not_converged"))
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
	Native               *agentv1.NativeOSUpdateProviderConfig
	// StateDirectory is the executor-private state directory; only scratch
	// copies of public APT configuration are created below it.
	StateDirectory string
	ExecuteNative  func(context.Context, *agentv1.NativeResourceTransactionRequest, func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)
}

type ownershipStore interface {
	LoadResourceOwnership(context.Context, string, string, string, *resourcev1.ResourceRef) (*agentv1.ResourceOwnershipLedger, error)
	ClaimResourceOwnership(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
	BeginResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot, []agentv1.ResourceOwnedDimension) (*agentv1.ResourceOwnershipLedger, error)
	CompleteResourceOwnershipEffect(context.Context, string, int64, *agentv1.ResourceOwnershipSnapshot) (*agentv1.ResourceOwnershipLedger, error)
}

var _ ownershipStore = (*journal.Store)(nil)

type Provider struct {
	config   Config
	store    ownershipStore
	manager  nativeManager
	backend  *resourcev1.BackendSelection
	update   resourcev1.OSUpdateBackend
	run      commandRunner
	creation func(context.Context, *agentv1.ResourceOwnershipSnapshot) error
	// aptPeriodic predicts APT's effective periodic upgrade setting with the
	// candidate override; set only on the executor side, which plans.
	aptPeriodic func(context.Context, []byte) (string, error)
	boot        string
	zoneinfo    string
	// runLock takes the runner's lock without waiting; Apply holds it from
	// before the ownership effect until the completion is durable.
	runLock func() (func() error, error)
	mu      sync.Mutex
	closed  bool
}

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

// nativeContext is shared by the executor and the root helper: it qualifies
// the product, the native tools and the systemd manager before any planning.
func nativeContext(ctx context.Context, platform *resourcev1.PlatformProduct, incarnation string) (_ *Provider, err error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	if err := validateMessage(platform); err != nil {
		return nil, err
	}
	if err := checkPlatform(platform); err != nil {
		return nil, err
	}
	update, native, _ := productBackend(platform)
	version, _, err := nativeTools(ctx, platform, runNative)
	if err != nil {
		return nil, err
	}
	backend := &resourcev1.BackendSelection{Backend: native, NativeVersion: version, ProviderVersion: "1", Product: proto.CloneOf(platform)}
	if err := validateMessage(backend); err != nil {
		return nil, err
	}
	boot, err := readNative("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return nil, err
	}
	manager, err := openBus(ctx)
	if err != nil {
		return nil, err
	}
	return &Provider{
		config: Config{Platform: proto.CloneOf(platform), ExecutorIncarnation: incarnation}, manager: manager, backend: backend, update: update,
		run: runNative, creation: nativefile.CreationMetadata, boot: strings.TrimSpace(string(boot)), zoneinfo: zoneinfoRoot,
	}, nil
}

func Open(ctx context.Context, config Config) (*Provider, error) {
	if ctx == nil || config.Journal == nil || config.ExecuteNative == nil || config.ActionID == "" || !filepath.IsAbs(config.StateDirectory) {
		return nil, ErrUnsupported
	}
	// Absent local opt-in refuses the kind before any native observation.
	for _, m := range []proto.Message{config.Native, config.Ownership, config.Platform} {
		if err := validateMessage(m); err != nil {
			return nil, err
		}
	}
	p, err := nativeContext(ctx, config.Platform, config.ExecutorIncarnation)
	if err != nil {
		return nil, err
	}
	p.config = config
	p.config.Native = proto.CloneOf(config.Native)
	p.config.Platform = proto.CloneOf(config.Platform)
	p.config.Ownership = proto.CloneOf(config.Ownership)
	p.store = config.Journal
	p.runLock = func() (func() error, error) { return osupdate.TryRunLock(resource.OSUpdateLockPath) }
	p.aptPeriodic = func(ctx context.Context, candidate []byte) (string, error) {
		return aptCandidatePeriodic(ctx, config.StateDirectory, candidate)
	}
	return p, nil
}

func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.manager == nil {
		return nil
	}
	return p.manager.Close()
}

// begin serializes provider calls and bounds every native observation.
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

func osUpdateRef() *resourcev1.ResourceRef {
	return &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"}
}

func validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	if desired.GetOsUpdate() == nil || !proto.Equal(desired.GetRef(), osUpdateRef()) {
		return ErrUnsupported
	}
	return nil
}

func (p *Provider) ledger(ctx context.Context) (*agentv1.ResourceOwnershipLedger, error) {
	ledger, err := p.store.LoadResourceOwnership(ctx, p.config.DeploymentID, p.config.DeviceID, p.config.EnrollmentGeneration, osUpdateRef())
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

// acquisitionAllowed never adopts: without an active ledger every owned path
// must be absent and no lindm-os-update.timer may be loaded, whatever the
// signed ownership mode says.
func acquisitionAllowed(owner *agentv1.ResourceOwnershipBinding, ledger *agentv1.ResourceOwnershipLedger, before *agentv1.ResourceOwnershipSnapshot, operation resourcev1.ResourceOperation) error {
	if ledger.GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return ErrOutcomeUnknown
	}
	if ledgerActive(ledger) {
		if !sameOwner(owner, ledger.GetOwner()) {
			return ErrConflict
		}
		return nil
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return ErrConflict
	}
	observation := before.GetObservation().GetOsUpdate()
	if observation.GetTimerActive() || observation.GetTimerCalendar() != "" {
		return fmt.Errorf("%w: %s is already loaded", ErrConflict, resource.OSUpdateTimerUnit)
	}
	for _, file := range before.GetOsUpdate().GetFiles() {
		if file.GetState().GetExists() {
			return fmt.Errorf("%w: unowned %s exists", ErrConflict, file.GetState().GetPath())
		}
	}
	return nil
}

func nativeFile(snapshot *agentv1.ResourceOwnershipSnapshot, kind resourcev1.OSUpdateNativeFile) *agentv1.OSUpdateNativeFileSnapshot {
	for _, file := range snapshot.GetOsUpdate().GetFiles() {
		if file.GetKind() == kind {
			return file
		}
	}
	return nil
}

func publicFiles(private *agentv1.OSUpdateOwnership) []*resourcev1.OSUpdateFileObservation {
	files := make([]*resourcev1.OSUpdateFileObservation, 0, len(private.GetFiles()))
	for _, file := range private.GetFiles() {
		public := &resourcev1.OSUpdateFileObservation{Kind: file.GetKind(), State: proto.CloneOf(file.GetState())}
		if file.GetState().GetExists() {
			public.ContentSha256 = bytes.Clone(file.GetState().GetFile().GetSha256())
		}
		files = append(files, public)
	}
	return files
}

// fileSnapshot is the nativefile view of one owned object.
func fileSnapshot(parent *agentv1.ResourceOwnershipSnapshot, file *agentv1.OSUpdateNativeFileSnapshot) *agentv1.ResourceOwnershipSnapshot {
	observation := proto.CloneOf(parent.GetObservation())
	observation.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: proto.CloneOf(file.GetState())}
	return &agentv1.ResourceOwnershipSnapshot{Observation: observation, ManagedFileContent: bytes.Clone(file.GetContent()), ManagedFileXattrs: file.GetXattrs()}
}

func absentIdentity() []byte {
	digest := sha256.Sum256([]byte("lindm.file.absent.v1"))
	return digest[:]
}

// target derives the complete owned image from signed desired state and the
// protected ledger only; server-provided inverse content is never accepted.
func (p *Provider) target(ctx context.Context, desired *resourcev1.OSUpdateDesired, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger, operation resourcev1.ResourceOperation) (*agentv1.ResourceOwnershipSnapshot, error) {
	if operation != resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if err := osupdate.ValidateRollingPolicy(p.update, desired); err != nil {
			return nil, err
		}
	}
	target := proto.CloneOf(before)
	observation := target.GetObservation().GetOsUpdate()
	if observation == nil || target.GetOsUpdate() == nil {
		return nil, ErrUnsupported
	}
	switch operation {
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE:
		if ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED || ledger.GetLastApplied() == nil || ledger.GetBaseline() == nil {
			return nil, ErrConflict
		}
		if !journal.OSUpdateOwnershipMatches(ledger.GetLastApplied(), before, ledger.GetOwnedDimensions()) {
			return nil, fmt.Errorf("%w: owned update policy drifted since the last effect (%s)", ErrConflict, journal.OSUpdateOwnershipDifference(ledger.GetLastApplied(), before, ledger.GetOwnedDimensions()))
		}
		switch ledger.GetOwner().GetPolicy().GetRelease() {
		case resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN:
			return target, nil
		case resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED:
		default:
			return nil, ErrUnsupported
		}
		for _, file := range ledger.GetBaseline().GetOsUpdate().GetFiles() {
			if file.GetState().GetExists() {
				return nil, ErrConflict
			}
		}
		for _, file := range target.GetOsUpdate().GetFiles() {
			file.Content = nil
			file.Xattrs = nil
			file.State.Exists = false
			file.State.File = nil
			file.State.NativeIdentitySha256 = absentIdentity()
			file.State.SecurityMetadataSha256 = nativefile.XattrDigest(nil)
		}
		target.OsUpdate.TimerActive = false
		observation.Effective = nil
		observation.TimerCalendar = ""
	case resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE:
		rendered, specs, err := renderFiles(p.zoneinfo, desired, p.update)
		if err != nil {
			return nil, err
		}
		for _, file := range target.GetOsUpdate().GetFiles() {
			content, ok := rendered[file.GetKind()]
			if !ok {
				return nil, ErrUnsupported
			}
			digest := sha256.Sum256(content)
			file.Content = bytes.Clone(content)
			file.State.File = &resourcev1.FileIdentity{Path: file.GetState().GetPath(), Mode: fileMode(file.GetKind()), Sha256: digest[:]}
			if !file.GetState().GetExists() {
				file.State.Exists = true
				image := fileSnapshot(target, file)
				if err := p.creation(ctx, image); err != nil {
					return nil, err
				}
				file.State.SecurityMetadataSha256 = bytes.Clone(image.GetObservation().GetManagedFile().GetSecurityMetadataSha256())
				file.Xattrs = image.GetManagedFileXattrs()
			}
		}
		target.OsUpdate.TimerActive = true
		observation.Effective = proto.CloneOf(desired)
		observation.TimerCalendar = joinCalendar(specs)
	default:
		return nil, ErrUnsupported
	}
	observation.TimerActive = target.GetOsUpdate().GetTimerActive()
	observation.Files = publicFiles(target.GetOsUpdate())
	observation.ConflictingUnits = nil
	if err := validateMessage(observation); err != nil {
		return nil, err
	}
	return target, nil
}

func sameFileImage(a, b *agentv1.OSUpdateNativeFileSnapshot) bool {
	if a == nil || b == nil {
		return a == b
	}
	x, y := a.GetState(), b.GetState()
	return a.GetKind() == b.GetKind() && x.GetPath() == y.GetPath() && x.GetExists() == y.GetExists() && bytes.Equal(a.GetContent(), b.GetContent()) && x.GetFile().GetMode() == y.GetFile().GetMode() && x.GetFile().GetUid() == y.GetFile().GetUid() && x.GetFile().GetGid() == y.GetFile().GetGid() && bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256())
}

func targetMatches(a, b *agentv1.ResourceOwnershipSnapshot) bool {
	if len(a.GetOsUpdate().GetFiles()) != len(b.GetOsUpdate().GetFiles()) || a.GetOsUpdate().GetTimerActive() != b.GetOsUpdate().GetTimerActive() {
		return false
	}
	for _, file := range a.GetOsUpdate().GetFiles() {
		if !sameFileImage(file, nativeFile(b, file.GetKind())) {
			return false
		}
	}
	return true
}

func sameObserved(a, b *resourcev1.ResourceObservation) bool {
	return proto.Equal(a.GetOsUpdate(), b.GetOsUpdate()) && a.GetMetadata().GetBootId() == b.GetMetadata().GetBootId() && a.GetMetadata().GetExecutorIncarnation() == b.GetMetadata().GetExecutorIncarnation() && bytes.Equal(a.GetMetadata().GetNativeRevision(), b.GetMetadata().GetNativeRevision())
}

// conflictRefused rejects a reconcile whose result could never converge
// because a native scheduler outside lindm's ownership would still install
// outside the window. On APT the effective periodic setting is predicted with
// the candidate override in place, so a later part or /etc/apt/apt.conf that
// re-enables it is refused before any effect.
func (p *Provider) conflictRefused(ctx context.Context, before, target *agentv1.ResourceOwnershipSnapshot) error {
	if p.update == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES {
		if p.aptPeriodic == nil {
			return ErrUnsupported
		}
		value, err := p.aptPeriodic(ctx, nativeFile(target, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC).GetContent())
		if err != nil {
			return err
		}
		if value != "" && value != "0" {
			return fmt.Errorf("%w: APT configuration overrides APT::Periodic::Unattended-Upgrade to %q", ErrConflict, value)
		}
		return nil
	}
	if units := before.GetObservation().GetOsUpdate().GetConflictingUnits(); len(units) != 0 {
		return fmt.Errorf("%w: native automatic updates outside the window: %s", ErrConflict, strings.Join(units, ", "))
	}
	return nil
}

func (p *Provider) plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation, before *agentv1.ResourceOwnershipSnapshot, ledger *agentv1.ResourceOwnershipLedger) (*resourcev1.ResourcePlan, *agentv1.ResourceOwnershipSnapshot, error) {
	if err := acquisitionAllowed(p.config.Ownership, ledger, before, operation); err != nil {
		return nil, nil, err
	}
	target, err := p.target(ctx, desired.GetOsUpdate(), before, ledger, operation)
	if err != nil {
		return nil, nil, err
	}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		if err := p.conflictRefused(ctx, before, target); err != nil {
			return nil, nil, err
		}
	}
	plan, err := p.makePlan(desired, operation, before, target, ledger)
	return plan, target, err
}

// Observe reads the owned files, the timer and competing schedulers without
// effects.
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

func changedFiles(before, target *agentv1.ResourceOwnershipSnapshot) []resourcev1.OSUpdateNativeFile {
	var changed []resourcev1.OSUpdateNativeFile
	for _, file := range target.GetOsUpdate().GetFiles() {
		if !sameFileImage(nativeFile(before, file.GetKind()), file) {
			changed = append(changed, file.GetKind())
		}
	}
	return changed
}

// timerChange reports whether the loaded timer must be started, restarted or
// stopped. A rewritten timer file is restarted so systemd recomputes the
// next elapse from the new calendar.
func timerChange(operation resourcev1.ResourceOperation, before, target *agentv1.ResourceOwnershipSnapshot, changed []resourcev1.OSUpdateNativeFile) bool {
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		return before.GetOsUpdate().GetTimerActive() && !target.GetOsUpdate().GetTimerActive()
	}
	if !target.GetOsUpdate().GetTimerActive() {
		return false
	}
	for _, kind := range changed {
		if kind == resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER {
			return true
		}
	}
	return !before.GetOsUpdate().GetTimerActive() || !sameCalendar(before.GetObservation().GetOsUpdate().GetTimerCalendar(), target.GetObservation().GetOsUpdate().GetTimerCalendar())
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
	candidate, err := digestMessage(target.GetOsUpdate())
	if err != nil {
		return nil, err
	}
	changed := changedFiles(before, target)
	native := &resourcev1.OSUpdatePlan{Desired: proto.CloneOf(desired.GetOsUpdate()), Backend: p.update, CandidateSha256: candidate, ChangedFiles: changed, TimerCalendar: target.GetObservation().GetOsUpdate().GetTimerCalendar(), TimerChange: timerChange(operation, before, target, changed)}
	if operation == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		last, err := digestMessage(ledger.GetLastApplied())
		if err != nil {
			return nil, err
		}
		identity, err := digestMessage(before.GetObservation().GetOsUpdate())
		if err != nil {
			return nil, err
		}
		native.Inverse = &resourcev1.OwnershipInverseBinding{LedgerRevisionSha256: ld[:], LastAppliedSha256: last, NativeIdentitySha256: identity, InverseSha256: bytes.Clone(candidate)}
	}
	plan := &resourcev1.ResourcePlan{
		Ref: osUpdateRef(), Operation: operation, DesiredSha256: dd[:], ObservationSha256: od[:], Backend: proto.CloneOf(p.backend), Claims: claims,
		OwnershipRevisionSha256: ld[:], Before: proto.CloneOf(before.GetObservation()),
		Safety: &resourcev1.PlanSafety{
			LockDomains:   []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_UPDATE_SOURCE, resourcev1.ClaimDomain_CLAIM_DOMAIN_SYSTEMD_DEFINITION, resourcev1.ClaimDomain_CLAIM_DOMAIN_NATIVE_FILE},
			Reversibility: resourcev1.Reversibility_REVERSIBILITY_REVERSIBLE, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS,
			Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED,
		},
		Plan: &resourcev1.ResourcePlan_OsUpdate{OsUpdate: native},
	}
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func ownedDimensions() []agentv1.ResourceOwnedDimension {
	return []agentv1.ResourceOwnedDimension{
		agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_POLICY,
		agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_SCHEDULE,
		agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_NATIVE_CONFIGURATION,
	}
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

func samePlan(a, b *resourcev1.ResourcePlan) bool {
	return proto.Equal(a.GetOsUpdate(), b.GetOsUpdate()) && proto.Equal(a.GetSafety(), b.GetSafety()) && equalClaims(a.GetClaims(), b.GetClaims())
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
	release, err := p.runLock()
	if errors.Is(err, osupdate.ErrRunInProgress) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = release() }()
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
	dimensions := ownedDimensions()
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
	completion, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	after, err := p.snapshot(completion)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !sameObserved(after.GetObservation(), reported.GetObservation()) || !targetMatches(after, target) {
		return nil, ErrOutcomeUnknown
	}
	result, err := verification(plan, after, target, p.update)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if _, err := p.store.CompleteResourceOwnershipEffect(completion, p.config.ActionID, int64(ledger.GetRevision()), after); err != nil {
		return result, errors.Join(ErrOutcomeUnknown, err)
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
		if ledgerActive(ledger) && !sameOwner(p.config.Ownership, ledger.GetOwner()) {
			return nil, ErrConflict
		}
		target, err = p.target(ctx, desired.GetOsUpdate(), after, ledger, plan.GetOperation())
		if err != nil {
			return nil, err
		}
	}
	result, err := verification(plan, after, target, p.update)
	if err != nil {
		return nil, err
	}
	if !result.GetOsUpdate().GetConverged() {
		return result, ErrNotConverged
	}
	return result, nil
}

func osUpdateChecks(plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot, backend resourcev1.OSUpdateBackend) *resourcev1.OSUpdateChecks {
	observed := after.GetObservation().GetOsUpdate()
	image := func(kind resourcev1.OSUpdateNativeFile) bool {
		return sameFileImage(nativeFile(after, kind), nativeFile(target, kind))
	}
	reconcile := plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE
	checks := &resourcev1.OSUpdateChecks{
		PolicyMatches: image(resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY),
		ScheduleActive: image(resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER) && image(resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER_WANTS) &&
			after.GetOsUpdate().GetTimerActive() == target.GetOsUpdate().GetTimerActive() && sameCalendar(observed.GetTimerCalendar(), plan.GetOsUpdate().GetTimerCalendar()),
		NativeConfigurationMatches: true,
		// A released policy hands scheduling back to the native defaults.
		NoConflictingScheduler: !reconcile || len(observed.GetConflictingUnits()) == 0,
	}
	if reconcile {
		checks.PolicyMatches = checks.GetPolicyMatches() && proto.Equal(observed.GetEffective(), plan.GetOsUpdate().GetDesired())
	}
	if kind := nativeConfigurationKind(backend); kind != resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_UNSPECIFIED {
		checks.NativeConfigurationMatches = image(kind)
	}
	checks.Converged = checks.GetPolicyMatches() && checks.GetScheduleActive() && checks.GetNativeConfigurationMatches() && checks.GetNoConflictingScheduler()
	return checks
}

func verification(plan *resourcev1.ResourcePlan, after, target *agentv1.ResourceOwnershipSnapshot, backend resourcev1.OSUpdateBackend) (*resourcev1.ResourceVerification, error) {
	checks := osUpdateChecks(plan, after, target, backend)
	disposition := resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
	if checks.GetConverged() {
		disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
	}
	pd, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	result := &resourcev1.ResourceVerification{Ref: osUpdateRef(), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: pd[:], After: proto.CloneOf(after.GetObservation()), Disposition: disposition, Checks: &resourcev1.ResourceVerification_OsUpdate{OsUpdate: checks}}
	if err := resource.ValidatePlanVerification(plan, result); err != nil {
		return nil, err
	}
	return result, nil
}

// snapshot observes the closed owned object set, the timer and competing
// native schedulers. It carries no volatile timer elapse times.
func (p *Provider) snapshot(ctx context.Context) (*agentv1.ResourceOwnershipSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kinds := ownedKinds(p.update)
	if err := parentsPresent(kinds); err != nil {
		return nil, err
	}
	version, oracle, err := nativeTools(ctx, p.config.Platform, p.run)
	if err != nil {
		return nil, err
	}
	if version != p.backend.GetNativeVersion() {
		return nil, ErrConflict
	}
	installed, err := p.manager.ServiceInstalled(ctx)
	if err != nil {
		return nil, err
	}
	if !installed {
		return nil, fmt.Errorf("%w: package unit %s is not installed", ErrMissingPrerequisite, resource.OSUpdateServiceUnit)
	}
	observed := &resourcev1.ResourceObservation{Ref: osUpdateRef(), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
	private := &agentv1.OSUpdateOwnership{}
	revision := sha256.New()
	revision.Write([]byte("lindm.os-update.observation.v1\x00"))
	for _, kind := range kinds {
		capture, err := nativefile.Capture(resource.OSUpdateNativePath(kind), observed)
		if err != nil {
			return nil, err
		}
		// Each file's revision covers inode times: an in-place rewrite between
		// plan and effect changes the observation even with equal bytes.
		revision.Write(capture.GetObservation().GetMetadata().GetNativeRevision())
		private.Files = append(private.Files, &agentv1.OSUpdateNativeFileSnapshot{Kind: kind, State: proto.CloneOf(capture.GetObservation().GetManagedFile()), Content: bytes.Clone(capture.GetManagedFileContent()), Xattrs: capture.GetManagedFileXattrs()})
	}
	timer, err := p.manager.Timer(ctx)
	if err != nil {
		return nil, err
	}
	conflicts, err := p.conflicts(ctx)
	if err != nil {
		return nil, err
	}
	private.TimerActive = timer.active
	observation := &resourcev1.OSUpdateObservation{Backend: p.update, NativeVersion: version, Files: publicFiles(private), TimerActive: timer.active, TimerCalendar: joinCalendar(timer.calendars), ConflictingUnits: conflicts, RebootOracleAvailable: oracle}
	if policy := nativeFile(&agentv1.ResourceOwnershipSnapshot{OsUpdate: private}, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY); policy.GetState().GetExists() {
		observation.Effective = decodePolicy(policy.GetContent())
	}
	observed.Observed = &resourcev1.ResourceObservation_OsUpdate{OsUpdate: observation}
	digest, err := digestMessage(observation)
	if err != nil {
		return nil, err
	}
	revision.Write(digest)
	observed.Metadata.NativeRevision = revision.Sum(nil)
	result := &agentv1.ResourceOwnershipSnapshot{Observation: observed, OsUpdate: private}
	if err := validateMessage(result); err != nil {
		return nil, err
	}
	if err := resource.ValidateObservation(observed); err != nil {
		return nil, err
	}
	return result, nil
}

func (p *Provider) conflicts(ctx context.Context) ([]string, error) {
	switch p.update {
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES:
		value, err := aptPeriodicUpgrade(ctx, p.run)
		if err != nil {
			return nil, err
		}
		if value != "" && value != "0" {
			return []string{"apt-daily-upgrade.timer"}, nil
		}
		return nil, nil
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC:
		return p.manager.Conflicts(ctx, []string{"dnf5-automatic*.timer", "dnf-automatic*.timer"})
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC:
		return p.manager.Conflicts(ctx, []string{"dnf-automatic*.timer"})
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN, resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER:
		return p.manager.Conflicts(ctx, []string{"pacman*.timer", "pamac*.timer", "zypper*.timer", "transactional-update*.timer"})
	default:
		return nil, ErrUnsupported
	}
}
