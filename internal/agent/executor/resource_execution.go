//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/accountprovider"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/definitionprovider"
	"lindm/internal/agent/encryptionprovider"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/osupdateprovider"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/agent/passwordprovider"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/sysctlprovider"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// nativeResource is a process-local seam, never caller-supplied execution data.
// Production selects a native provider by the signed, canonical resource kind.
type nativeResource = resourceprovider.Provider

// resourceOpen is everything an opener may use; kinds take what they need.
type resourceOpen struct {
	service  *Service
	intent   *agentv1.ResourceExecutionIntent
	platform *resourcev1.PlatformProduct
	secrets  secretAccessor
}

// resourceKind is the executor's per-kind entry: the provider opener and any
// kind-specific plan/verification shape rules beyond the generic ones.
type resourceKind struct {
	open         func(context.Context, resourceOpen) (nativeResource, error)
	plan         func(*resourcev1.ResourcePlan) error
	verification func(*resourcev1.ResourcePlan, *resourcev1.ResourceVerification) error
}

// resourceKinds is the executor's only resource-kind dispatch. It is filled
// once by init because openers transitively reach the plan validators.
var resourceKinds resourceprovider.Registry[resourceKind]

func init() {
	resourceKinds = resourceprovider.NewRegistry(map[resourcev1.ResourceKind]resourceKind{
		resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE:        {open: openPackageResource},
		resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE:       {open: openServiceResource, plan: serviceprovider.ValidatePlan, verification: serviceprovider.ValidateVerification},
		resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:          {open: openFileResource},
		resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP:           {open: openAccountResource},
		resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:            {open: openAccountResource},
		resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:                {open: openSysctlResource},
		resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION:    {open: openDefinitionResource},
		resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:         {open: openFirewallResource},
		resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE: {open: openEncryptionResource},
		resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:       {open: openPasswordResource},
		resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY:      {open: openOSUpdateResource},
	})
}

func (s *Service) openNativeResource(ctx context.Context, intent *agentv1.ResourceExecutionIntent, secrets secretAccessor) (nativeResource, error) {
	if err := resource.ValidateDesired(intent.GetDesired()); err != nil {
		return nil, err
	}
	kind, err := resourceKinds.Lookup(intent.GetDesired().GetRef().GetKind())
	if err != nil {
		return nil, errors.Join(serviceprovider.ErrUnsupported, err)
	}
	platform, err := inventory.HostPlatform(ctx)
	if err != nil {
		return nil, err
	}
	return kind.open(ctx, resourceOpen{service: s, intent: intent, platform: platform, secrets: secrets})
}

// Native package transactions keep their staged helper protocol (stage,
// cancel, transaction) but expose the same Provider contract here.
func openPackageResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	record, _, err := s.store.LoadResourceAction(ctx, intent.GetActionId())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(record.GetIntent(), intent) || !bytes.Equal(digestBytes(record.GetIntentEnvelope()), record.GetIntentSha256()) {
		return nil, errRecoveryHold
	}
	return packageprovider.Open(ctx, packageprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), StateDirectory: s.directory, Native: s.packageProvider,
		Preparation: intent.GetPreparation(), IntentDigest: record.GetIntentSha256(),
		NativeStage: s.packageNativeStage, NativeStageCancel: s.packageNativeCancel, NativeTransaction: s.packageNativeTransaction,
	})
}

func openServiceResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	return serviceprovider.Open(ctx, serviceprovider.Config{
		ExecutorIncarnation: o.service.incarnation, Ownership: o.intent.GetOwnership(), Platform: o.platform,
	})
}

func openFileResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return fileprovider.Open(ctx, fileprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Files,
		ProtectedPaths: s.nativeResources.ProtectedPaths, ExecuteNative: s.resourceNativeTransaction,
	})
}

func openAccountResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return accountprovider.Open(ctx, accountprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Accounts,
		NativeTransaction: s.resourceNativeApply, NativeDigest: s.store.PrivateDigest, Secrets: o.secrets,
		NativeObserve: func(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
			result, err := s.observeNativeResource(ctx, desired, o.platform, nil)
			if err != nil {
				return nil, err
			}
			return result.GetAfter(), nil
		},
	})
}

func openSysctlResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return sysctlprovider.Open(ctx, sysctlprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Sysctl, NativeApply: s.resourceNativeApply,
	})
}

func openDefinitionResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return definitionprovider.Open(ctx, definitionprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), ExecuteNative: s.resourceNativeTransaction,
	})
}

func openEncryptionResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return encryptionprovider.Open(ctx, encryptionprovider.Config{
		ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		AuthenticatedEscrow: s.authenticatedResourceEscrow,
		Observe: func(ctx context.Context) (*actionprovider.RootEncryptionEvidence, error) {
			result, err := s.observeNativeResource(ctx, intent.GetDesired(), o.platform, nil)
			if err != nil {
				return nil, err
			}
			return rootEncryptionEvidence(result)
		},
	})
}

func openPasswordResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return passwordprovider.Open(ctx, passwordprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Password, ExecuteNative: s.resourceNativeTransaction,
	})
}

func openOSUpdateResource(ctx context.Context, o resourceOpen) (nativeResource, error) {
	s, intent := o.service, o.intent
	return osupdateprovider.Open(ctx, osupdateprovider.Config{
		Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: o.platform,
		ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
		EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.OSUpdate, StateDirectory: s.directory,
		ExecuteNative: s.resourceNativeTransaction,
	})
}

func readBoottime() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	ns := ts.Nano()
	if ns < 0 {
		return 0, errInternal
	}
	return uint64(ns), nil
}

func (s *Service) PrepareResourceExecution(ctx context.Context, req *connect.Request[agentv1.PrepareResourceExecutionRequest]) (*connect.Response[agentv1.PrepareResourceExecutionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareResourceExecution(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) StartResourceExecution(ctx context.Context, req *connect.Request[agentv1.StartResourceExecutionRequest]) (*connect.Response[agentv1.StartResourceExecutionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.startResourceExecution(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) GetResourceExecution(ctx context.Context, req *connect.Request[agentv1.GetResourceExecutionRequest]) (*connect.Response[agentv1.GetResourceExecutionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil || s.admit(req.Msg) != nil {
		return nil, mapError(errInvalid)
	}
	if _, err := canonicalUUID(req.Msg.GetActionId()); err != nil {
		return nil, mapError(errInvalid)
	}
	if err := s.lock(ctx); err != nil {
		return nil, mapError(err)
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	record, revision, err := s.loadResourceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if err := s.expireResourceAction(ctx, loaded, record, revision); err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.GetResourceExecutionResponse{Status: resourceStatus(record)}), nil
}

// resourceAction is the immutable signed-action descriptor for generic
// resource executions.
var resourceAction = &signedAction[*agentv1.ResourceExecutionIntent, *agentv1.ResourceExecutionChallenge, *agentv1.ResourceExecutionStartGrant, *agentv1.ResourceExecutionRecord]{
	payloadType: trust.ResourceIntentType, maxIntent: 131072,
	newIntent:    func() *agentv1.ResourceExecutionIntent { return new(agentv1.ResourceExecutionIntent) },
	targetIDs:    resourceTargetIDs,
	verifyIntent: (*trust.ExecutionVerifier).VerifyResourceIntent,
	verifyStart:  (*trust.ExecutionVerifier).VerifyResourceStart,
	verifyRecord: (*Service).verifyResourceRecord,
	load:         (*journal.Store).LoadResourceAction,
	store:        (*journal.Store).UpdateResourceAction,
}

func resourceTargetIDs(intent *agentv1.ResourceExecutionIntent) []string {
	return []string{intent.GetDesiredRevision()}
}

func (s *Service) prepareResourceExecution(ctx context.Context, req *agentv1.PrepareResourceExecutionRequest) (*agentv1.PrepareResourceExecutionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	actionID, err := resourceAction.lookup(s, req.GetIntentEnvelope())
	if err != nil {
		return nil, err
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	loaded, err := s.enrolled(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if old, revision, err := s.loadResourceAction(ctx, loaded, actionID); err == nil {
		// Replays carry the exact deliveries the signed intent authenticated;
		// another action's ciphertext or changed bytes never reach a provider.
		if !bytes.Equal(old.GetIntentEnvelope(), req.GetIntentEnvelope()) || !sameResourceSecrets(old, req.GetSealedSecrets()) {
			s.mu.Unlock()
			return nil, errIdempotencyConflict
		}
		if old.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
			return s.pollResourcePreparationLocked(ctx, loaded, old, revision)
		}
		s.mu.Unlock()
		return resourcePreparation(old), nil
	} else if !errors.Is(err, journal.ErrResourceActionNotFound) {
		s.mu.Unlock()
		return nil, err
	}
	intent, err := resourceAction.current(ctx, s, loaded, req.GetIntentEnvelope())
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if err := s.verifyResourceSecrets(loaded, intent, req.GetSealedSecrets()); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if intent.GetPreparation() != nil {
		return s.admitResourcePreparationLocked(ctx, loaded, intent, req.GetIntentEnvelope(), req.GetSealedSecrets())
	}
	// Admission and Add are serialized with Close. Native preflight never holds
	// the authority mutex and is canceled by either the RPC or service lifetime.
	s.operations.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.workerContext, cancel)
	s.mu.Unlock()
	defer s.operations.Done()
	defer cancel()
	defer stop()
	provider, err := s.openResource(ctx, intent, s.resourceSecrets(intent, req.GetSealedSecrets()))
	if err != nil {
		return s.refuseResourceAdmission(ctx, req.GetIntentEnvelope(), err)
	}
	defer func() { _ = provider.Close() }()
	plan, err := provider.Plan(ctx, intent.GetDesired(), intent.GetOperation())
	if err != nil {
		return s.refuseResourceAdmission(ctx, req.GetIntentEnvelope(), err)
	}
	if validateResourcePlan(plan) != nil || !proto.Equal(resource.PlanDesired(plan), intent.GetDesired()) || plan.GetOperation() != intent.GetOperation() {
		return nil, errInternal
	}
	var verification *resourcev1.ResourceVerification
	if !resourceDrift(plan) {
		verification, err = provider.Verify(ctx, plan)
		if err := validateReadOnlyResourceResult(plan, verification, err); err != nil {
			return nil, err
		}
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err = s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	// A concurrent identical request may have completed preflight first.
	if old, _, err := s.loadResourceAction(ctx, loaded, actionID); err == nil {
		if !bytes.Equal(old.GetIntentEnvelope(), req.GetIntentEnvelope()) || !sameResourceSecrets(old, req.GetSealedSecrets()) {
			return nil, errIdempotencyConflict
		}
		return resourcePreparation(old), nil
	} else if !errors.Is(err, journal.ErrResourceActionNotFound) {
		return nil, err
	}
	intent, err = resourceAction.current(ctx, s, loaded, req.GetIntentEnvelope())
	if err != nil {
		return nil, err
	}
	// Identity may have renewed during preflight; reauthenticate the deliveries.
	if err := s.verifyResourceSecrets(loaded, intent, req.GetSealedSecrets()); err != nil {
		return nil, err
	}
	now := s.now()
	record := &agentv1.ResourceExecutionRecord{
		FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(),
		IntentEnvelope: bytes.Clone(req.GetIntentEnvelope()), IntentSha256: digestBytes(req.GetIntentEnvelope()),
		Intent: intent, NativePlan: plan, AcceptedRoot: loaded.execution.root,
		AcceptedDelegationEnvelope: bytes.Clone(loaded.execution.state.GetDelegationEnvelope()),
		AcceptedAt:                 protoTimestamp(now), State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED,
		Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE,
	}
	if plan.GetBefore().GetMetadata().GetBootId() != loaded.state.GetSessionBootId() || plan.GetBefore().GetMetadata().GetExecutorIncarnation() != s.incarnation {
		return nil, errResourceRejected
	}
	if resourceDrift(plan) {
		if err := s.makeResourceChallenge(ctx, loaded, record); err != nil {
			return nil, err
		}
		// Only authenticated ciphertext is journaled, and only until terminal.
		for _, sealed := range req.GetSealedSecrets() {
			record.SealedSecrets = append(record.SealedSecrets, bytes.Clone(sealed))
		}
	} else {
		recordReadOnlyResourceResult(record, verification)
		record.FirewallEvidence = nativeFirewallEvidence(provider)
		record.CompletedAt = protoTimestamp(now)
	}
	// Validate protected generated evidence before it can become a receipt.
	if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
		return nil, errInternal
	}
	if _, err := s.store.AcceptResourceAction(ctx, loaded.revision, loaded.execution.revision, record); err != nil {
		return nil, s.resourceStoreError(err)
	}
	return resourcePreparation(record), nil
}

func (s *Service) startResourceExecution(ctx context.Context, req *agentv1.StartResourceExecutionRequest) (*agentv1.StartResourceExecutionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	if _, err := canonicalUUID(req.GetActionId()); err != nil {
		return nil, errInvalid
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	record, revision, err := s.loadResourceAction(ctx, loaded, req.GetActionId())
	if err != nil {
		return nil, err
	}
	// An already accepted exact grant is only a historical lookup, even after
	// expiry/revocation. It cannot queue work, consume again or extend a deadline.
	if len(record.GetStartGrantEnvelope()) != 0 {
		if !bytes.Equal(record.GetStartGrantEnvelope(), req.GetStartGrantEnvelope()) {
			return nil, errIdempotencyConflict
		}
		return &agentv1.StartResourceExecutionResponse{Status: resourceStatus(record)}, nil
	}
	if err := s.expireResourceAction(ctx, loaded, record, revision); err != nil {
		return nil, err
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED {
		return nil, errResourceRejected
	}
	if _, err := resourceAction.authorizeStart(ctx, s, loaded, record, req.GetStartGrantEnvelope()); err != nil {
		return nil, err
	}
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED
	next.StartGrantEnvelope = bytes.Clone(req.GetStartGrantEnvelope())
	next.StartGrantSha256 = digestBytes(req.GetStartGrantEnvelope())
	next.GrantAcceptedAt = protoTimestamp(s.now())
	if err := s.updateResourceAction(ctx, loaded, revision, next); err != nil {
		return nil, err
	}
	s.wakeResourceWorker()
	return &agentv1.StartResourceExecutionResponse{Status: resourceStatus(next)}, nil
}

func resourceTarget(loaded *bound, intent *agentv1.ResourceExecutionIntent) bool {
	return signedTarget(loaded, intent, resourceTargetIDs(intent)...)
}

// makeResourceChallenge issues the start challenge for a prepared drift plan.
// Staged preparations are challenged when they become prepared, never beyond
// their signed preparation deadline.
func (s *Service) makeResourceChallenge(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord) error {
	issued := record.GetAcceptedAt().AsTime()
	limits := []time.Time{record.GetIntent().GetExpiresAt().AsTime()}
	if preparation := record.GetIntent().GetPreparation(); preparation != nil {
		issued = s.now()
		limits = append(limits, preparation.GetDeadline().AsTime())
	}
	window, err := s.openChallenge(loaded, issued, record.GetNativePlan().GetBefore().GetMetadata().GetBootId(), limits...)
	if err != nil {
		return err
	}
	planDigest, err := resource.PlanDigest(record.GetNativePlan())
	if err != nil {
		return err
	}
	intent := record.GetIntent()
	challenge := &agentv1.ResourceExecutionChallenge{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		ActionId: intent.GetActionId(), DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: intent.GetResourceSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(),
		IntentSha256: bytes.Clone(record.GetIntentSha256()), NativePlanSha256: planDigest[:], Nonce: window.nonce,
		BootId: window.boot, ExecutorIncarnation: s.incarnation, IssuedAt: protoTimestamp(window.issued), ExpiresAt: protoTimestamp(window.expires),
		Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(),
	}
	proof, err := s.authority.Sign(ctx, challenge, loaded.identityKey)
	if err != nil {
		return err
	}
	record.Challenge, record.ChallengeProof, record.ChallengeBoottimeNs = challenge, proof, window.boottime
	record.ChallengeCertificatePem = bytes.Clone(loaded.state.GetCertificatePem())
	return nil
}

func (s *Service) expireResourceAction(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, revision int64) error {
	switch record.GetState() {
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING:
		return s.checkResourcePreparation(ctx, loaded, record, revision)
	case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED:
	default:
		return nil
	}
	if record.GetIntent().GetPreparation() != nil {
		if err := s.challengeDeadline(record.GetChallenge(), record.GetChallengeBoottimeNs()); !errors.Is(err, errResourceExpired) {
			return err
		}
		return s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED)
	}
	return resourceAction.expire(ctx, s, loaded, record, revision, func(next *agentv1.ResourceExecutionRecord) {
		next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
		next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
		next.CompletedAt = protoTimestamp(s.now())
		// Sealed deliveries are retained only while a native use may still follow.
		next.SealedSecrets = nil
	})
}

func resourceDrift(plan *resourcev1.ResourcePlan) bool {
	return resource.PlanRequiresEffect(plan)
}

func digestBytes(encoded []byte) []byte {
	sum := sha256.Sum256(encoded)
	return sum[:]
}

func digestMessage(msg proto.Message) ([]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(msg)
	if err != nil {
		return nil, err
	}
	return digestBytes(encoded), nil
}

func resourceStatus(record *agentv1.ResourceExecutionRecord) *agentv1.ResourceExecutionStatus {
	return &agentv1.ResourceExecutionStatus{
		ActionId: record.GetIntent().GetActionId(), IntentSha256: bytes.Clone(record.GetIntentSha256()), State: record.GetState(), Failure: record.GetFailure(),
		AcceptedAt: proto.CloneOf(record.GetAcceptedAt()), StartedAt: proto.CloneOf(record.GetStartedAt()), CompletedAt: proto.CloneOf(record.GetCompletedAt()),
		Before: proto.CloneOf(record.GetNativePlan().GetBefore()), Verification: proto.CloneOf(record.GetVerification()),
		PreparationOutcome: proto.CloneOf(record.GetPreparationOutcome()),
		AdmissionRefusal:   proto.CloneOf(record.GetAdmissionRefusal()),
		ReadOnly:           record.GetNativePlan() != nil && !resourceDrift(record.GetNativePlan()),
		Remediations:       encryptionprovider.Remediations(record.GetVerification()),
	}
}

func resourcePreparation(record *agentv1.ResourceExecutionRecord) *agentv1.PrepareResourceExecutionResponse {
	return &agentv1.PrepareResourceExecutionResponse{Status: resourceStatus(record), NativePlan: proto.CloneOf(record.GetNativePlan()), ChallengeProof: bytes.Clone(record.GetChallengeProof())}
}

func validateResourcePlan(plan *resourcev1.ResourcePlan) error {
	if err := resource.ValidatePlan(plan); err != nil {
		return err
	}
	if kind, err := resourceKinds.Lookup(plan.GetRef().GetKind()); err == nil && kind.plan != nil {
		return kind.plan(plan)
	}
	return nil
}

func validateResourceVerification(plan *resourcev1.ResourcePlan, verification *resourcev1.ResourceVerification) error {
	if err := resource.ValidatePlanVerification(plan, verification); err != nil {
		return err
	}
	if kind, err := resourceKinds.Lookup(plan.GetRef().GetKind()); err == nil && kind.verification != nil {
		return kind.verification(plan, verification)
	}
	return nil
}

// WithPackageProvider retains root-owned source authorization. An RPC cannot
// enable package management or replace its approved repositories and signing keys.
func WithPackageProvider(config *agentv1.NativePackageProviderConfig) Option {
	return func(s *Service) {
		s.packageProvider = proto.CloneOf(config)
	}
}
