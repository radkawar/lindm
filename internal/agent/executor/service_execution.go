//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"connectrpc.com/connect"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
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
	"lindm/internal/agent/packageprovider"
	"lindm/internal/agent/passwordprovider"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/agent/sysctlprovider"
	"lindm/internal/resource"
	"lindm/internal/trust"
)

// nativeResource is a process-local seam, never caller-supplied execution data.
// Production selects a native provider by the signed, canonical resource kind.
type nativeResource interface {
	Plan(context.Context, *resourcev1.ResourceDesiredState, resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error)
	Verify(context.Context, *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error)
	Apply(context.Context, *resourcev1.ResourcePlan, func(context.Context) error) (*resourcev1.ResourceVerification, error)
	Close() error
}

func (s *Service) openNativeResource(ctx context.Context, intent *agentv1.ResourceExecutionIntent, secrets secretAccessor) (nativeResource, error) {
	if err := resource.ValidateDesired(intent.GetDesired()); err != nil {
		return nil, err
	}
	platform, err := inventory.HostPlatform(ctx)
	if err != nil {
		return nil, err
	}
	if intent.GetDesired().GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE {
		record, _, err := s.store.LoadResourceAction(ctx, intent.GetActionId())
		if err != nil {
			return nil, err
		}
		if !proto.Equal(record.GetIntent(), intent) || !bytes.Equal(digestBytes(record.GetIntentEnvelope()), record.GetIntentSha256()) {
			return nil, errRecoveryHold
		}
		return packageprovider.Open(ctx, packageprovider.Config{
			Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
			EnrollmentGeneration: intent.GetEnrollmentGeneration(), StateDirectory: s.directory, Native: s.packageProvider,
			Preparation: intent.GetPreparation(), IntentDigest: record.GetIntentSha256(),
			NativeStage: s.packageNativeStage, NativeStageCancel: s.packageNativeCancel, NativeTransaction: s.packageNativeTransaction,
		})
	}
	switch intent.GetDesired().GetRef().GetKind() {
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE:
		return serviceprovider.Open(ctx, serviceprovider.Config{
			ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
		})
	case resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE:
		return fileprovider.Open(ctx, fileprovider.Config{
			Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
			EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Files,
			ProtectedPaths: s.nativeResources.ProtectedPaths, ExecuteNative: s.resourceNativeTransaction,
		})
	case resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER:
		return accountprovider.Open(ctx, accountprovider.Config{
			Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
			EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Accounts,
			NativeTransaction: s.resourceNativeApply, NativeDigest: s.store.PrivateDigest, Secrets: secrets,
			NativeObserve: func(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
				result, err := s.observeNativeResource(ctx, desired, platform, nil)
				if err != nil {
					return nil, err
				}
				return result.GetAfter(), nil
			},
		})
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL:
		return sysctlprovider.Open(ctx, sysctlprovider.Config{
			Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
			EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Sysctl, NativeApply: s.resourceNativeApply,
		})
	case resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION:
		return definitionprovider.Open(ctx, definitionprovider.Config{
			Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
			EnrollmentGeneration: intent.GetEnrollmentGeneration(), ExecuteNative: s.resourceNativeTransaction,
		})
	case resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE:
		return s.openFirewallResource(ctx, intent, platform)
	case resourcev1.ResourceKind_RESOURCE_KIND_ENCRYPTION_COMPLIANCE:
		return encryptionprovider.Open(ctx, encryptionprovider.Config{
			ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			AuthenticatedEscrow: s.authenticatedResourceEscrow,
			Observe: func(ctx context.Context) (*actionprovider.RootEncryptionEvidence, error) {
				result, err := s.observeNativeResource(ctx, intent.GetDesired(), platform, nil)
				if err != nil {
					return nil, err
				}
				return rootEncryptionEvidence(result)
			},
		})
	case resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY:
		return passwordprovider.Open(ctx, passwordprovider.Config{
			Journal: s.store, ExecutorIncarnation: s.incarnation, Ownership: intent.GetOwnership(), Platform: platform,
			ActionID: intent.GetActionId(), DeploymentID: intent.GetDeploymentId(), DeviceID: intent.GetDeviceId(),
			EnrollmentGeneration: intent.GetEnrollmentGeneration(), Native: s.nativeResources.Password, ExecuteNative: s.resourceNativeTransaction,
		})
	default:
		return nil, serviceprovider.ErrUnsupported
	}
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

// lookupResourceIntent extracts a bounded routing key only. Neither this payload
// nor its envelope is authority until current or historical verification below.
func (s *Service) lookupResourceIntent(encoded []byte) (string, error) {
	if len(encoded) == 0 || len(encoded) > 131072 {
		return "", errInvalid
	}
	var envelope dsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || envelope.PayloadType != trust.ResourceIntentType || len(envelope.Signatures) == 0 || len(envelope.Signatures) > 16 {
		return "", errInvalid
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 131072 {
		return "", errInvalid
	}
	intent := new(agentv1.ResourceExecutionIntent)
	if proto.Unmarshal(payload, intent) != nil || s.admit(intent) != nil {
		return "", errInvalid
	}
	if _, err := canonicalUUID(intent.GetActionId()); err != nil {
		return "", errInvalid
	}
	return intent.GetActionId(), nil
}

func (s *Service) prepareResourceExecution(ctx context.Context, req *agentv1.PrepareResourceExecutionRequest) (*agentv1.PrepareResourceExecutionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	actionID, err := s.lookupResourceIntent(req.GetIntentEnvelope())
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
	intent, err := s.currentResourceIntent(ctx, loaded, req.GetIntentEnvelope())
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
	intent, err = s.currentResourceIntent(ctx, loaded, req.GetIntentEnvelope())
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
	if _, err := s.authorizeResourceStart(ctx, loaded, record, req.GetStartGrantEnvelope()); err != nil {
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

func (s *Service) resourceIdentitySession(loaded *bound) error {
	if !certUsable(loaded.cert, s.now()) {
		return errIdentityExpired
	}
	if loaded.renewal != nil {
		return errRenewalPending
	}
	if loaded.state.GetPendingSession() != nil {
		return errSessionPending
	}
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if _, err := canonicalUUID(boot); err != nil {
		return errInternal
	}
	if loaded.state.GetSessionEpoch() == 0 || loaded.state.GetSessionBootId() != boot {
		return errSessionRequired
	}
	return nil
}

func (s *Service) currentResourceIntent(ctx context.Context, loaded *bound, envelope []byte) (*agentv1.ResourceExecutionIntent, error) {
	if err := s.resourceIdentitySession(loaded); err != nil {
		return nil, err
	}
	if loaded.execution.delegation == nil || s.now().Before(loaded.execution.state.GetAcceptedAt().AsTime()) {
		return nil, errResourceRejected
	}
	intent, err := loaded.execution.verifier.VerifyResourceIntent(ctx, loaded.execution.root, loaded.execution.delegation, envelope, s.now())
	if err != nil {
		return nil, resourceAuthorityError(ctx, err)
	}
	if !resourceTarget(loaded, intent) {
		return nil, errResourceRejected
	}
	return intent, nil
}

func resourceTarget(loaded *bound, intent *agentv1.ResourceExecutionIntent) bool {
	if intent.GetDeploymentId() != loaded.bootstrap.Root.GetDeploymentId() || intent.GetDeviceId() != loaded.state.GetDeviceId() || intent.GetEnrollmentGeneration() != loaded.state.GetEnrollmentGeneration() {
		return false
	}
	for _, id := range []string{intent.GetDeploymentId(), intent.GetDeviceId(), intent.GetEnrollmentGeneration(), intent.GetActionId(), intent.GetDesiredRevision(), intent.GetActorId()} {
		if _, err := canonicalUUID(id); err != nil {
			return false
		}
	}
	return true
}

func (s *Service) makeResourceChallenge(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord) error {
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if boot != record.GetNativePlan().GetBefore().GetMetadata().GetBootId() {
		return errResourceRejected
	}
	ns, err := s.boottime()
	if err != nil {
		return err
	}
	now := record.GetAcceptedAt().AsTime()
	if record.GetIntent().GetPreparation() != nil {
		now = s.now()
	}
	expires := now.Add(30 * time.Second)
	if intentEnd := record.GetIntent().GetExpiresAt().AsTime(); intentEnd.Before(expires) {
		expires = intentEnd
	}
	if preparation := record.GetIntent().GetPreparation(); preparation != nil && preparation.GetDeadline().AsTime().Before(expires) {
		expires = preparation.GetDeadline().AsTime()
	}
	lifetime := expires.Sub(now)
	if lifetime <= 0 || ns > math.MaxInt64-uint64(lifetime) {
		return errResourceExpired
	}
	planDigest, err := resource.PlanDigest(record.GetNativePlan())
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(s.entropy, nonce); err != nil {
		return err
	}
	intent := record.GetIntent()
	challenge := &agentv1.ResourceExecutionChallenge{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		ActionId: intent.GetActionId(), DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: intent.GetResourceSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(),
		IntentSha256: bytes.Clone(record.GetIntentSha256()), NativePlanSha256: planDigest[:], Nonce: nonce,
		BootId: boot, ExecutorIncarnation: s.incarnation, IssuedAt: protoTimestamp(now), ExpiresAt: protoTimestamp(expires),
		Ref: proto.CloneOf(intent.GetDesired().GetRef()), Operation: intent.GetOperation(),
	}
	proof, err := s.authority.Sign(ctx, challenge, loaded.identityKey)
	if err != nil {
		return err
	}
	record.Challenge, record.ChallengeProof = challenge, proof
	record.ChallengeBoottimeNs = ns + uint64(lifetime)
	record.ChallengeCertificatePem = bytes.Clone(loaded.state.GetCertificatePem())
	return nil
}

func (s *Service) authorizeResourceStart(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, grant []byte) (*agentv1.ResourceExecutionStartGrant, error) {
	if _, err := s.currentResourceIntent(ctx, loaded, record.GetIntentEnvelope()); err != nil {
		return nil, err
	}
	if err := s.resourceDeadline(record); err != nil {
		return nil, err
	}
	verified, err := loaded.execution.verifier.VerifyResourceStart(ctx, loaded.execution.root, loaded.execution.delegation, grant, record.GetIntent(), record.GetChallenge(), s.now())
	if err != nil {
		return nil, resourceAuthorityError(ctx, err)
	}
	return verified, nil
}

func (s *Service) resourceDeadline(record *agentv1.ResourceExecutionRecord) error {
	challenge := record.GetChallenge()
	if challenge == nil || challenge.GetExecutorIncarnation() != s.incarnation || s.now().Before(challenge.GetIssuedAt().AsTime()) || !s.now().Before(challenge.GetExpiresAt().AsTime()) {
		return errResourceExpired
	}
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if boot != challenge.GetBootId() {
		return errResourceExpired
	}
	ns, err := s.boottime()
	if err != nil {
		return err
	}
	lifetime := uint64(challenge.GetExpiresAt().AsTime().Sub(challenge.GetIssuedAt().AsTime()))
	deadline := record.GetChallengeBoottimeNs()
	if deadline < lifetime || ns < deadline-lifetime || ns >= deadline {
		return errResourceExpired
	}
	return nil
}

func (s *Service) expireResourceAction(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, revision int64) error {
	if record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		return s.checkResourcePreparation(ctx, loaded, record, revision)
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED && record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
		return nil
	}
	if err := s.resourceDeadline(record); err == nil {
		return nil
	} else if !errors.Is(err, errResourceExpired) {
		return err
	}
	if record.GetIntent().GetPreparation() != nil {
		return s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED)
	}
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
	next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
	next.CompletedAt = protoTimestamp(s.now())
	if err := s.updateResourceAction(ctx, loaded, revision, next); err != nil {
		return err
	}
	proto.Reset(record)
	proto.Merge(record, next)
	return nil
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

func resourceAuthorityError(ctx context.Context, _ error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errResourceRejected
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
	if plan.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE {
		return serviceprovider.ValidatePlan(plan)
	}
	return nil
}

func validateResourceVerification(plan *resourcev1.ResourcePlan, verification *resourcev1.ResourceVerification) error {
	if err := resource.ValidatePlanVerification(plan, verification); err != nil {
		return err
	}
	if plan.GetRef().GetKind() == resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE {
		return serviceprovider.ValidateVerification(plan, verification)
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
