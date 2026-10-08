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
	"lindm/internal/agent/journal"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/trust"
)

// nativeService is a process-local seam, never caller-supplied execution data.
// Production always opens the protected native systemd provider.
type nativeService interface {
	Plan(context.Context, *agentv1.ServiceDesiredState) (*agentv1.ServicePlan, error)
	Verify(context.Context, *agentv1.ServicePlan) (*agentv1.ServiceVerification, error)
	Apply(context.Context, *agentv1.ServicePlan, func(context.Context) error) (*agentv1.ServiceVerification, error)
	Close() error
}

func openNativeService(ctx context.Context) (nativeService, error) { return serviceprovider.Open(ctx) }

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

func (s *Service) PrepareServiceExecution(ctx context.Context, req *connect.Request[agentv1.PrepareServiceExecutionRequest]) (*connect.Response[agentv1.PrepareServiceExecutionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.prepareServiceExecution(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) StartServiceExecution(ctx context.Context, req *connect.Request[agentv1.StartServiceExecutionRequest]) (*connect.Response[agentv1.StartServiceExecutionResponse], error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	if req == nil {
		return nil, mapError(errInvalid)
	}
	msg, err := s.startServiceExecution(ctx, req.Msg)
	if err != nil {
		return nil, mapError(err)
	}
	return noStore(msg), nil
}

func (s *Service) GetServiceExecution(ctx context.Context, req *connect.Request[agentv1.GetServiceExecutionRequest]) (*connect.Response[agentv1.GetServiceExecutionResponse], error) {
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
	record, revision, err := s.loadServiceAction(ctx, loaded, req.Msg.GetActionId())
	if err != nil {
		return nil, mapError(err)
	}
	if err := s.expireServiceAction(ctx, loaded, record, revision); err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.GetServiceExecutionResponse{Status: serviceStatus(record)}), nil
}

// lookupServiceIntent extracts a bounded routing key only. Neither this payload
// nor its envelope is authority until current or historical verification below.
func (s *Service) lookupServiceIntent(encoded []byte) (string, error) {
	if len(encoded) == 0 || len(encoded) > 16384 {
		return "", errInvalid
	}
	var envelope dsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || envelope.PayloadType != trust.ServiceIntentType || len(envelope.Signatures) == 0 || len(envelope.Signatures) > 16 {
		return "", errInvalid
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 16384 {
		return "", errInvalid
	}
	intent := new(agentv1.ServiceExecutionIntent)
	if proto.Unmarshal(payload, intent) != nil || s.admit(intent) != nil {
		return "", errInvalid
	}
	if _, err := canonicalUUID(intent.GetActionId()); err != nil {
		return "", errInvalid
	}
	return intent.GetActionId(), nil
}

func (s *Service) prepareServiceExecution(ctx context.Context, req *agentv1.PrepareServiceExecutionRequest) (*agentv1.PrepareServiceExecutionResponse, error) {
	if err := s.admit(req); err != nil {
		return nil, err
	}
	actionID, err := s.lookupServiceIntent(req.GetIntentEnvelope())
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
	if old, _, err := s.loadServiceAction(ctx, loaded, actionID); err == nil {
		s.mu.Unlock()
		if !bytes.Equal(old.GetIntentEnvelope(), req.GetIntentEnvelope()) {
			return nil, errIdempotencyConflict
		}
		return servicePreparation(old), nil
	} else if !errors.Is(err, journal.ErrServiceActionNotFound) {
		s.mu.Unlock()
		return nil, err
	}
	intent, err := s.currentServiceIntent(ctx, loaded, req.GetIntentEnvelope())
	if err != nil {
		s.mu.Unlock()
		return nil, err
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
	provider, err := s.openService(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = provider.Close() }()
	plan, err := provider.Plan(ctx, intent.GetDesired())
	if err != nil {
		return nil, err
	}
	if serviceprovider.ValidatePlan(plan) != nil || !proto.Equal(plan.GetDesired(), intent.GetDesired()) {
		return nil, errInternal
	}
	var verification *agentv1.ServiceVerification
	if !serviceDrift(plan) {
		verification, err = provider.Verify(ctx, plan)
		if err != nil {
			return nil, err
		}
		if serviceprovider.ValidateVerification(plan, verification) != nil || !verification.GetConverged() {
			return nil, errInternal
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
	if old, _, err := s.loadServiceAction(ctx, loaded, actionID); err == nil {
		if !bytes.Equal(old.GetIntentEnvelope(), req.GetIntentEnvelope()) {
			return nil, errIdempotencyConflict
		}
		return servicePreparation(old), nil
	} else if !errors.Is(err, journal.ErrServiceActionNotFound) {
		return nil, err
	}
	intent, err = s.currentServiceIntent(ctx, loaded, req.GetIntentEnvelope())
	if err != nil {
		return nil, err
	}
	now := s.now()
	record := &agentv1.ServiceExecutionRecord{
		FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(),
		IntentEnvelope: bytes.Clone(req.GetIntentEnvelope()), IntentSha256: digestBytes(req.GetIntentEnvelope()),
		Intent: intent, NativePlan: plan, AcceptedRoot: loaded.execution.root,
		AcceptedDelegationEnvelope: bytes.Clone(loaded.execution.state.GetDelegationEnvelope()),
		AcceptedAt:                 protoTimestamp(now), State: agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED,
		Failure: agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NONE,
	}
	if plan.GetBefore().GetBootId() != loaded.state.GetSessionBootId() {
		return nil, errServiceRejected
	}
	if serviceDrift(plan) {
		if err := s.makeServiceChallenge(ctx, loaded, record); err != nil {
			return nil, err
		}
	} else {
		record.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED
		record.Verification = verification
		record.CompletedAt = protoTimestamp(now)
	}
	// Validate protected generated evidence before it can become a receipt.
	if err := s.verifyServiceRecord(ctx, loaded, record); err != nil {
		return nil, errInternal
	}
	if _, err := s.store.AcceptServiceAction(ctx, loaded.revision, loaded.execution.revision, record); err != nil {
		return nil, s.serviceStoreError(err)
	}
	return servicePreparation(record), nil
}

func (s *Service) startServiceExecution(ctx context.Context, req *agentv1.StartServiceExecutionRequest) (*agentv1.StartServiceExecutionResponse, error) {
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
	record, revision, err := s.loadServiceAction(ctx, loaded, req.GetActionId())
	if err != nil {
		return nil, err
	}
	// An already accepted exact grant is only a historical lookup, even after
	// expiry/revocation. It cannot queue work, consume again or extend a deadline.
	if len(record.GetStartGrantEnvelope()) != 0 {
		if !bytes.Equal(record.GetStartGrantEnvelope(), req.GetStartGrantEnvelope()) {
			return nil, errIdempotencyConflict
		}
		return &agentv1.StartServiceExecutionResponse{Status: serviceStatus(record)}, nil
	}
	if err := s.expireServiceAction(ctx, loaded, record, revision); err != nil {
		return nil, err
	}
	if record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED {
		return nil, errServiceRejected
	}
	if _, err := s.authorizeServiceStart(ctx, loaded, record, req.GetStartGrantEnvelope()); err != nil {
		return nil, err
	}
	next := proto.CloneOf(record)
	next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED
	next.StartGrantEnvelope = bytes.Clone(req.GetStartGrantEnvelope())
	next.StartGrantSha256 = digestBytes(req.GetStartGrantEnvelope())
	next.GrantAcceptedAt = protoTimestamp(s.now())
	if err := s.updateServiceAction(ctx, loaded, revision, next); err != nil {
		return nil, err
	}
	s.wakeServiceWorker()
	return &agentv1.StartServiceExecutionResponse{Status: serviceStatus(next)}, nil
}

func (s *Service) serviceIdentitySession(loaded *bound) error {
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

func (s *Service) currentServiceIntent(ctx context.Context, loaded *bound, envelope []byte) (*agentv1.ServiceExecutionIntent, error) {
	if err := s.serviceIdentitySession(loaded); err != nil {
		return nil, err
	}
	if loaded.execution.delegation == nil || s.now().Before(loaded.execution.state.GetAcceptedAt().AsTime()) {
		return nil, errServiceRejected
	}
	intent, err := loaded.execution.verifier.VerifyServiceIntent(ctx, loaded.execution.root, loaded.execution.delegation, envelope, s.now())
	if err != nil {
		return nil, serviceAuthorityError(ctx, err)
	}
	if !serviceTarget(loaded, intent) {
		return nil, errServiceRejected
	}
	return intent, nil
}

func serviceTarget(loaded *bound, intent *agentv1.ServiceExecutionIntent) bool {
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

func (s *Service) makeServiceChallenge(ctx context.Context, loaded *bound, record *agentv1.ServiceExecutionRecord) error {
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if boot != record.GetNativePlan().GetBefore().GetBootId() {
		return errServiceRejected
	}
	ns, err := s.boottime()
	if err != nil {
		return err
	}
	now := record.GetAcceptedAt().AsTime()
	expires := now.Add(30 * time.Second)
	if intentEnd := record.GetIntent().GetExpiresAt().AsTime(); intentEnd.Before(expires) {
		expires = intentEnd
	}
	lifetime := expires.Sub(now)
	if lifetime <= 0 || ns > math.MaxInt64-uint64(lifetime) {
		return errServiceExpired
	}
	planDigest, err := digestMessage(record.GetNativePlan())
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(s.entropy, nonce); err != nil {
		return err
	}
	intent := record.GetIntent()
	challenge := &agentv1.ServiceExecutionChallenge{
		DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(),
		ActionId: intent.GetActionId(), DesiredRevision: intent.GetDesiredRevision(), ResourceSequence: intent.GetResourceSequence(), RecoveryEpoch: intent.GetRecoveryEpoch(),
		IntentSha256: bytes.Clone(record.GetIntentSha256()), NativePlanSha256: planDigest, Nonce: nonce,
		BootId: boot, ExecutorIncarnation: s.incarnation, IssuedAt: protoTimestamp(now), ExpiresAt: protoTimestamp(expires),
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

func (s *Service) authorizeServiceStart(ctx context.Context, loaded *bound, record *agentv1.ServiceExecutionRecord, grant []byte) (*agentv1.ServiceExecutionStartGrant, error) {
	if _, err := s.currentServiceIntent(ctx, loaded, record.GetIntentEnvelope()); err != nil {
		return nil, err
	}
	if err := s.serviceDeadline(record); err != nil {
		return nil, err
	}
	verified, err := loaded.execution.verifier.VerifyServiceStart(ctx, loaded.execution.root, loaded.execution.delegation, grant, record.GetIntent(), record.GetChallenge(), s.now())
	if err != nil {
		return nil, serviceAuthorityError(ctx, err)
	}
	return verified, nil
}

func (s *Service) serviceDeadline(record *agentv1.ServiceExecutionRecord) error {
	challenge := record.GetChallenge()
	if challenge == nil || challenge.GetExecutorIncarnation() != s.incarnation || s.now().Before(challenge.GetIssuedAt().AsTime()) || !s.now().Before(challenge.GetExpiresAt().AsTime()) {
		return errServiceExpired
	}
	boot, err := s.bootID()
	if err != nil {
		return err
	}
	if boot != challenge.GetBootId() {
		return errServiceExpired
	}
	ns, err := s.boottime()
	if err != nil {
		return err
	}
	lifetime := uint64(challenge.GetExpiresAt().AsTime().Sub(challenge.GetIssuedAt().AsTime()))
	deadline := record.GetChallengeBoottimeNs()
	if deadline < lifetime || ns < deadline-lifetime || ns >= deadline {
		return errServiceExpired
	}
	return nil
}

func (s *Service) expireServiceAction(ctx context.Context, loaded *bound, record *agentv1.ServiceExecutionRecord, revision int64) error {
	if record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_PREPARED && record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED {
		return nil
	}
	if err := s.serviceDeadline(record); err == nil {
		return nil
	} else if !errors.Is(err, errServiceExpired) {
		return err
	}
	next := proto.CloneOf(record)
	next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
	next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_EXPIRED
	next.CompletedAt = protoTimestamp(s.now())
	if err := s.updateServiceAction(ctx, loaded, revision, next); err != nil {
		return err
	}
	proto.Reset(record)
	proto.Merge(record, next)
	return nil
}

func serviceDrift(plan *agentv1.ServicePlan) bool {
	return plan.GetChangeRuntime() || plan.GetChangeEnablement()
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

func serviceAuthorityError(ctx context.Context, _ error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errServiceRejected
}

func serviceStatus(record *agentv1.ServiceExecutionRecord) *agentv1.ServiceExecutionStatus {
	return &agentv1.ServiceExecutionStatus{
		ActionId: record.GetIntent().GetActionId(), IntentSha256: bytes.Clone(record.GetIntentSha256()), State: record.GetState(), Failure: record.GetFailure(),
		AcceptedAt: proto.CloneOf(record.GetAcceptedAt()), StartedAt: proto.CloneOf(record.GetStartedAt()), CompletedAt: proto.CloneOf(record.GetCompletedAt()),
		Before: proto.CloneOf(record.GetNativePlan().GetBefore()), Verification: proto.CloneOf(record.GetVerification()),
	}
}

func servicePreparation(record *agentv1.ServiceExecutionRecord) *agentv1.PrepareServiceExecutionResponse {
	return &agentv1.PrepareServiceExecutionResponse{Status: serviceStatus(record), NativePlan: proto.CloneOf(record.GetNativePlan()), ChallengeProof: bytes.Clone(record.GetChallengeProof())}
}
