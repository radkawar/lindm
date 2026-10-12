//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/admissiondetail"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/resource"
)

// These two helpers take ownership of the caller's authority lock. Admission is
// durable before opening the provider, so a killed RPC cannot orphan its stage.
func (s *Service) admitResourcePreparationLocked(ctx context.Context, loaded *bound, intent *agentv1.ResourceExecutionIntent, envelope []byte, sealed [][]byte) (*agentv1.PrepareResourceExecutionResponse, error) {
	if !s.now().Before(intent.GetPreparation().GetDeadline().AsTime()) {
		s.mu.Unlock()
		return nil, errResourceExpired
	}
	record := &agentv1.ResourceExecutionRecord{
		FormatVersion: 1, InstallationId: loaded.state.GetInstallationId(),
		IntentEnvelope: bytes.Clone(envelope), IntentSha256: digestBytes(envelope), Intent: intent,
		AcceptedRoot: proto.CloneOf(loaded.execution.root), AcceptedDelegationEnvelope: bytes.Clone(loaded.execution.state.GetDelegationEnvelope()),
		AcceptedAt: protoTimestamp(s.now()), State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING,
		Failure: agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE,
	}
	for _, delivery := range sealed {
		record.SealedSecrets = append(record.SealedSecrets, bytes.Clone(delivery))
	}
	if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	revision, err := s.store.AcceptResourceAction(ctx, loaded.revision, loaded.execution.revision, record)
	if err != nil {
		err = s.resourceStoreError(err)
		s.mu.Unlock()
		return nil, err
	}
	return s.pollResourcePreparationLocked(ctx, loaded, record, revision)
}

func (s *Service) pollResourcePreparationLocked(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, revision int64) (*agentv1.PrepareResourceExecutionResponse, error) {
	if err := s.checkResourcePreparation(ctx, loaded, record, revision); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		s.mu.Unlock()
		return resourcePreparation(record), nil
	}
	actionID := record.GetIntent().GetActionId()
	if _, active := s.resourcePreparations[actionID]; active {
		s.mu.Unlock()
		return resourcePreparation(record), nil
	}
	if s.resourcePreparations == nil {
		s.resourcePreparations = make(map[string]struct{})
	}
	s.resourcePreparations[actionID] = struct{}{}
	s.operations.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.workerContext, cancel)
	s.mu.Unlock()
	defer s.operations.Done()
	defer func() {
		s.mu.Lock()
		delete(s.resourcePreparations, actionID)
		s.mu.Unlock()
	}()
	defer cancel()
	defer stop()
	provider, operationErr := s.openResource(ctx, record.GetIntent(), s.resourceSecrets(record.GetIntent(), record.GetSealedSecrets()))
	var plan *resourcev1.ResourcePlan
	var verification *resourcev1.ResourceVerification
	if operationErr == nil {
		defer func() { _ = provider.Close() }()
		plan, operationErr = provider.Plan(ctx, record.GetIntent().GetDesired(), record.GetIntent().GetOperation())
		if operationErr == nil && (validateResourcePlan(plan) != nil || !proto.Equal(resource.PlanDesired(plan), record.GetIntent().GetDesired()) || plan.GetOperation() != record.GetIntent().GetOperation()) {
			operationErr = errInternal
		}
		if operationErr == nil && !resourceDrift(plan) {
			verification, operationErr = provider.Verify(ctx, plan)
			operationErr = validateReadOnlyResourceResult(plan, verification, operationErr)
		}
	}
	// Request loss does not cancel the independently owned stage. Exact retries
	// recover from the journal and the helper's durable request/result digest.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	current, revision, err := s.loadResourceAction(ctx, loaded, record.GetIntent().GetActionId())
	if err != nil {
		return nil, err
	}
	if current.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		if current.GetPreparationOutcome() != nil {
			if err := s.cancelNativePreparation(ctx, current); err != nil {
				return nil, err
			}
		} else if operationErr == nil && !proto.Equal(plan, current.GetNativePlan()) {
			// Two READY results for one immutable action may never disagree.
			s.noteTrustDamage()
			return nil, errRecoveryHold
		}
		return resourcePreparation(current), nil
	}
	if err := s.checkResourcePreparation(ctx, loaded, current, revision); err != nil {
		return nil, err
	}
	if current.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		return resourcePreparation(current), nil
	}
	if errors.Is(operationErr, resource.ErrPreparing) {
		if plan != nil {
			return nil, errInternal
		}
		return resourcePreparation(current), nil
	}
	if operationErr != nil {
		slog.Warn("resource preparation failed", "action_id", current.GetIntent().GetActionId(), "error", operationErr)
		if err := s.endResourcePreparationDetail(ctx, loaded, current, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, preparationFailure(operationErr), admissiondetail.Of(operationErr)); err != nil {
			return nil, err
		}
		return resourcePreparation(current), nil
	}
	if plan.GetBefore().GetMetadata().GetBootId() != loaded.state.GetSessionBootId() || plan.GetBefore().GetMetadata().GetExecutorIncarnation() != s.incarnation {
		slog.Warn("resource preparation crossed a boot or executor restart", "action_id", current.GetIntent().GetActionId())
		if err := s.endResourcePreparation(ctx, loaded, current, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION); err != nil {
			return nil, err
		}
		return resourcePreparation(current), nil
	}
	next := proto.CloneOf(current)
	next.NativePlan = plan
	if resourceDrift(plan) {
		next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED
		if err := s.makeResourceChallenge(ctx, loaded, next); err != nil {
			return nil, err
		}
	} else {
		if err := s.cancelNativePreparation(ctx, current); err != nil {
			return nil, err
		}
		recordReadOnlyResourceResult(next, verification)
		next.FirewallEvidence = nativeFirewallEvidence(provider)
		next.CompletedAt = protoTimestamp(s.now())
	}
	if err := s.updateResourceAction(ctx, loaded, revision, next); err != nil {
		return nil, err
	}
	return resourcePreparation(next), nil
}

// preparationFailure classifies an effect-free staging failure. A native
// frontend holding the package lock (a release upgrade) is a retried hold; any
// provider's unsupported refusal is UNSUPPORTED, exactly as at admission.
func preparationFailure(err error) agentv1.ResourceExecutionFailure {
	if errors.Is(err, packageprovider.ErrBusy) {
		return agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY
	}
	if _, failure, classified := resourceAdmissionCause(err); classified && failure == agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED {
		return failure
	}
	return agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION
}

// Called under the authority lock. Current trust and signed wall deadline are
// checked on every bounded cycle; acceptance time and ownership never change.
func (s *Service) checkResourcePreparation(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, revision int64) error {
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
		return nil
	}
	if s.now().Before(record.GetAcceptedAt().AsTime()) || !s.now().Before(record.GetIntent().GetPreparation().GetDeadline().AsTime()) {
		return s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED)
	}
	if _, err := resourceAction.current(ctx, s, loaded, record.GetIntentEnvelope()); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_AUTHORITY)
	}
	return nil
}

func (s *Service) cancelNativePreparation(ctx context.Context, record *agentv1.ResourceExecutionRecord) error {
	return s.cancelPreparation(ctx, record.GetIntent())
}

func (s *Service) cancelPackagePreparation(ctx context.Context, intent *agentv1.ResourceExecutionIntent) error {
	// Cleanup must still work after source configuration, package tools or
	// platform qualification change. It only names the previously owned action.
	return packageprovider.CancelPreparation(ctx, packageprovider.Config{
		ActionID: intent.GetActionId(), StateDirectory: s.directory, NativeStageCancel: s.packageNativeCancel,
	})
}

func (s *Service) endResourcePreparation(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, revision int64, state agentv1.ResourceExecutionState, failure agentv1.ResourceExecutionFailure) error {
	return s.endResourcePreparationDetail(ctx, loaded, record, revision, state, failure, "")
}

// endResourcePreparationDetail also records the provider's closed actionable
// detail (for example existing_package_unverified or native_tool_outdated) of
// an effect-free staging failure, so the administrator sees the cause.
func (s *Service) endResourcePreparationDetail(ctx context.Context, loaded *bound, record *agentv1.ResourceExecutionRecord, revision int64, state agentv1.ResourceExecutionState, failure agentv1.ResourceExecutionFailure, detail string) error {
	// Cleanup is retried if the RPC or durable completion fails. The native
	// cancellation tombstone forbids a concurrent late Stage from recreating it.
	if err := s.cancelNativePreparation(ctx, record); err != nil {
		return err
	}
	next := proto.CloneOf(record)
	next.State, next.Failure, next.CompletedAt = state, failure, protoTimestamp(s.now())
	if record.GetNativePlan() == nil {
		next.PreparationOutcome = &agentv1.ResourcePreparationOutcome{Preparation: proto.CloneOf(record.GetIntent().GetPreparation()), Failure: failure, Detail: detail}
	}
	if err := s.updateResourceAction(ctx, loaded, revision, next); err != nil {
		return err
	}
	proto.Reset(record)
	proto.Merge(record, next)
	return nil
}

func (s *Service) CancelResourcePreparation(ctx context.Context, req *connect.Request[agentv1.CancelResourcePreparationRequest]) (*connect.Response[agentv1.CancelResourcePreparationResponse], error) {
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
	if errors.Is(err, journal.ErrResourceActionNotFound) {
		if err := s.store.CancelUnpreparedResourceAction(ctx, loaded.revision, req.Msg.GetActionId(), req.Msg.GetIntentSha256()); err != nil {
			return nil, mapError(s.resourceStoreError(err))
		}
		return noStore(&agentv1.CancelResourcePreparationResponse{NeverPrepared: true}), nil
	}
	if err != nil {
		return nil, mapError(err)
	}
	if !bytes.Equal(record.GetIntentSha256(), req.Msg.GetIntentSha256()) {
		return nil, mapError(errIdempotencyConflict)
	}
	if record.GetCompletedAt() != nil {
		return noStore(&agentv1.CancelResourcePreparationResponse{Status: resourceStatus(record)}), nil
	}
	if record.GetIntent().GetPreparation() == nil || len(record.GetStartGrantEnvelope()) != 0 || (record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING && record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED) {
		return nil, mapError(errResourceRejected)
	}
	if err := s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUPERSEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_SUPERSEDED); err != nil {
		return nil, mapError(err)
	}
	return noStore(&agentv1.CancelResourcePreparationResponse{Status: resourceStatus(record)}), nil
}
