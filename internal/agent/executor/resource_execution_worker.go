//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"

	"lindm/internal/agent/journal"
	"lindm/internal/agent/osupdateprovider"
	"lindm/internal/agent/packageprovider"
	"lindm/internal/resource"
)

func (s *Service) wakeResourceWorker() {
	select {
	case s.workerWake <- struct{}{}:
	default:
	}
}

// New calls this before publishing Service. A new incarnation makes every
// unconsumed challenge unusable, even if the host did not reboot. RUNNING is
// authenticated here and left for the worker's read-only reconciliation.
func (s *Service) recoverResourceActions(ctx context.Context) error {
	if s.store == nil || s.hold {
		return nil
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return err
	}
	cursor := ""
	for {
		record, revision, err := s.store.NextUnfinishedResourceAction(ctx, cursor)
		if errors.Is(err, journal.ErrResourceActionNotFound) {
			return nil
		}
		if err != nil {
			return s.resourceStoreError(err)
		}
		if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
			if errors.Is(err, errRecoveryHold) {
				s.noteTrustDamage()
			}
			return err
		}
		cursor = record.GetIntent().GetActionId()
		if record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
			if err := s.checkResourcePreparation(ctx, loaded, record, revision); errors.Is(err, errRecoveryHold) {
				return err
			}
			continue
		}
		if record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
			s.wakeResourceWorker()
			continue
		}
		if record.GetIntent().GetPreparation() != nil {
			if err := s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED); err != nil {
				return err
			}
			continue
		}
		record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
		record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED
		record.CompletedAt = protoTimestamp(s.now())
		if err := s.updateResourceAction(ctx, loaded, revision, record); err != nil {
			return err
		}
	}
}

func (s *Service) resourceWorker() {
	defer s.worker.Done()
	defer s.interruptResourceActions()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.workerContext.Done():
			return
		case <-s.workerWake:
		case <-tick.C:
		}
		cursor := ""
		for s.workerContext.Err() == nil {
			record, err := s.nextResourceWork(s.workerContext, cursor)
			if errors.Is(err, journal.ErrResourceActionNotFound) {
				break
			}
			if err != nil {
				// Cleanup may need a later bounded cycle while a helper stops.
				// Only damaged protected evidence enters permanent recovery hold.
				if s.workerContext.Err() == nil && (errors.Is(err, errRecoveryHold) || errors.Is(err, journal.ErrRecoveryHold)) {
					s.mu.Lock()
					s.noteTrustDamage()
					s.mu.Unlock()
				}
				break
			}
			cursor = record.GetIntent().GetActionId()
			switch record.GetState() {
			case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED:
				s.runResourceAction(record)
			case agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING:
				s.reconcileResourceAction(record)
			}
		}
	}
}

func (s *Service) nextResourceWork(ctx context.Context, cursor string) (*agentv1.ResourceExecutionRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.store == nil {
		return nil, journal.ErrResourceActionNotFound
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	record, revision, err := s.store.NextUnfinishedResourceAction(ctx, cursor)
	if err != nil {
		return nil, s.resourceStoreError(err)
	}
	if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return nil, err
	}
	if err := s.expireResourceAction(ctx, loaded, record, revision); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) runResourceAction(record *agentv1.ResourceExecutionRecord) {
	provider, err := s.openResource(s.workerContext, record.GetIntent(), s.resourceSecrets(record.GetIntent(), record.GetSealedSecrets()))
	if err != nil {
		s.finishResourceAction(record.GetIntent().GetActionId(), nil, err, false, nil)
		return
	}
	defer func() { _ = provider.Close() }()
	result, err := provider.Apply(s.workerContext, record.GetNativePlan(), func(ctx context.Context) error {
		return s.consumeResourceStart(ctx, record)
	})
	s.finishResourceAction(record.GetIntent().GetActionId(), result, err, false, nativeFirewallEvidence(provider))
}

// This is the sole effect gate. The native provider calls it after its own
// serialization, final native reads and subscription setup, immediately before
// the first mutation. There is intentionally no RPC-supplied callback or plan.
func (s *Service) consumeResourceStart(ctx context.Context, expected *agentv1.ResourceExecutionRecord) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return err
	}
	record, revision, err := s.loadResourceAction(ctx, loaded, expected.GetIntent().GetActionId())
	if err != nil {
		return err
	}
	if record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED || !proto.Equal(record.GetNativePlan(), expected.GetNativePlan()) || !bytes.Equal(record.GetStartGrantEnvelope(), expected.GetStartGrantEnvelope()) {
		return errResourceRejected
	}
	grant, err := s.authorizeResourceStart(ctx, loaded, record, record.GetStartGrantEnvelope())
	if err != nil {
		return err
	}
	next := proto.CloneOf(record)
	next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING
	next.StartedAt = protoTimestamp(s.now())
	if err := s.updateResourceAction(ctx, loaded, revision, next); err != nil {
		return err
	}
	// A slow durable commit cannot extend the start window. A rejection here
	// leaves consumed RUNNING evidence but permits no native mutation.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.resourceDeadline(record); err != nil {
		return err
	}
	now := s.now()
	if now.Before(grant.GetNotBefore().AsTime()) || !now.Before(grant.GetExpiresAt().AsTime()) {
		return errResourceExpired
	}
	if !certUsable(loaded.cert, now) {
		return errIdentityExpired
	}
	return nil
}

// Previously RUNNING work is NEVER replayed. Verify only observes the original
// signed desired state and native definition/boot fences; uncertainty survives.
func (s *Service) reconcileResourceAction(record *agentv1.ResourceExecutionRecord) {
	provider, err := s.openResource(s.workerContext, record.GetIntent(), s.resourceSecrets(record.GetIntent(), record.GetSealedSecrets()))
	if err != nil {
		s.finishResourceAction(record.GetIntent().GetActionId(), nil, err, true, nil)
		return
	}
	defer func() { _ = provider.Close() }()
	result, err := provider.Verify(s.workerContext, record.GetNativePlan())
	s.finishResourceAction(record.GetIntent().GetActionId(), result, err, true, nativeFirewallEvidence(provider))
}

func (s *Service) finishResourceAction(actionID string, result *resourcev1.ResourceVerification, operationErr error, reconcile bool, firewallEvidence *agentv1.ConnectivityVerificationEvidence) {
	// Completion is evidence, not new authority. It survives request cancellation,
	// shutdown cancellation, trust rotation, expired identity and expired grants.
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded, err := s.load(ctx)
	if err != nil {
		s.noteTrustDamage()
		return
	}
	record, revision, err := s.loadResourceAction(ctx, loaded, actionID)
	if err != nil {
		s.noteTrustDamage()
		return
	}
	state := record.GetState()
	if state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING && state != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_QUEUED {
		// A higher sequence or a concurrent read may already have expired or
		// superseded this queued action. Never overwrite its terminal evidence.
		return
	}
	if operationErr != nil {
		// The signed status carries only the typed failure; the local journal
		// keeps the provider error for the device administrator.
		slog.Warn("resource execution failed", "action_id", actionID, "state", state.String(), "error", operationErr)
	}
	next := proto.CloneOf(record)
	next.CompletedAt = protoTimestamp(s.now())
	if result != nil && validateResourceVerification(record.GetNativePlan(), result) != nil {
		result = nil
		operationErr = errInternal
	}
	next.Verification = result
	next.FirewallEvidence = nil
	if result != nil {
		next.FirewallEvidence = proto.CloneOf(firewallEvidence)
	}
	if state == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
		if operationErr == nil && result.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
			next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
		} else if !reconcile && errors.Is(operationErr, resource.ErrNotConverged) && result != nil {
			next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
		} else {
			next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_OBSERVATION
			if errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
				next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED
			}
		}
	} else {
		next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED
		next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE
		switch {
		case errors.Is(operationErr, context.Canceled), errors.Is(operationErr, errClosed):
			next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED
		case errors.Is(operationErr, errResourceExpired):
			next.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_EXPIRED
		case errors.Is(operationErr, errResourceRejected), errors.Is(operationErr, errIdentityExpired), errors.Is(operationErr, errSessionRequired), errors.Is(operationErr, errSessionPending), errors.Is(operationErr, errRenewalPending), errors.Is(operationErr, journal.ErrResourceActionRejected):
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_AUTHORITY
		case errors.Is(operationErr, packageprovider.ErrBusy), errors.Is(operationErr, osupdateprovider.ErrBusy):
			// Refused before the start gate: no effect, retried by the server.
			next.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY
		default:
			if _, failure, classified := resourceAdmissionCause(operationErr); classified {
				next.Failure = failure
			}
		}
	}
	if err := s.updateResourceAction(ctx, loaded, revision, next); err != nil {
		// Do not replay an effect after a failed durable completion. Keeping the
		// RUNNING row plus recovery hold is safer than a fabricated success.
		s.noteTrustDamage()
	}
}

func (s *Service) interruptResourceActions() {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil || s.hold {
		return
	}
	loaded, err := s.load(ctx)
	if err != nil {
		s.noteTrustDamage()
		return
	}
	cursor := ""
	for {
		record, revision, err := s.store.NextUnfinishedResourceAction(ctx, cursor)
		if errors.Is(err, journal.ErrResourceActionNotFound) {
			return
		}
		if err != nil {
			s.noteTrustDamage()
			return
		}
		if err := s.verifyResourceRecord(ctx, loaded, record); err != nil {
			s.noteTrustDamage()
			return
		}
		cursor = record.GetIntent().GetActionId()
		if record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARING {
			// Independent staging survives executor shutdown. The signed helper
			// deadline remains authoritative; restart resumes the same action.
			continue
		}
		if record.GetIntent().GetPreparation() != nil && record.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
			if err := s.endResourcePreparation(ctx, loaded, record, revision, agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED); err != nil {
				return
			}
			continue
		}
		if record.GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_RUNNING {
			record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN
		} else {
			record.State = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_EXPIRED
		}
		record.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_INTERRUPTED
		record.CompletedAt = protoTimestamp(s.now())
		if err := s.updateResourceAction(ctx, loaded, revision, record); err != nil {
			s.noteTrustDamage()
			return
		}
	}
}
