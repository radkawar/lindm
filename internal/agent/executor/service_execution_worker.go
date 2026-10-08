//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/serviceprovider"
)

func (s *Service) wakeServiceWorker() {
	select {
	case s.workerWake <- struct{}{}:
	default:
	}
}

// New calls this before publishing Service. A new incarnation makes every
// unconsumed challenge unusable, even if the host did not reboot. RUNNING is
// authenticated here and left for the worker's read-only reconciliation.
func (s *Service) recoverServiceActions(ctx context.Context) error {
	if s.store == nil || s.hold {
		return nil
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return err
	}
	cursor := ""
	for {
		record, revision, err := s.store.NextUnfinishedServiceAction(ctx, cursor)
		if errors.Is(err, journal.ErrServiceActionNotFound) {
			return nil
		}
		if err != nil {
			return s.serviceStoreError(err)
		}
		if err := s.verifyServiceRecord(ctx, loaded, record); err != nil {
			if errors.Is(err, errRecoveryHold) {
				s.noteTrustDamage()
			}
			return err
		}
		cursor = record.GetIntent().GetActionId()
		if record.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING {
			s.wakeServiceWorker()
			continue
		}
		record.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
		record.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED
		record.CompletedAt = protoTimestamp(s.now())
		if err := s.updateServiceAction(ctx, loaded, revision, record); err != nil {
			return err
		}
	}
}

func (s *Service) serviceWorker() {
	defer s.worker.Done()
	defer s.interruptServiceActions()
	for {
		select {
		case <-s.workerContext.Done():
			return
		case <-s.workerWake:
		}
		cursor := ""
		for s.workerContext.Err() == nil {
			record, err := s.nextServiceWork(s.workerContext, cursor)
			if errors.Is(err, journal.ErrServiceActionNotFound) {
				break
			}
			if err != nil {
				// Storage/binding failures do not cause a replay loop. The durable
				// pending row remains evidence; operator recovery is required.
				if s.workerContext.Err() == nil {
					s.mu.Lock()
					s.noteTrustDamage()
					s.mu.Unlock()
				}
				break
			}
			cursor = record.GetIntent().GetActionId()
			switch record.GetState() {
			case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED:
				s.runServiceAction(record)
			case agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING:
				s.reconcileServiceAction(record)
			}
		}
	}
}

func (s *Service) nextServiceWork(ctx context.Context, cursor string) (*agentv1.ServiceExecutionRecord, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.store == nil {
		return nil, journal.ErrServiceActionNotFound
	}
	loaded, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	record, _, err := s.store.NextUnfinishedServiceAction(ctx, cursor)
	if err != nil {
		return nil, s.serviceStoreError(err)
	}
	if err := s.verifyServiceRecord(ctx, loaded, record); err != nil {
		if errors.Is(err, errRecoveryHold) {
			s.noteTrustDamage()
		}
		return nil, err
	}
	return record, nil
}

func (s *Service) runServiceAction(record *agentv1.ServiceExecutionRecord) {
	provider, err := s.openService(s.workerContext)
	if err != nil {
		s.finishServiceAction(record.GetIntent().GetActionId(), nil, err, false)
		return
	}
	defer func() { _ = provider.Close() }()
	result, err := provider.Apply(s.workerContext, record.GetNativePlan(), func(ctx context.Context) error {
		return s.consumeServiceStart(ctx, record)
	})
	s.finishServiceAction(record.GetIntent().GetActionId(), result, err, false)
}

// This is the sole effect gate. The native provider calls it after its own
// serialization, final native reads and subscription setup, immediately before
// the first mutation. There is intentionally no RPC-supplied callback or plan.
func (s *Service) consumeServiceStart(ctx context.Context, expected *agentv1.ServiceExecutionRecord) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	loaded, err := s.enrolled(ctx)
	if err != nil {
		return err
	}
	record, revision, err := s.loadServiceAction(ctx, loaded, expected.GetIntent().GetActionId())
	if err != nil {
		return err
	}
	if record.GetState() != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED || !proto.Equal(record.GetNativePlan(), expected.GetNativePlan()) || !bytes.Equal(record.GetStartGrantEnvelope(), expected.GetStartGrantEnvelope()) {
		return errServiceRejected
	}
	grant, err := s.authorizeServiceStart(ctx, loaded, record, record.GetStartGrantEnvelope())
	if err != nil {
		return err
	}
	next := proto.CloneOf(record)
	next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING
	next.StartedAt = protoTimestamp(s.now())
	if err := s.updateServiceAction(ctx, loaded, revision, next); err != nil {
		return err
	}
	// A slow durable commit cannot extend the start window. A rejection here
	// leaves consumed RUNNING evidence but permits no native mutation.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.serviceDeadline(record); err != nil {
		return err
	}
	now := s.now()
	if now.Before(grant.GetNotBefore().AsTime()) || !now.Before(grant.GetExpiresAt().AsTime()) {
		return errServiceExpired
	}
	if !certUsable(loaded.cert, now) {
		return errIdentityExpired
	}
	return nil
}

// Previously RUNNING work is NEVER replayed. Verify only observes the original
// signed desired state and native definition/boot fences; uncertainty survives.
func (s *Service) reconcileServiceAction(record *agentv1.ServiceExecutionRecord) {
	provider, err := s.openService(s.workerContext)
	if err != nil {
		s.finishServiceAction(record.GetIntent().GetActionId(), nil, err, true)
		return
	}
	defer func() { _ = provider.Close() }()
	result, err := provider.Verify(s.workerContext, record.GetNativePlan())
	s.finishServiceAction(record.GetIntent().GetActionId(), result, err, true)
}

func (s *Service) finishServiceAction(actionID string, result *agentv1.ServiceVerification, operationErr error, reconcile bool) {
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
	record, revision, err := s.loadServiceAction(ctx, loaded, actionID)
	if err != nil {
		s.noteTrustDamage()
		return
	}
	state := record.GetState()
	if state != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING && state != agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_QUEUED {
		// A higher sequence or a concurrent read may already have expired or
		// superseded this queued action. Never overwrite its terminal evidence.
		return
	}
	next := proto.CloneOf(record)
	next.CompletedAt = protoTimestamp(s.now())
	if result != nil && serviceprovider.ValidateVerification(record.GetNativePlan(), result) != nil {
		result = nil
		operationErr = errInternal
	}
	next.Verification = result
	if state == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING {
		if operationErr == nil && result.GetConverged() {
			next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED
		} else if !reconcile && errors.Is(operationErr, serviceprovider.ErrNotConverged) && result != nil {
			next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NATIVE
		} else {
			next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_OBSERVATION
			if errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
				next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED
			}
		}
	} else {
		next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_FAILED
		next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_NATIVE
		switch {
		case errors.Is(operationErr, context.Canceled), errors.Is(operationErr, errClosed):
			next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED
		case errors.Is(operationErr, errServiceExpired):
			next.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_EXPIRED
		case errors.Is(operationErr, serviceprovider.ErrConflict):
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_PRECONDITION
		case errors.Is(operationErr, serviceprovider.ErrUnsupported):
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_UNSUPPORTED
		case errors.Is(operationErr, errServiceRejected), errors.Is(operationErr, errIdentityExpired), errors.Is(operationErr, errSessionRequired), errors.Is(operationErr, errSessionPending), errors.Is(operationErr, errRenewalPending), errors.Is(operationErr, journal.ErrServiceActionRejected):
			next.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_AUTHORITY
		}
	}
	if err := s.updateServiceAction(ctx, loaded, revision, next); err != nil {
		// Do not replay an effect after a failed durable completion. Keeping the
		// RUNNING row plus recovery hold is safer than a fabricated success.
		s.noteTrustDamage()
	}
}

func (s *Service) interruptServiceActions() {
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
		record, revision, err := s.store.NextUnfinishedServiceAction(ctx, cursor)
		if errors.Is(err, journal.ErrServiceActionNotFound) {
			return
		}
		if err != nil {
			s.noteTrustDamage()
			return
		}
		if err := s.verifyServiceRecord(ctx, loaded, record); err != nil {
			s.noteTrustDamage()
			return
		}
		cursor = record.GetIntent().GetActionId()
		if record.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_RUNNING {
			record.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN
		} else {
			record.State = agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED
		}
		record.Failure = agentv1.ServiceExecutionFailure_SERVICE_EXECUTION_FAILURE_INTERRUPTED
		record.CompletedAt = protoTimestamp(s.now())
		if err := s.updateServiceAction(ctx, loaded, revision, record); err != nil {
			s.noteTrustDamage()
			return
		}
	}
}
